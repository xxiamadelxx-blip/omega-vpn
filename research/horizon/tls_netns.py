#!/usr/bin/env python3
"""Ω Horizon G2 lab: real mTLS 1.3 over isolated Linux NAT and blind TCP relay.

Not a production VPN and NOT NAT hole punching. Six private net namespaces,
no Internet egress, ephemeral OpenSSL CA, no user payload or Android code.
Peer initiates an outbound TCP connection to the relay, then speaks TLS server
on that socket. The blind relay forwards the TLS records; it has NO TLS keys.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from lab import (Identity, _client_context, _server_context, _common_name,
                 _send_frame, _read_frame)
from netns_lab import Topology, PEER_LAN, PEER_NAT, RELAY_LAN, namespace_command

TCP_DIRECT = 39105
TCP_RELAY = 39106
MARKER = b"OMEGA-TLS-ONLY-LAB-"
CLIENT_PEER_CN = "omega-peer"
SERVER_CLIENT_CN = "omega-client"


def issue_certificates(directory: Path) -> None:
    """Temporary lab test CA with independent server and client credentials."""
    def openssl(*args: str) -> None:
        completed = subprocess.run(["openssl", *map(str, args)], check=False,
                                   capture_output=True, text=True, timeout=15)
        if completed.returncode:
            raise RuntimeError("OpenSSL laboratory certificate creation failed")

    ca = directory / "ca.pem"
    ca_key = directory / "ca.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(ca_key),
            "-out", str(ca), "-days", "1", "-sha256",
            "-subj", "/CN=OmegaHorizonLabOnlyCA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for cn, usage in ((CLIENT_PEER_CN, "serverAuth"),
                      (SERVER_CLIENT_CN, "clientAuth"),
                      ("other-peer", "serverAuth")):
        key, csr, pem, ext = (directory / f"{cn}.{extension}"
                              for extension in ("key", "csr", "pem", "ext"))
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key),
                "-out", str(csr), "-subj", f"/CN={cn}")
        ext.write_text("basicConstraints=CA:FALSE\n"
                       "keyUsage=digitalSignature\n"
                       f"extendedKeyUsage={usage}\n"
                       f"subjectAltName=DNS:{cn}\n")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(ca),
                "-CAkey", str(ca_key), "-CAcreateserial", "-out",
                str(pem), "-days", "1", "-sha256", "-extfile", str(ext))


def identity(role: str, *, wrong_peer: bool = False) -> Identity:
    folder = Path(os.environ["OMEGA_HORIZON_CERT_DIR"])
    name = (("other-peer" if wrong_peer else CLIENT_PEER_CN)
            if role == "peer" else SERVER_CLIENT_CN)
    return Identity(ca=folder / "ca.pem", cert=folder / f"{name}.pem",
                    key=folder / f"{name}.key",
                    peer_dns_name=CLIENT_PEER_CN if role == "client" else "",
                    peer_common_name=SERVER_CLIENT_CN if role == "peer"
                    else CLIENT_PEER_CN)


def peer_session(connection: socket.socket, *, wrong_peer: bool) -> None:
    ctx = _server_context(identity("peer", wrong_peer=wrong_peer))
    connection.settimeout(4)
    with ctx.wrap_socket(connection, server_side=True) as secure:
        if _common_name(secure.getpeercert()) != SERVER_CLIENT_CN:
            raise ValueError("unrecognized authenticated client")
        message = _read_frame(secure)
        if not message.startswith(MARKER) or len(message) > 100:
            raise ValueError("not a synthetic experiment")
        _send_frame(secure, b"ACK:" + message)


def peer_worker(mode: str, wrong_peer: bool) -> int:
    if mode == "direct":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((PEER_LAN, TCP_DIRECT))
            listener.listen(2)
            listener.settimeout(5)
            incoming, _ = listener.accept()
            with incoming:
                peer_session(incoming, wrong_peer=wrong_peer)
    elif mode == "backhaul":
        # The peer establishes the outbound TCP mapping before a client
        # arrives. Relay accepts this as a blind TCP byte stream.
        with socket.create_connection((RELAY_LAN, TCP_RELAY), timeout=3) as conn:
            peer_session(conn, wrong_peer=wrong_peer)
    else:
        raise ValueError("invalid peer worker mode")
    return 0


def relay_worker(tamper: bool) -> int:
    if "OMEGA_HORIZON_CERT_DIR" in os.environ:
        raise RuntimeError("relay must never receive certificate paths or keys")
    count = 0
    transcript = bytearray()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((RELAY_LAN, TCP_RELAY))
        listener.listen(2)
        listener.settimeout(5)
        backhaul, _ = listener.accept()
        with backhaul:
            downstream, _ = listener.accept()
            with downstream:
                backhaul.settimeout(5)
                downstream.settimeout(5)
                tampered = False
                start = time.monotonic()
                while time.monotonic() - start < 6:
                    ready, _, _ = select.select([backhaul, downstream], [], [], 1)
                    if not ready:
                        break
                    for source in ready:
                        try:
                            packet = source.recv(65536)
                        except (ConnectionResetError, BrokenPipeError):
                            # A rejected peer certificate legitimately resets TLS.
                            # The forwarding node must still produce evidence.
                            print(json.dumps({
                                "status": "RELAY_REMOTE_RESET",
                                "bytes": count,
                                "tls_record_sample_contains_marker": MARKER in transcript
                            }), flush=True)
                            return 0
                        if not packet:
                            print(json.dumps({"status": "RELAY_CLOSED",
                                              "bytes": count,
                                              "tls_record_sample_contains_marker":
                                              MARKER in transcript}), flush=True)
                            return 0
                        destination = downstream if source is backhaul else backhaul
                        if tamper and source is backhaul and not tampered:
                            packet = bytes((packet[0] ^ 0xFF,)) + packet[1:]
                            tampered = True
                        count += len(packet)
                        if len(transcript) < 32768:
                            transcript.extend(packet[:32768 - len(transcript)])
                        try:
                            destination.sendall(packet)
                        except (ConnectionResetError, BrokenPipeError):
                            print(json.dumps({
                                "status": "RELAY_PEER_CLOSED",
                                "bytes": count,
                                "tls_record_sample_contains_marker": MARKER in transcript
                            }), flush=True)
                            return 0
    print(json.dumps({"status": "RELAY_FINISHED", "bytes": count,
                      "tls_record_sample_contains_marker": MARKER in transcript}),
          flush=True)
    return 0


def client_worker() -> int:
    direct = (PEER_NAT, TCP_DIRECT)
    relay = (RELAY_LAN, TCP_RELAY)
    ctx = _client_context(identity("client"))
    nonce = MARKER + os.urandom(12)
    attempts = []
    started = time.monotonic()
    for path, endpoint in (("direct", direct), ("relay", relay)):
        try:
            raw = socket.create_connection(endpoint, timeout=1.2)
        except OSError:
            attempts.append(path + "_unreachable")
            continue
        with raw:
            try:
                raw.settimeout(3)
                # Failure of peer authentication MUST be fatal, not fallback.
                with ctx.wrap_socket(raw, server_hostname=CLIENT_PEER_CN) as tls:
                    if _common_name(tls.getpeercert()) != CLIENT_PEER_CN:
                        raise ssl.SSLError("expected peer identity absent")
                    _send_frame(tls, nonce)
                    answer = _read_frame(tls)
                    if answer != b"ACK:" + nonce:
                        raise ssl.SSLError("authenticated response mismatch")
                    print(json.dumps({
                        "result": "PASS_TLS13", "path": path,
                        "version": tls.version(), "peer": CLIENT_PEER_CN,
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
                        "previous_failures": attempts}), flush=True)
                    return 0
            except (ssl.SSLError, OSError, EOFError, ValueError):
                print(json.dumps({"result": "AUTH_OR_TLS_FAILED", "path": path,
                                  "downgraded": False,
                                  "previous_failures": attempts}), flush=True)
                return 13
    print(json.dumps({"result": "NO_PATH", "previous_failures": attempts}),
          flush=True)
    return 11


def isolated_worker(topology: Topology, namespace: str, worker_type: str,
                    certificate_directory: Path, *args: str) -> subprocess.Popen:
    env = dict(os.environ)
    if worker_type == "relay":
        env.pop("OMEGA_HORIZON_CERT_DIR", None)
    else:
        env["OMEGA_HORIZON_CERT_DIR"] = str(certificate_directory)
    cmd = namespace_command(topology.names[namespace], sys.executable,
                            os.path.abspath(__file__), "--worker", worker_type, *args)
    return subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def tcp_direct_mapping(topology: Topology) -> None:
    topology.exec("pnat", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                  "-i", "m1", "-p", "tcp", "--dport", str(TCP_DIRECT),
                  "-j", "DNAT", "--to-destination", f"{PEER_LAN}:{TCP_DIRECT}")
    topology.exec("pnat", "iptables", "-I", "FORWARD", "1",
                  "-i", "m1", "-o", "m0", "-p", "tcp",
                  "--dport", str(TCP_DIRECT), "-j", "ACCEPT")


def test_case(label: str, root: Path) -> dict:
    workers: list[subprocess.Popen] = []
    with Topology() as network:
        try:
            if label == "direct":
                tcp_direct_mapping(network)
                peer = isolated_worker(network, "peer", "peer", root, "--mode", "direct")
                workers.append(peer)
            else:
                relay = isolated_worker(network, "relay", "relay", root,
                                        *(["--tamper"] if label == "tamper" else []))
                workers.append(relay)
                time.sleep(0.18)
                peer = isolated_worker(network, "peer", "peer", root, "--mode",
                                       "backhaul",
                                       *(["--wrong-peer"] if label == "wrong_peer" else []))
                workers.append(peer)
            time.sleep(0.35)
            result = subprocess.run(
                namespace_command(network.names["client"], sys.executable,
                                  os.path.abspath(__file__), "--worker", "client"),
                capture_output=True, text=True, timeout=9,
                env={**os.environ, "OMEGA_HORIZON_CERT_DIR": str(root)})
            if result.returncode not in (0, 11, 13):
                raise AssertionError("unexpected client status: " + result.stderr[-600:])
            data = json.loads(result.stdout.strip().splitlines()[-1])
            if label == "direct":
                desired = ("PASS_TLS13", "direct")
            elif label == "relay":
                desired = ("PASS_TLS13", "relay")
            else:
                desired = ("AUTH_OR_TLS_FAILED", "relay")
            if (data["result"], data["path"]) != desired:
                raise AssertionError(f"{label} should yield {desired}, got {data}")
            relay_details = None
            for p in workers:
                try:
                    out, err = p.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    p.terminate()
                    out, err = p.communicate(timeout=3)
                if label in ("direct", "relay") and p.returncode != 0:
                    raise AssertionError("unexpected peer/relay worker failure: " + err[-400:])
                if p is workers[0] and label != "direct":
                    if not out.strip():
                        raise AssertionError("missing relay result in " + label + ": " + err[-400:])
                    relay_details = json.loads(out.strip().splitlines()[-1])
                    if relay_details["bytes"] == 0 or \
                       relay_details["tls_record_sample_contains_marker"]:
                        raise AssertionError("relay exposed probe marker or no TLS records")
            return {"case": label, "status": "PASS", "client": data,
                    "blind_relay": relay_details}
        finally:
            for p in workers:
                if p.poll() is None:
                    p.terminate()
                try:
                    p.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    p.kill()


def orchestrate() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("Linux netns integration requires isolated CI runner + sudo")
    with tempfile.TemporaryDirectory(prefix="omega-horizon-mtls-netns-") as temp:
        root = Path(temp)
        issue_certificates(root)
        checks = [test_case(label, root) for label in
                  ("direct", "relay", "wrong_peer", "tamper")]
    print(json.dumps({"suite": "omega_horizon_mtls_over_isolated_nat",
                      "status": "PASS", "cases": len(checks), "checks": checks,
                      "internet_egress": False, "android_tun": False,
                      "udp_encryption_claimed": False, "real_cgnat_claimed": False},
                     indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--orchestrate", action="store_true")
    parser.add_argument("--worker", choices=("client", "peer", "relay"))
    parser.add_argument("--mode", choices=("direct", "backhaul"))
    parser.add_argument("--wrong-peer", action="store_true")
    parser.add_argument("--tamper", action="store_true")
    args = parser.parse_args()
    if args.orchestrate:
        orchestrate()
    elif args.worker == "client":
        sys.exit(client_worker())
    elif args.worker == "peer":
        sys.exit(peer_worker(args.mode, args.wrong_peer))
    elif args.worker == "relay":
        sys.exit(relay_worker(args.tamper))
    else:
        parser.error("select --orchestrate or --worker")
