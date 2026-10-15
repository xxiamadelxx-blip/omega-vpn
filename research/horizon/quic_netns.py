#!/usr/bin/env python3
"""Ω Horizon G2 QUIC/TLS 1.3 lab: authenticated UDP with ephemeral key exchange.

Single-use test CA and pinned *leaf certificate*, QUIC datagrams, controlled
NAT/relay, reject wrong certificate or handshake tampering, re-connect without
pre-shared symmetric traffic keys, and test application replay after restart.

NO Android VPN, arbitrary Internet exit, public relay, NAT hole punching,
anonymity guarantee, production peer enrollment, or user packets.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import DatagramFrameReceived
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from netns_lab import CLIENT_LAN, PEER_LAN, PEER_NAT, RELAY_LAN, Topology, namespace_command
from tls_netns import issue_certificates

ALPN = ["omega-horizon-quic-research-v1"]
PEER_PORT = 39131
RELAY_PORT = 39132
REGISTER = b"OMEGA_QUIC_TEST_REGISTER"
PROBE_PREFIX = b"OMEGA_QUIC_SYNTHETIC_ONLY:"
PROBE_LENGTH = len(PROBE_PREFIX) + 16
REPLY_PREFIX = b"ACK:"
DUP_PREFIX = b"DUP:"
MAX_PACKET = 4096


def lab_folder() -> Path:
    path = os.environ.get("OMEGA_HORIZON_QUIC_LAB_CERT_DIR")
    if not path:
        raise RuntimeError("missing QUIC lab certificate directory")
    return Path(path)


def _cert_fingerprint(cert: x509.Certificate) -> bytes:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).digest()


def issue_clone_certificate(directory: Path) -> None:
    """Same valid DNS identity, different key, signed by the SAME lab CA.

    This makes trust-store validation pass, but explicit pinned leaf mismatch.
    """
    ext = directory / "clone.ext"
    ext.write_text(
        "basicConstraints=CA:FALSE\n"
        "keyUsage=digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:omega-peer\n"
    )
    key = directory / "clone.key"
    csr = directory / "clone.csr"
    cert = directory / "clone.pem"

    def invoke(*args: str) -> None:
        completed = subprocess.run(["openssl", *args],
                                   capture_output=True, text=True, timeout=12)
        if completed.returncode:
            raise RuntimeError("ephemeral lab clone certificate generation failed")

    invoke("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
           "-nodes", "-keyout", str(key), "-out", str(csr),
           "-subj", "/CN=omega-peer")
    invoke("x509", "-req", "-in", str(csr),
           "-CA", str(directory / "ca.pem"),
           "-CAkey", str(directory / "ca.key"),
           "-CAcreateserial", "-out", str(cert), "-days", "1", "-sha256",
           "-extfile", str(ext))


def make_configuration(role: str, cert_variant: str = "valid") -> QuicConfiguration:
    folder = lab_folder()
    if role == "peer":
        name = {"valid": "omega-peer", "wrong-name": "other-peer",
                "clone": "clone"}[cert_variant]
        cfg = QuicConfiguration(
            is_client=False, alpn_protocols=ALPN,
            idle_timeout=6.0, max_datagram_frame_size=1200,
        )
        cfg.load_cert_chain(str(folder / (name + ".pem")),
                            str(folder / (name + ".key")))
    elif role == "client":
        cfg = QuicConfiguration(
            is_client=True, alpn_protocols=ALPN, server_name="omega-peer",
            cafile=str(folder / "ca.pem"),
            verify_mode=ssl.CERT_REQUIRED, max_datagram_frame_size=1200,
            idle_timeout=2.4,
        )
        # No ticket handler and no session_ticket: no 0-RTT replays.
    else:
        raise ValueError("unknown lab role")
    return cfg


class QuicPeer(QuicConnectionProtocol):
    def quic_event_received(self, event) -> None:
        if not isinstance(event, DatagramFrameReceived):
            return
        payload = event.data
        if not payload.startswith(PROBE_PREFIX) or len(payload) != PROBE_LENGTH:
            return
        # Application-level idempotence across separate QUIC sessions and
        # restarts. Stored are SHA256 hashes of synthetic random nonces only.
        # Not packet-level TLS replay protection, and not a production cache.
        digest = hashlib.sha256(payload).digest()
        with sqlite3.connect(lab_folder() / "test_nonce_ledger.sqlite3") as db:
            db.execute("CREATE TABLE IF NOT EXISTS used(digest BLOB PRIMARY KEY)")
            try:
                db.execute("INSERT INTO used (digest) VALUES (?)", (digest,))
                result = REPLY_PREFIX
            except sqlite3.IntegrityError:
                result = DUP_PREFIX
        self._quic.send_datagram_frame(result + payload)
        self.transmit()


class QuicClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reply = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event) -> None:
        if isinstance(event, DatagramFrameReceived) and not self.reply.done():
            self.reply.set_result(event.data)


async def peer_worker(mode: str, cert_variant: str) -> None:
    if mode not in ("direct", "relay"):
        raise ValueError("peer mode unknown")
    server = await serve(
        PEER_LAN, PEER_PORT,
        configuration=make_configuration("peer", cert_variant),
        create_protocol=QuicPeer,
    )
    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, shutdown.set)

    async def keep_relay_mapping() -> None:
        # Outgoing packet from the same UDP listener opens NAT state,
        # enabling server replies to reach a relay without inbound port.
        while not shutdown.is_set():
            server._transport.sendto(REGISTER, (RELAY_LAN, RELAY_PORT))
            await asyncio.sleep(0.22)

    register_task = (asyncio.create_task(keep_relay_mapping())
                     if mode == "relay" else None)
    try:
        await asyncio.wait_for(shutdown.wait(), timeout=10)
    except asyncio.TimeoutError:
        pass
    finally:
        shutdown.set()
        if register_task:
            register_task.cancel()
            try:
                await register_task
            except asyncio.CancelledError:
                pass
        server.close()


async def client_probe(endpoint_host: str, endpoint_port: int,
                       nonce: bytes, fingerprint: bytes) -> dict:
    config = make_configuration("client")
    started = time.monotonic()
    try:
        async with connect(
            endpoint_host, endpoint_port,
            configuration=config, create_protocol=QuicClient
        ) as protocol:
            # Verify both CA+DNS within aioquic, AND the exact expected leaf.
            # This checks a pinned peer identity before sending any test payload.
            cert = protocol._quic.tls._peer_certificate
            if cert is None or not hmac.compare_digest(
                    fingerprint, _cert_fingerprint(cert)):
                return {"status": "PIN_REJECTED", "application_datagram_sent": False}
            connection_id = protocol._quic.host_cid.hex()
            payload = PROBE_PREFIX + nonce
            protocol._quic.send_datagram_frame(payload)
            protocol.transmit()
            result = await asyncio.wait_for(protocol.reply, timeout=2.0)
            if result == REPLY_PREFIX + payload:
                answer = "PASS_QUIC_DATAGRAM"
            elif result == DUP_PREFIX + payload:
                answer = "DUPLICATE_REJECTED"
            else:
                return {"status": "INVALID_APPLICATION_REPLY"}
            return {
                "status": answer, "connection_id": connection_id,
                "pinned_leaf_verified": True,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 2),
            }
    except (asyncio.TimeoutError, ConnectionError, OSError) as exc:
        return {"status": "HANDSHAKE_OR_PATH_FAILED",
                "error_class": type(exc).__name__,
                "application_datagram_sent": False}


def run_client() -> int:
    host = os.environ.get("OMEGA_QUIC_DEST_HOST")
    port = int(os.environ.get("OMEGA_QUIC_DEST_PORT", "0"))
    nonce_hex = os.environ.get("OMEGA_QUIC_NONCE", "")
    if host not in (PEER_NAT, RELAY_LAN) or port not in (PEER_PORT, RELAY_PORT):
        raise RuntimeError("attempt to use a non-lab network destination")
    if len(nonce_hex) != 32:
        raise RuntimeError("missing 16-byte lab nonce")
    expected = x509.load_pem_x509_certificate(
        (lab_folder() / "omega-peer.pem").read_bytes()
    )
    result = asyncio.run(client_probe(
        host, port, bytes.fromhex(nonce_hex), _cert_fingerprint(expected)
    ))
    print(json.dumps(result), flush=True)
    return 0 if result["status"] in ("PASS_QUIC_DATAGRAM",
                                     "DUPLICATE_REJECTED", "PIN_REJECTED",
                                     "HANDSHAKE_OR_PATH_FAILED") else 17


def relay_worker(corrupt: bool) -> None:
    if "OMEGA_HORIZON_QUIC_LAB_CERT_DIR" in os.environ:
        raise RuntimeError("relay must have neither certificate directory nor peer key")
    stop = False

    def close(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, close)
    peer_mapping = None
    client_mapping = None
    count = 0
    marker_visible = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((RELAY_LAN, RELAY_PORT))
        sock.settimeout(0.15)
        while not stop:
            try:
                data, source = sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            if data == REGISTER and source[0] == PEER_NAT:
                peer_mapping = source
                continue
            if peer_mapping is None:
                continue
            if PROBE_PREFIX in data:
                marker_visible = True
            if source == peer_mapping and client_mapping:
                target = client_mapping
                if corrupt:
                    data = data[:-1] + bytes([data[-1] ^ 1])
            elif source[0] == "10.53.10.2":
                client_mapping = source
                target = peer_mapping
            else:
                continue
            count += len(data)
            sock.sendto(data, target)
    print(json.dumps({
        "relay_status": "STOPPED", "forwarded_bytes": count,
        "marker_visible_in_network_packet": marker_visible,
        "has_peer_secrets": False, "corrupt_mode": corrupt,
    }), flush=True)


def launch(topology: Topology, role: str, folder: Path, *,
           mode: str = "relay", cert_variant: str = "valid",
           corrupt: bool = False) -> subprocess.Popen:
    env = dict(os.environ)
    if role == "relay":
        env.pop("OMEGA_HORIZON_QUIC_LAB_CERT_DIR", None)
    else:
        env["OMEGA_HORIZON_QUIC_LAB_CERT_DIR"] = str(folder)
    cmd = namespace_command(
        topology.names[role], sys.executable, os.path.abspath(__file__),
        "--worker", role, "--mode", mode, "--certificate", cert_variant,
        *(["--corrupt"] if corrupt else []),
    )
    return subprocess.Popen(
        cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True,
    )


def invoke_client(topology: Topology, folder: Path, *,
                  route: str, nonce: bytes) -> dict:
    env = dict(os.environ)
    env["OMEGA_HORIZON_QUIC_LAB_CERT_DIR"] = str(folder)
    env["OMEGA_QUIC_NONCE"] = nonce.hex()
    env["OMEGA_QUIC_DEST_HOST"] = (RELAY_LAN if route == "relay" else PEER_NAT)
    env["OMEGA_QUIC_DEST_PORT"] = str(RELAY_PORT if route == "relay" else PEER_PORT)
    cmd = namespace_command(
        topology.names["client"], sys.executable, os.path.abspath(__file__),
        "--worker", "client",
    )
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise AssertionError("QUIC client test failed: " +
                             result.stderr[-700:] + " " + result.stdout[-500:])
    return json.loads(result.stdout.strip().splitlines()[-1])


def stop_worker(proc: subprocess.Popen) -> dict | None:
    if proc.poll() is None:
        proc.terminate()
    try:
        out, err = proc.communicate(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=3)
    if proc.returncode and proc.returncode != -signal.SIGTERM:
        raise AssertionError("QUIC lab worker crashed: " + err[-500:])
    if out.strip():
        try:
            return json.loads(out.strip().splitlines()[-1])
        except ValueError:
            raise AssertionError("QUIC relay returned invalid report")
    return None


def configure_direct(topology: Topology) -> None:
    topology.exec("pnat", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                  "-i", "m1", "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "DNAT", "--to-destination", f"{PEER_LAN}:{PEER_PORT}")
    topology.exec("pnat", "iptables", "-I", "FORWARD", "1", "-i", "m1",
                  "-o", "m0", "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "ACCEPT")


def scenario(folder: Path, label: str) -> dict:
    workers: list[subprocess.Popen] = []
    with Topology() as topology:
        try:
            mode = "direct" if label in ("direct", "wrong-name", "clone-pin") else "relay"
            variant = ("wrong-name" if label == "wrong-name" else
                       "clone" if label == "clone-pin" else "valid")
            if mode == "direct":
                configure_direct(topology)
            else:
                relay = launch(topology, "relay", folder, corrupt=label=="tamper")
                workers.append(relay)
                time.sleep(0.15)
            peer = launch(topology, "peer", folder, mode=mode,
                          cert_variant=variant)
            workers.append(peer)
            time.sleep(0.5)
            if any(p.poll() is not None for p in workers):
                raise AssertionError("QUIC peer or relay did not stay alive")

            nonce = secrets.token_bytes(16)
            first = invoke_client(topology, folder, route=mode, nonce=nonce)
            if label in ("direct", "relay", "reconnect", "restart-replay"):
                if first["status"] != "PASS_QUIC_DATAGRAM" or not first["pinned_leaf_verified"]:
                    raise AssertionError(f"{label} failed encrypted QUIC: {first}")
            elif label == "clone-pin":
                if first["status"] != "PIN_REJECTED" or first["application_datagram_sent"]:
                    raise AssertionError("impostor with same DNS name bypassed leaf pin")
            else:
                if first["status"] != "HANDSHAKE_OR_PATH_FAILED":
                    raise AssertionError(f"{label} unexpectedly completed QUIC: {first}")

            extra = {}
            if label == "reconnect":
                again = invoke_client(topology, folder, route=mode,
                                      nonce=secrets.token_bytes(16))
                if again["status"] != "PASS_QUIC_DATAGRAM":
                    raise AssertionError("reconnection failed")
                if again["connection_id"] == first["connection_id"]:
                    raise AssertionError("fresh QUIC connection ID not rotated")
                extra["reconnection"] = again
            if label == "restart-replay":
                stop_worker(peer)
                peer = launch(topology, "peer", folder, mode=mode)
                workers.append(peer)
                time.sleep(0.65)
                again = invoke_client(topology, folder, route=mode, nonce=nonce)
                if again["status"] != "DUPLICATE_REJECTED":
                    raise AssertionError("replay of synthetic nonce accepted after peer restart")
                extra["replayed_after_server_restart"] = again
                fresh = invoke_client(topology, folder, route=mode,
                                      nonce=secrets.token_bytes(16))
                if fresh["status"] != "PASS_QUIC_DATAGRAM":
                    raise AssertionError("peer failed to accept fresh session after restart")
                extra["fresh_after_restart"] = fresh

            relay_report = None
            if mode == "relay":
                relay_report = stop_worker(workers[0])
                if relay_report is None:
                    raise AssertionError("blind relay did not report observed traffic")
                if (relay_report["has_peer_secrets"] or
                    relay_report["marker_visible_in_network_packet"] or
                    relay_report["forwarded_bytes"] == 0):
                    raise AssertionError("relay leaked lab data or did not forward QUIC")
            return {"case": label, "result": "PASS", "client": first,
                    "extra": extra, "relay_observation": relay_report}
        finally:
            for worker in reversed(workers):
                if worker.poll() is None:
                    worker.terminate()
                try:
                    worker.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.communicate(timeout=3)


def orchestrate() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("requires a disposable privileged Linux CI runner")
    with tempfile.TemporaryDirectory(prefix="omega-quic-g2-") as tmp:
        folder = Path(tmp)
        issue_certificates(folder)
        issue_clone_certificate(folder)
        labels = ("direct", "relay", "wrong-name", "clone-pin",
                  "tamper", "reconnect", "restart-replay")
        output = [scenario(folder, item) for item in labels]
    print(json.dumps({
        "suite": "omega_horizon_standard_quic_tls13",
        "status": "PASS", "scenarios": len(output),
        "has_out_of_band_symmetric_psk": False,
        "certificate_name_and_leaf_pin_verified": True,
        "uses_standard_quic_tls13_handshake": True,
        "server_replay_ledger_persists_restart": True,
        "client_certificate_authentication": False,
        "nat_hole_punching_implemented": False,
        "internet_exit": False,
        "android_tun": False,
        "checks": output,
    }, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--orchestrate", action="store_true")
    parser.add_argument("--worker", choices=("peer", "relay", "client"))
    parser.add_argument("--mode", choices=("direct", "relay"), default="relay")
    parser.add_argument("--certificate", choices=("valid", "wrong-name", "clone"),
                        default="valid")
    parser.add_argument("--corrupt", action="store_true")
    args = parser.parse_args()
    if args.orchestrate:
        orchestrate()
    elif args.worker == "peer":
        asyncio.run(peer_worker(args.mode, args.certificate))
    elif args.worker == "client":
        raise SystemExit(run_client())
    elif args.worker == "relay":
        relay_worker(args.corrupt)
    else:
        parser.error("select --orchestrate or --worker")
