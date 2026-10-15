#!/usr/bin/env python3
"""Ω Horizon G2: encrypted UDP over two NATs + untrusted blind relay.

ISOLATED RESEARCH TEST ONLY. No real Internet, VPN/TUN, service discovery,
production key exchange or persisted replay state. A fresh out-of-band 32-byte
test PSK is given only to client and peer. The relay never sees the PSK.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import signal
import socket
import subprocess
import sys
import time

from netns_lab import Topology, CLIENT_LAN, PEER_LAN, PEER_NAT, RELAY_LAN, namespace_command
from secure_datagram import MAGIC, RecordRejected, RecordSession, ReplayRejected

PEER_PORT = 39021
RELAY_PORT = 39022
REGISTER = b"OMEGA_G2_LAB_REGISTER_ONLY"
MARKER = b"OMEGA_G2_SECRET_SYNTHETIC"
LAB_PROBE_PREFIX = MARKER + b":"
SOURCE_IPS = {"direct": PEER_NAT, "relay": RELAY_LAN}


def key_from_environment() -> bytes:
    hex_key = os.environ.get("OMEGA_HORIZON_AEAD_KEY", "")
    if len(hex_key) != 64:
        raise RuntimeError("lab peer secret not provisioned")
    return bytes.fromhex(hex_key)


def peer_worker() -> None:
    state = RecordSession("peer", key_from_environment())
    # Separate the direct listening socket from the outbound relay socket.
    # Sharing one UDP source port created conflicting NAT/conntrack mappings:
    # an existing peer->relay flow shadowed a later direct DNAT rule.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as direct, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as via_relay:
        direct.bind((PEER_LAN, PEER_PORT))
        via_relay.bind((PEER_LAN, 0))
        next_registration = 0.0
        while True:
            now = time.monotonic()
            if now >= next_registration:
                via_relay.sendto(REGISTER, (RELAY_LAN, RELAY_PORT))
                next_registration = now + 0.25
            ready, _, _ = select.select([direct, via_relay], [], [], 0.10)
            for connection in ready:
                wire, address = connection.recvfrom(1024)
                if not wire.startswith(MAGIC):
                    continue
                try:
                    payload = state.open(wire)
                except RecordRejected:
                    # Malformed, unauthenticated or replayed records get NO ACK.
                    continue
                if payload.startswith(LAB_PROBE_PREFIX):
                    connection.sendto(state.seal(b"ACK:" + payload), address)


def relay_worker(corrupt_reply: bool) -> None:
    if "OMEGA_HORIZON_AEAD_KEY" in os.environ:
        raise RuntimeError("relay must not possess the peer AEAD key")
    stop = False
    def request_stop(_signum, _frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGTERM, request_stop)
    count = 0
    encrypted_observed = False
    marker_visible = False
    endpoint = None
    remote = None
    already_corrupted = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((RELAY_LAN, RELAY_PORT))
        sock.settimeout(0.15)
        while not stop:
            try:
                data, source = sock.recvfrom(1024)
            except socket.timeout:
                continue
            if data == REGISTER and source[0] == PEER_NAT:
                endpoint = source
                continue
            if endpoint is None or not data.startswith(MAGIC):
                continue
            encrypted_observed = True
            if MARKER in data:
                marker_visible = True
            if source == endpoint and remote is not None:
                target = remote
                if corrupt_reply and not already_corrupted:
                    data = data[:-1] + bytes((data[-1] ^ 1,))
                    already_corrupted = True
            elif source[0] == "10.53.10.2":
                remote = source
                target = endpoint
            else:
                continue
            count += len(data)
            sock.sendto(data, target)
    print(json.dumps({"result": "RELAY_STOPPED", "ciphertext_bytes": count,
                      "encrypted_records_seen": encrypted_observed,
                      "synthetic_secret_marker_in_wire": marker_visible,
                      "tamper_mode": corrupt_reply}), flush=True)


def client_worker() -> None:
    state = RecordSession("client", key_from_environment())
    previous_wire: bytes | None = None
    previous_target: tuple[str, int] | None = None
    for line in sys.stdin:
        # Keep one AEAD identity but rotate the local UDP socket on each path
        # attempt. An old conntrack entry can otherwise hide a new NAT DNAT
        # mapping for a previously failed direct destination tuple.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((CLIENT_LAN, 0))
            command = line.strip()
            if command == "stop":
                break
            if command not in ("exchange", "replay"):
                print(json.dumps({"result": "INVALID_COMMAND"}), flush=True)
                continue
            if command == "replay":
                if previous_wire is None or previous_target is None:
                    print(json.dumps({"result": "REPLAY_NOT_READY"}), flush=True)
                    continue
                sock.sendto(previous_wire, previous_target)
                sock.settimeout(0.38)
                try:
                    got, _ = sock.recvfrom(1024)
                    # A real reply to the duplicate must not be accepted.
                    print(json.dumps({"result": "REPLAY_UNEXPECTED_RESPONSE",
                                      "bytes": len(got)}), flush=True)
                except socket.timeout:
                    print(json.dumps({"result": "REPLAY_BLOCKED"}), flush=True)
                continue

            plaintext = LAB_PROBE_PREFIX + str(state.next_sequence).encode("ascii")
            expected = b"ACK:" + plaintext
            wire = state.seal(plaintext)
            failures = []
            started = time.monotonic()
            result = {"result": "NO_PATH", "route": None}
            for route, target, wait in (
                ("direct", (PEER_NAT, PEER_PORT), 0.35),
                ("relay", (RELAY_LAN, RELAY_PORT), 0.90)
            ):
                sock.sendto(wire, target)
                sock.settimeout(wait)
                try:
                    response, address = sock.recvfrom(1024)
                except socket.timeout:
                    failures.append(route + "_timeout")
                    continue
                if address[0] != SOURCE_IPS[route]:
                    result = {"result": "AUTH_FAIL", "reason": "unexpected_source",
                              "route": route}
                    break
                try:
                    opened = state.open(response)
                except RecordRejected:
                    result = {"result": "AUTH_FAIL", "reason": "bad_encrypted_record",
                              "route": route}
                    break
                if opened != expected:
                    result = {"result": "AUTH_FAIL", "reason": "bad_authenticated_response",
                              "route": route}
                    break
                previous_wire, previous_target = wire, target
                result = {"result": "PASS_AEAD", "route": route}
                break
            result.update({"session": state.session_id.hex()[:12],
                           "elapsed_ms": round((time.monotonic()-started)*1000, 2),
                           "failed_routes": failures})
            print(json.dumps(result), flush=True)


def launch(topology: Topology, role: str, secret: str,
           *, tamper: bool = False) -> subprocess.Popen:
    env = dict(os.environ)
    if role in ("peer", "client"):
        env["OMEGA_HORIZON_AEAD_KEY"] = secret
    else:
        env.pop("OMEGA_HORIZON_AEAD_KEY", None)
    command = namespace_command(topology.names[role], sys.executable,
                                os.path.abspath(__file__), "--worker", role,
                                *(["--corrupt-reply"] if tamper else []))
    return subprocess.Popen(command, env=env, stdin=subprocess.PIPE if role=="client" else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)


def send_command(client: subprocess.Popen, cmd: str, deadline: float = 6) -> dict:
    if client.poll() is not None:
        raise AssertionError("client quit unexpectedly")
    client.stdin.write(cmd + "\n")
    client.stdin.flush()
    ready, _, _ = select.select([client.stdout], [], [], deadline)
    if not ready:
        raise AssertionError("client did not return a synthetic UDP probe result")
    line = client.stdout.readline()
    if not line:
        raise AssertionError("client pipe closed without evidence")
    return json.loads(line)


def close_worker(proc: subprocess.Popen) -> tuple[str, str]:
    if proc.poll() is None:
        proc.terminate()
    try:
        return proc.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate(timeout=3)


def expect(result: dict, status: str, route: str | None = None) -> None:
    if result.get("result") != status or (route is not None and result.get("route") != route):
        raise AssertionError(f"wanted {status}/{route}, got {result}")


def allow_direct(topology: Topology) -> None:
    topology.exec("pnat", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
                  "-i", "m1", "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "DNAT", "--to-destination", f"{PEER_LAN}:{PEER_PORT}")
    topology.exec("pnat", "iptables", "-I", "FORWARD", "1", "-i", "m1",
                  "-o", "m0", "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "ACCEPT")


def direct_block(topology: Topology, drop: bool) -> None:
    op = "-I" if drop else "-D"
    args = ["FORWARD", "1"] if drop else ["FORWARD"]
    topology.exec("wan", "iptables", op, *args, "-s", "10.53.10.2",
                  "-d", PEER_NAT, "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "DROP")


def run_experiment() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("requires root on disposable isolated Linux runner")
    secret = os.urandom(32).hex()
    steps = []
    workers: list[subprocess.Popen] = []
    with Topology() as topology:
        try:
            peer = launch(topology, "peer", secret)
            relay = launch(topology, "relay", secret)
            client = launch(topology, "client", secret)
            workers += [peer, relay, client]
            time.sleep(1)
            if any(p.poll() is not None for p in workers):
                raise AssertionError("a required lab worker exited unexpectedly")

            a = send_command(client, "exchange")
            expect(a, "PASS_AEAD", "relay")
            steps.append({"case": "closed_nat_encrypted_relay", **a})
            session = a["session"]

            allow_direct(topology)
            b = send_command(client, "exchange")
            expect(b, "PASS_AEAD", "direct")
            steps.append({"case": "direct_same_crypto_session", **b})

            replay = send_command(client, "replay")
            expect(replay, "REPLAY_BLOCKED")
            steps.append({"case": "duplicate_ciphertext_rejected_by_peer", **replay})

            direct_block(topology, True)
            c = send_command(client, "exchange")
            expect(c, "PASS_AEAD", "relay")
            steps.append({"case": "blocked_direct_encrypted_fallback", **c})

            relay_data, relay_err = close_worker(relay)
            relay_report = json.loads(relay_data.strip().splitlines()[-1])
            if (relay_report["synthetic_secret_marker_in_wire"] or
                relay_report["ciphertext_bytes"] < 64 or
                not relay_report["encrypted_records_seen"]):
                raise AssertionError("relay observed plaintext or forwarded no ciphertext")

            d = send_command(client, "exchange")
            expect(d, "NO_PATH")
            steps.append({"case": "relay_failure_no_plaintext_fallback", **d})

            relay = launch(topology, "relay", secret)
            workers.append(relay)
            time.sleep(0.9)
            e = send_command(client, "exchange")
            expect(e, "PASS_AEAD", "relay")
            steps.append({"case": "relay_restart_preserves_crypto_session", **e})

            close_worker(relay)
            relay = launch(topology, "relay", secret, tamper=True)
            workers.append(relay)
            time.sleep(0.9)
            f = send_command(client, "exchange")
            expect(f, "AUTH_FAIL", "relay")
            steps.append({"case": "relay_ciphertext_tamper_blocked", **f})

            close_worker(relay)
            direct_block(topology, False)
            g = send_command(client, "exchange")
            expect(g, "PASS_AEAD", "direct")
            steps.append({"case": "unblocked_direct_same_crypto_session", **g})

            if any(x["session"] != session for x in steps if "session" in x):
                raise AssertionError("path switch unexpectedly rotated session identity")
            print(json.dumps({
                "suite": "omega_horizon_encrypted_udp_isolated_nat",
                "status": "PASS", "cases": len(steps),
                "same_client_session_across_paths": True,
                "relay_ciphertext_recorded": relay_report,
                "aead": "ChaCha20-Poly1305",
                "key_derivation": "HKDF-SHA256 from ephemeral out-of-band lab PSK",
                "pfs_claimed": False, "public_internet_egress": False,
                "actual_nat_hole_punching_claimed": False,
                "android_vpn_claimed": False,
                "checks": steps
            }, indent=2), flush=True)
        finally:
            for proc in reversed(workers):
                close_worker(proc)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--orchestrate", action="store_true")
    cli.add_argument("--worker", choices=("peer", "relay", "client"))
    cli.add_argument("--corrupt-reply", action="store_true")
    args = cli.parse_args()
    if args.orchestrate:
        run_experiment()
    elif args.worker == "peer":
        peer_worker()
    elif args.worker == "relay":
        relay_worker(args.corrupt_reply)
    elif args.worker == "client":
        client_worker()
    else:
        cli.error("choose --orchestrate or --worker")
