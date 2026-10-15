#!/usr/bin/env python3
"""Ω Horizon G2 lab: isolated Linux network namespaces, controlled UDP/NAT.

Lab addresses ONLY. No public IPs, TUN, Internet egress or user traffic.
UDP frames use Python stdlib HMAC to detect synthetic probe tampering, NOT
end-to-end encryption or a production authentication protocol. The separate
TLS-1.3 lab tests authenticated encryption (research/horizon/lab.py).

Invocation: sudo -E python3 research/horizon/netns_lab.py --orchestrate
Unprivileged parser tests: python3 research/horizon/netns_lab.py --self-test
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import signal
import socket
import statistics
import subprocess
import sys
import time
import unittest

PEER_LAN = "10.53.2.2"
PEER_NAT = "10.53.20.2"
CLIENT_LAN = "10.53.1.2"
RELAY_LAN = "10.53.30.2"
PEER_PORT = 39001
RELAY_PORT = 39002
REGISTER = b"OMEGA_LAB_REGISTER_V1"
NONCE_BYTES = 12
MAC_BYTES = 32


def frame(kind: bytes, nonce: bytes, key: bytes) -> bytes:
    if kind not in (b"P", b"A") or len(nonce) != NONCE_BYTES or len(key) != 32:
        raise ValueError("invalid synthetic UDP lab frame")
    message = kind + nonce
    return message + hmac.new(key, message, hashlib.sha256).digest()


def parse_frame(raw: bytes, kind: bytes, key: bytes) -> bytes:
    if len(raw) != 1 + NONCE_BYTES + MAC_BYTES or raw[:1] != kind:
        raise ValueError("invalid synthetic UDP lab frame")
    expected = hmac.new(key, raw[:-MAC_BYTES], hashlib.sha256).digest()
    if not hmac.compare_digest(raw[-MAC_BYTES:], expected):
        raise ValueError("synthetic UDP lab HMAC failure")
    return raw[1:1 + NONCE_BYTES]


def lab_key() -> bytes:
    value = os.environ.get("OMEGA_HORIZON_LAB_KEY", "")
    if len(value) != 64:
        raise RuntimeError("missing ephemeral synthetic lab key")
    return bytes.fromhex(value)


def peer_worker() -> None:
    key = lab_key()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((PEER_LAN, PEER_PORT))
        sock.settimeout(0.13)
        next_register = 0.0
        while True:
            now = time.monotonic()
            if now >= next_register:
                # Outbound mapping permits responses from this relay under NAT.
                sock.sendto(REGISTER, (RELAY_LAN, RELAY_PORT))
                next_register = now + 0.3
            try:
                payload, address = sock.recvfrom(256)
            except socket.timeout:
                continue
            try:
                nonce = parse_frame(payload, b"P", key)
            except ValueError:
                continue
            sock.sendto(frame(b"A", nonce, key), address)


def relay_worker(corrupt: bool) -> None:
    # The intermediary must never possess the probe's end-to-end MAC key.
    if os.environ.get("OMEGA_HORIZON_LAB_KEY"):
        raise RuntimeError("relay inadvertently received peer secret")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((RELAY_LAN, RELAY_PORT))
        sock.settimeout(0.3)
        peer_address = None
        client_address = None
        while True:
            try:
                payload, address = sock.recvfrom(256)
            except socket.timeout:
                continue
            if payload == REGISTER:
                # Lab protocol only. This is deliberately NOT production discovery
                # or proof of peer identity; peer's HMAC response is checked by client.
                if address[0] == PEER_NAT:
                    peer_address = address
                continue
            if not peer_address:
                continue
            if payload[:1] == b"P" and len(payload) == 45:
                client_address = address
                sock.sendto(payload, peer_address)
            elif (payload[:1] == b"A" and len(payload) == 45 and
                  address == peer_address and client_address):
                if corrupt:
                    payload = payload[:-1] + bytes([payload[-1] ^ 0xFF])
                sock.sendto(payload, client_address)


def client_worker() -> int:
    key = lab_key()
    nonce = secrets.token_bytes(NONCE_BYTES)
    question = frame(b"P", nonce, key)
    samples = []
    session_started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((CLIENT_LAN, 0))
        for path, destination in (("direct", (PEER_NAT, PEER_PORT)),
                                  ("relay", (RELAY_LAN, RELAY_PORT))):
            start = time.monotonic()
            sock.sendto(question, destination)
            sock.settimeout(0.95)
            try:
                raw, actual = sock.recvfrom(256)
            except socket.timeout:
                samples.append({"path": path, "status": "TIMEOUT"})
                continue
            # A cross-path packet or a forged reply cannot count as a PASS.
            if actual[0] != destination[0]:
                print(json.dumps({"result": "AUTH_FAIL",
                                  "reason": "unexpected_endpoint", "path": path,
                                  "total_elapsed_ms": round(1000 * (time.monotonic() - session_started), 2)}), flush=True)
                return 13
            try:
                reply_nonce = parse_frame(raw, b"A", key)
                if reply_nonce != nonce:
                    raise ValueError("synthetic nonce mismatch")
            except ValueError:
                print(json.dumps({"result": "AUTH_FAIL",
                                  "reason": "authenticated_frame_rejected", "path": path,
                                  "total_elapsed_ms": round(1000 * (time.monotonic() - session_started), 2)}), flush=True)
                return 13
            print(json.dumps({"result": "PASS", "path": path,
                              "path_rtt_ms": round(1000 * (time.monotonic() - start), 2),
                              "total_elapsed_ms": round(1000 * (time.monotonic() - session_started), 2),
                              "failed_paths": samples}), flush=True)
            return 0
    print(json.dumps({"result": "NO_PATH", "path": None,
                      "total_elapsed_ms": round(1000 * (time.monotonic() - session_started), 2),
                      "failed_paths": samples}), flush=True)
    return 11


def run(*args: str, timeout: float = 9, check: bool = True,
        env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, encoding="utf8", capture_output=True,
                            timeout=timeout, env=env)
    if check and result.returncode:
        raise RuntimeError(f"lab command failed: {args[:6]} "
                           f"exit={result.returncode}: {result.stderr[-400:]}")
    return result


def namespace_command(ns: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", ns, *args]


class Topology:
    """Six non-default-route namespaces, all links inside 10.53.0.0/16."""

    def __init__(self) -> None:
        self.names = {role: f"oh{os.getpid()}{suffix}"
                      for role, suffix in (("client", "c"), ("cnat", "n"),
                                           ("peer", "p"), ("pnat", "m"),
                                           ("relay", "r"), ("wan", "w"))}
        self.created: list[str] = []

    def __enter__(self) -> "Topology":
        try:
            for ns in self.names.values():
                run("ip", "netns", "add", ns)
                self.created.append(ns)
                run("ip", "-n", ns, "link", "set", "lo", "up")
            # Endpoints: (namespace, interface, address) and link partner.
            self.link("client", "c0", "10.53.1.2/24", "cnat", "n0", "10.53.1.1/24")
            self.link("cnat", "n1", "10.53.10.2/24", "wan", "w1", "10.53.10.1/24")
            self.link("peer", "p0", "10.53.2.2/24", "pnat", "m0", "10.53.2.1/24")
            self.link("pnat", "m1", "10.53.20.2/24", "wan", "w2", "10.53.20.1/24")
            self.link("relay", "r0", "10.53.30.2/24", "wan", "w3", "10.53.30.1/24")
            self.route("client", "10.53.1.1")
            self.route("cnat", "10.53.10.1")
            self.route("peer", "10.53.2.1")
            self.route("pnat", "10.53.20.1")
            self.route("relay", "10.53.30.1")
            for role in ("cnat", "pnat", "wan"):
                self.exec(role, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1")
            for role, prefix, outgoing in (("cnat", "10.53.1.0/24", "n1"),
                                           ("pnat", "10.53.2.0/24", "m1")):
                self.exec(role, "iptables", "-t", "nat", "-A", "POSTROUTING",
                          "-s", prefix, "-o", outgoing, "-j", "MASQUERADE")
                # No unsolicited inbound traverses either simulated NAT.
                outside, inside = ("n1", "n0") if role == "cnat" else ("m1", "m0")
                self.exec(role, "iptables", "-A", "FORWARD", "-i", inside,
                          "-o", outside, "-j", "ACCEPT")
                self.exec(role, "iptables", "-A", "FORWARD", "-i", outside,
                          "-o", inside, "-m", "conntrack", "--ctstate",
                          "ESTABLISHED,RELATED", "-j", "ACCEPT")
                self.exec(role, "iptables", "-A", "FORWARD", "-i", outside,
                          "-o", inside, "-j", "DROP")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def link(self, a: str, ifa: str, ipa: str, b: str, ifb: str, ipb: str) -> None:
        run("ip", "link", "add", ifa, "type", "veth", "peer", "name", ifb)
        run("ip", "link", "set", ifa, "netns", self.names[a])
        run("ip", "link", "set", ifb, "netns", self.names[b])
        for role, interface, ip in ((a, ifa, ipa), (b, ifb, ipb)):
            run("ip", "-n", self.names[role], "addr", "add", ip, "dev", interface)
            run("ip", "-n", self.names[role], "link", "set", interface, "up")

    def route(self, role: str, gateway: str) -> None:
        run("ip", "-n", self.names[role], "route", "add", "default", "via", gateway)

    def exec(self, role: str, *args: str, **kwargs) -> subprocess.CompletedProcess:
        return run(*namespace_command(self.names[role], *args), **kwargs)

    def open_mapping(self) -> None:
        # Explicit inbound static mapping, not a claim of NAT hole punching.
        self.exec("pnat", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", "m1",
                  "-p", "udp", "--dport", str(PEER_PORT), "-j", "DNAT",
                  "--to-destination", f"{PEER_LAN}:{PEER_PORT}")
        self.exec("pnat", "iptables", "-I", "FORWARD", "1", "-i", "m1",
                  "-o", "m0", "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "ACCEPT")

    def block_direct(self) -> None:
        self.exec("wan", "iptables", "-I", "FORWARD", "1", "-s", "10.53.10.2",
                  "-d", PEER_NAT, "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "DROP")

    def unblock_direct(self) -> None:
        self.exec("wan", "iptables", "-D", "FORWARD", "-s", "10.53.10.2",
                  "-d", PEER_NAT, "-p", "udp", "--dport", str(PEER_PORT),
                  "-j", "DROP")

    def __exit__(self, *unused) -> None:
        # No host routing, firewall or sysctl was changed.
        for ns in reversed(self.created):
            run("ip", "netns", "del", ns, check=False)


def worker(topology: Topology, role: str, key: str, corrupt: bool = False):
    env = dict(os.environ)
    if role in ("peer", "client"):
        env["OMEGA_HORIZON_LAB_KEY"] = key
    else:
        env.pop("OMEGA_HORIZON_LAB_KEY", None)
    command = namespace_command(
        topology.names[role], sys.executable, os.path.abspath(__file__),
        "--worker", role, *(["--corrupt"] if corrupt else []))
    return subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, start_new_session=True)


def client(topology: Topology, key: str) -> dict:
    env = dict(os.environ)
    env["OMEGA_HORIZON_LAB_KEY"] = key
    result = topology.exec("client", sys.executable, os.path.abspath(__file__),
                           "--worker", "client", timeout=7, check=False, env=env)
    try:
        data = json.loads(result.stdout.strip().splitlines()[-1])
    except Exception as exc:
        raise RuntimeError("client emitted no structured probe result: " +
                           result.stderr[-500:]) from exc
    if result.returncode not in (0, 11, 13):
        raise RuntimeError("unexpected client exit code")
    return data


def expect(result: dict, status: str, path: str | None) -> None:
    if result.get("result") != status or result.get("path") != path:
        raise AssertionError(f"expected {status}/{path}, received {result}")


def orchestrate() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("real network namespaces require root on an isolated runner")
    key = secrets.token_hex(32)  # ephemeral, never logged or committed
    workers: list[subprocess.Popen] = []
    checks: list[dict] = []
    started = time.monotonic()
    with Topology() as topology:
        try:
            peer = worker(topology, "peer", key)
            relay = worker(topology, "relay", key)
            workers.extend((peer, relay))
            time.sleep(1.6)
            if peer.poll() is not None or relay.poll() is not None:
                raise RuntimeError("peer/relay exited before test")

            # Inbound unmapped NAT: direct connection fails; peer's outbound
            # REGISTER keeps relay NAT mapping active.
            one = client(topology, key)
            expect(one, "PASS", "relay")
            checks.append({"case": "unmapped_nat_relay_fallback", **one})

            topology.open_mapping()
            two = client(topology, key)
            expect(two, "PASS", "direct")
            checks.append({"case": "explicit_inbound_mapping_direct", **two})

            topology.block_direct()
            three = client(topology, key)
            expect(three, "PASS", "relay")
            checks.append({"case": "synthetic_direct_block_relay_fallback", **three})

            relay.terminate()
            relay.wait(timeout=3)
            four = client(topology, key)
            expect(four, "NO_PATH", None)
            checks.append({"case": "blocked_direct_and_dead_relay_fail_closed", **four})

            relay = worker(topology, "relay", key)
            workers.append(relay)
            time.sleep(1.2)
            five = client(topology, key)
            expect(five, "PASS", "relay")
            checks.append({"case": "relay_restart_recovery", **five})

            # A compromised intermediary can alter bytes but cannot construct
            # a matching HMAC response without the peer key. Reusing the
            # previously closed socket is safe after the old worker exits.
            relay.terminate()
            relay.wait(timeout=3)
            corrupt_relay = worker(topology, "relay", key, corrupt=True)
            workers.append(corrupt_relay)
            time.sleep(1.2)
            tampered = client(topology, key)
            expect(tampered, "AUTH_FAIL", "relay")
            checks.append({"case": "relay_reply_tampering_rejected", **tampered})
            corrupt_relay.terminate()
            corrupt_relay.wait(timeout=3)
            relay = worker(topology, "relay", key)
            workers.append(relay)
            time.sleep(1.2)
            recovered = client(topology, key)
            expect(recovered, "PASS", "relay")
            checks.append({"case": "normal_relay_recovers_after_tampering", **recovered})

            topology.unblock_direct()
            six = client(topology, key)
            expect(six, "PASS", "direct")
            checks.append({"case": "direct_unblocked_recovery", **six})

            successful = [c["total_elapsed_ms"] for c in checks if c["result"] == "PASS"]
            fallback = [c["total_elapsed_ms"] for c in checks
                        if c["result"] == "PASS" and c["path"] == "relay"]
            metrics = {
                "suite": "omega_horizon_linux_netns_nat_udp",
                "status": "PASS",
                "network_namespaces": 6,
                "scenarios": len(checks),
                "root_network_modifications": False,
                "internet_egress": False,
                "data_encryption_proven_by_this_suite": False,
                "actual_nat_hole_punching_implemented": False,
                "mean_end_to_end_success_ms": round(statistics.mean(successful), 2),
                "mean_relay_fallback_end_to_end_ms": round(statistics.mean(fallback), 2),
                "elapsed_seconds": round(time.monotonic() - started, 2),
                "checks": checks
            }
            print(json.dumps(metrics, indent=2), flush=True)
        finally:
            for child in workers:
                if child.poll() is None:
                    child.terminate()
            for child in workers:
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)


class FramingTests(unittest.TestCase):
    def test_valid_and_modified_authenticated_probe(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        pkt = frame(b"P", nonce, key)
        self.assertEqual(parse_frame(pkt, b"P", key), nonce)
        with self.assertRaises(ValueError):
            parse_frame(pkt[:-1] + bytes([pkt[-1] ^ 1]), b"P", key)

    def test_frame_rejects_type_replay_and_key_change(self):
        key = bytes(range(32))
        nonce = bytes(range(12))
        pkt = frame(b"P", nonce, key)
        with self.assertRaises(ValueError):
            parse_frame(pkt, b"A", key)
        with self.assertRaises(ValueError):
            parse_frame(pkt, b"P", bytes(reversed(key)))
        with self.assertRaises(ValueError):
            frame(b"U", nonce, key)

    def test_synthetic_probe_never_embeds_user_packets(self):
        pkt = frame(b"P", b"123456789012", bytes(range(32)))
        self.assertEqual(len(pkt), 45)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--orchestrate", action="store_true")
    cli.add_argument("--worker", choices=("client", "peer", "relay"))
    cli.add_argument("--self-test", action="store_true")
    cli.add_argument("--corrupt", action="store_true")
    args = cli.parse_args()
    if args.orchestrate:
        orchestrate()
    elif args.worker == "client":
        sys.exit(client_worker())
    elif args.worker == "peer":
        peer_worker()
    elif args.worker == "relay":
        relay_worker(args.corrupt)
    elif args.self_test:
        unittest.main(argv=[sys.argv[0]], exit=False)
    else:
        cli.error("select --orchestrate, --self-test, or --worker")
