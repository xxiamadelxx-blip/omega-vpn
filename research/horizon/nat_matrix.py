#!/usr/bin/env python3
"""Ω Horizon G2: deterministic NAT mapping/filtering laboratory (NOT a VPN).

Each fixture creates six Linux network namespaces through netns_lab.Topology,
with a completely isolated WAN and private 10.53/16 addresses. Two reflector
addresses measure the peer's external UDP source ports. An unrelated third
address attempts an unsolicited inbound packet. No Internet egress or actual
user packets; no keys or public endpoints.

Usage:
  python3 research/horizon/nat_matrix.py --self-test
  sudo -E python3 research/horizon/nat_matrix.py --orchestrate
"""
from __future__ import annotations

import argparse
import json
import os
import select
import socket
import subprocess
import sys
import time
import unittest

from netns_lab import Topology, PEER_LAN, PEER_NAT, PEER_PORT, RELAY_LAN, namespace_command

REFLECTOR_PORT = 39004
REFLECTOR_IPS = ("10.53.30.2", "10.53.30.3")
UNSOLICITED_IP = "10.53.30.4"
PROBE = b"OMEGA_NAT_MAPPING_LAB_ONLY"
UNSOLICITED_PROBE = b"UNSOLICITED_NOT_ALLOWED"
MODES = ("preserve_port", "destination_variant")


def mapping_reply(port: int) -> bytes:
    if not 1024 <= port <= 65535:
        raise ValueError("mapped port out of range")
    return b"MAP:" + str(port).encode("ascii")


def parse_reply(message: bytes) -> int:
    if not message.startswith(b"MAP:") or len(message) > 10:
        raise ValueError("not a lab mapping response")
    suffix = message[4:]
    if not suffix or not suffix.isascii() or not suffix.isdigit():
        raise ValueError("malformed port")
    number = int(suffix)
    if not 1024 <= number <= 65535:
        raise ValueError("invalid mapped port")
    return number


def reflector() -> int:
    """Two separate 'public' observers in the isolated relay namespace.

    The third socket has a deliberately different source IP/port so ordinary
    conntrack state should not regard its packet as a response to peer traffic.
    """
    watched = {}
    observations = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outsider:
        for sock, address in zip((first, second), REFLECTOR_IPS):
            sock.bind((address, REFLECTOR_PORT))
            watched[sock] = address
        outsider.bind((UNSOLICITED_IP, REFLECTOR_PORT + 1))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(observations) != 2:
            readable, _, _ = select.select(list(watched), [], [], 0.1)
            for sock in readable:
                data, sender = sock.recvfrom(128)
                if data != PROBE or sender[0] != PEER_NAT:
                    continue
                address = watched[sock]
                observations[address] = sender[1]
                sock.sendto(mapping_reply(sender[1]), sender)
        if len(observations) != 2:
            print(json.dumps({"status": "FAIL_REFLECTOR_INCOMPLETE",
                              "observed": observations}), flush=True)
            return 11

        # No corresponding outbound flow to this distinct IP was created.
        time.sleep(0.06)
        outsider.sendto(UNSOLICITED_PROBE,
                        (PEER_NAT, observations[REFLECTOR_IPS[0]]))
        print(json.dumps({"status": "PASS_REFLECTOR",
                          "ports": observations, "unsolicited_sent": True}), flush=True)
        return 0


def observer_peer() -> int:
    """One UDP socket and local source port for both different destinations."""
    observed = {}
    unsolicited_received = False
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((PEER_LAN, PEER_PORT))
        for target in REFLECTOR_IPS:
            sock.sendto(PROBE, (target, REFLECTOR_PORT))
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and len(observed) != 2:
            sock.settimeout(min(0.15, max(0.01, deadline - time.monotonic())))
            try:
                raw, sender = sock.recvfrom(128)
            except socket.timeout:
                continue
            if raw == UNSOLICITED_PROBE:
                unsolicited_received = True
                continue
            if sender[0] not in REFLECTOR_IPS or sender[1] != REFLECTOR_PORT:
                continue
            try:
                port = parse_reply(raw)
            except ValueError:
                print(json.dumps({"status": "FAIL_MALFORMED_REPLY"}), flush=True)
                return 12
            observed[sender[0]] = port

        # Wait long enough for the unrelated reflector address to send a packet.
        sock.settimeout(0.3)
        try:
            raw, _ = sock.recvfrom(128)
            if raw == UNSOLICITED_PROBE:
                unsolicited_received = True
        except socket.timeout:
            pass
    status = ("PASS_PEER" if len(observed) == 2 and not unsolicited_received
              else "FAIL_PEER")
    print(json.dumps({"status": status, "ports": observed,
                      "unsolicited_received": unsolicited_received}), flush=True)
    return 0 if status == "PASS_PEER" else 13


def _worker_command(topology: Topology, role: str, worker_name: str) -> list[str]:
    return namespace_command(topology.names[role],
                             sys.executable, os.path.abspath(__file__),
                             "--worker", worker_name)


def apply_fixture(topology: Topology, mode: str) -> None:
    """Choose explicit NAT mappings rather than hope for a kernel port allocation.

    The original MASQUERADE remains after these more specific netns-local rules.
    This is a source-port mapping experiment, not an RFC 4787 certification.
    """
    if mode not in MODES:
        raise ValueError("unknown NAT fixture")
    for address in (*REFLECTOR_IPS, UNSOLICITED_IP):
        topology.exec("relay", "ip", "addr", "add", f"{address}/32",
                      "dev", "r0", check=(address != RELAY_LAN))
        # RELAY_LAN is already assigned /24; duplicate /32 may be rejected.
    if mode == "preserve_port":
        assignments = ((REFLECTOR_IPS[0], PEER_PORT),
                       (REFLECTOR_IPS[1], PEER_PORT))
    else:
        assignments = ((REFLECTOR_IPS[0], 40123),
                       (REFLECTOR_IPS[1], 40124))
    for destination, external_port in assignments:
        topology.exec("pnat", "iptables", "-t", "nat", "-I", "POSTROUTING", "1",
                      "-s", PEER_LAN, "-p", "udp",
                      "--sport", str(PEER_PORT), "-d", destination,
                      "-o", "m1", "-j", "SNAT",
                      "--to-source", f"{PEER_NAT}:{external_port}")


def fixture(mode: str) -> dict:
    with Topology() as topology:
        apply_fixture(topology, mode)
        process = subprocess.Popen(_worker_command(topology, "relay", "reflector"),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True)
        try:
            time.sleep(0.2)
            peer = subprocess.run(_worker_command(topology, "peer", "peer"),
                                  capture_output=True, text=True, timeout=5)
            reflector_out, reflector_err = process.communicate(timeout=4)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=3)

        if peer.returncode != 0 or process.returncode != 0:
            raise AssertionError(
                f"bad worker status: peer={peer.returncode} reflector={process.returncode}; "
                f"peer={peer.stdout[-400:]} {peer.stderr[-250:]} "
                f"reflector={reflector_out[-400:]} {reflector_err[-250:]}")
        a = json.loads(peer.stdout.strip().splitlines()[-1])
        b = json.loads(reflector_out.strip().splitlines()[-1])
        if a["status"] != "PASS_PEER" or b["status"] != "PASS_REFLECTOR":
            raise AssertionError(f"unexpected observation: {a} {b}")
        if a["ports"] != b["ports"]:
            raise AssertionError("peer and reflector mapped-port observations differ")
        ports = a["ports"]
        if set(ports) != set(REFLECTOR_IPS):
            raise AssertionError("not all independent reflectors responded")
        stable = ports[REFLECTOR_IPS[0]] == ports[REFLECTOR_IPS[1]]
        expect_stable = mode == "preserve_port"
        if stable != expect_stable:
            raise AssertionError(f"fixture {mode} was not realized: {ports}")
        return {"fixture": mode, "result": "PASS", "ports": ports,
                "mapping_same_external_port": stable,
                "unsolicited_blocked": not a["unsolicited_received"],
                "reflector_acknowledged_unsolicited_send": b["unsolicited_sent"]}


def orchestrate() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("requires sudo on an isolated runner with network namespaces")
    checks = [fixture(mode) for mode in MODES]
    print(json.dumps({
        "suite": "omega_horizon_nat_mapping_matrix",
        "status": "PASS", "cases": len(checks), "checks": checks,
        "isolated_private_network_only": True,
        "asserts_real_isp_or_cgnat_compatibility": False,
        "claims_hole_punch_success": False
    }, indent=2), flush=True)


class ParsingTests(unittest.TestCase):
    def test_mapping_reply_roundtrip(self):
        for port in (1024, 39001, 65535):
            self.assertEqual(parse_reply(mapping_reply(port)), port)

    def test_invalid_port_and_malformed_replies(self):
        for bad in (0, 1023, 65536, -1):
            with self.assertRaises(ValueError):
                mapping_reply(bad)
        for bad in (b"", b"MAP:999999", b"MAP:12a3", b"XMAP:39001",
                    b"MAP: 39001", b"MAP:"):
            with self.assertRaises(ValueError):
                parse_reply(bad)

    def test_declared_fixtures_are_explicit(self):
        self.assertEqual(MODES, ("preserve_port", "destination_variant"))
        self.assertEqual(len(set(REFLECTOR_IPS)), 2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--orchestrate", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--worker", choices=("reflector", "peer"))
    args = parser.parse_args()
    if args.orchestrate:
        orchestrate()
    elif args.worker == "reflector":
        sys.exit(reflector())
    elif args.worker == "peer":
        sys.exit(observer_peer())
    elif args.self_test:
        unittest.main(argv=[sys.argv[0]], exit=False)
    else:
        parser.error("choose --orchestrate, --self-test or --worker")
