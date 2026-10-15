"""Ω Horizon research AEAD primitive tests. Never uses public endpoints."""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_datagram import (RecordSession, RecordRejected, ReplayRejected,
                             MAGIC, MAX_PLAINTEXT, HEADER, MAX_SEQUENCE)


class DatagramRecordsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.psk = os.urandom(32)
        self.client = RecordSession("client", self.psk)
        self.peer = RecordSession("peer", self.psk)

    def test_round_trip_and_key_separation(self):
        probe = b"OMEGA PRIVATE LAB SYNTHETIC ONLY"
        request = self.client.seal(probe)
        self.assertEqual(self.peer.open(request), probe)
        self.assertNotIn(probe, request)
        response = self.peer.seal(b"ACK:" + probe)
        self.assertEqual(self.client.open(response), b"ACK:" + probe)
        self.assertNotEqual(response, request)

    def test_pinned_session_reused_across_paths(self):
        first = self.client.seal(b"over direct path")
        self.assertEqual(self.peer.open(first), b"over direct path")
        second = self.client.seal(b"over relay path")
        self.assertEqual(self.peer.open(second), b"over relay path")
        third = self.peer.seal(b"ack after route switch")
        self.assertEqual(self.client.open(third), b"ack after route switch")
        self.assertEqual(self.peer.session_id, self.client.session_id)

    def test_exact_duplicate_rejected(self):
        packet = self.client.seal(b"one-shot")
        self.peer.open(packet)
        with self.assertRaises(ReplayRejected):
            self.peer.open(packet)

    def test_receive_reordering_within_window(self):
        items = [self.client.seal(f"packet-{n}".encode()) for n in range(5)]
        self.assertEqual(self.peer.open(items[4]), b"packet-4")
        self.assertEqual(self.peer.open(items[0]), b"packet-0")
        self.assertEqual(self.peer.open(items[3]), b"packet-3")
        with self.assertRaises(ReplayRejected):
            self.peer.open(items[3])

    def test_expired_sequence_rejected(self):
        old = self.client.seal(b"old")
        for _ in range(128):
            newer = self.client.seal(b"new")
        self.peer.open(newer)
        with self.assertRaises(ReplayRejected):
            self.peer.open(old)

    def test_authentication_failure_does_not_consume_nonce_slot(self):
        good = self.client.seal(b"valid first packet")
        altered = good[:-1] + bytes([good[-1] ^ 1])
        with self.assertRaises(RecordRejected):
            self.peer.open(altered)
        self.assertIsNone(self.peer.session_id)
        self.assertEqual(self.peer.open(good), b"valid first packet")

    def test_tamper_ciphertext_and_authenticated_header_rejected(self):
        packet = self.client.seal(b"lab probe")
        for index in (5, 8, HEADER.size + 2, len(packet) - 1):
            changed = packet[:index] + bytes([packet[index] ^ 1]) + packet[index + 1:]
            with self.subTest(index=index), self.assertRaises(RecordRejected):
                self.peer.open(changed)

    def test_wrong_key_rejected(self):
        impostor = RecordSession("peer", os.urandom(32))
        with self.assertRaises(RecordRejected):
            impostor.open(self.client.seal(b"unauthorized"))

    def test_wrong_session_rejected(self):
        self.peer.open(self.client.seal(b"initial"))
        other = RecordSession("client", self.psk)
        with self.assertRaises(RecordRejected):
            self.peer.open(other.seal(b"new session with same PSK"))

    def test_reflected_client_packet_rejected(self):
        packet = self.client.seal(b"directional keys")
        with self.assertRaises(RecordRejected):
            self.client.open(packet)

    def test_wire_version_rejected(self):
        packet = self.client.seal(b"hello")
        with self.assertRaises(RecordRejected):
            self.peer.open(b"FAIL" + packet[4:])
        with self.assertRaises(RecordRejected):
            self.peer.open(packet[:4] + b"\x02" + packet[5:])

    def test_truncated_and_oversized_record_rejected(self):
        with self.assertRaises(RecordRejected):
            self.peer.open(MAGIC)
        with self.assertRaises(RecordRejected):
            self.peer.open(b"R" * 2000)
        with self.assertRaises(ValueError):
            self.client.seal(b"0" * (MAX_PLAINTEXT + 1))
        with self.assertRaises(ValueError):
            self.client.seal(b"")

    def test_peer_cannot_send_before_authenticated_first_packet(self):
        with self.assertRaises(RecordRejected):
            self.peer.seal(b"ACK")

    def test_sequence_exhaustion_never_wraps(self):
        self.client.next_sequence = MAX_SEQUENCE
        self.client.seal(b"last")
        with self.assertRaises(RecordRejected):
            self.client.seal(b"must rotate")

    def test_new_client_session_is_randomized(self):
        other = RecordSession("client", self.psk)
        self.assertNotEqual(self.client.session_id, other.session_id)

    def test_reject_invalid_role_and_key(self):
        with self.assertRaises(ValueError):
            RecordSession("relay", self.psk)
        with self.assertRaises(ValueError):
            RecordSession("client", b"not a 32 byte key")


if __name__ == "__main__":
    unittest.main()
