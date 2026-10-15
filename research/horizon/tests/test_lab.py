"""Run: python3 -m unittest discover -s research/horizon/tests -v"""

import importlib.util
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "lab.py"
spec = importlib.util.spec_from_file_location("omega_horizon_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = lab
spec.loader.exec_module(lab)


def _openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True,
                   timeout=12)


def certs(folder: Path, name: str, ca: Path, cakey: Path, role: str):
    key = folder / (name + ".key")
    csr = folder / (name + ".csr")
    crt = folder / (name + ".crt")
    ext = folder / (name + ".ext")
    _openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", key, "-out", csr, "-subj", f"/CN={name}")
    ext.write_text(f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
                   f"extendedKeyUsage={role}\nsubjectAltName=DNS:{name}\n")
    _openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", cakey,
             "-CAcreateserial", "-out", crt, "-days", "1", "-sha256",
             "-extfile", ext)
    return crt, key


def unused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HorizonTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="omega-horizon-certs-")
        folder = Path(cls.temp.name)
        ca, key = folder / "ca.crt", folder / "ca.key"
        _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                 "-nodes", "-keyout", key, "-out", ca, "-days", "1", "-sha256",
                 "-subj", "/CN=OmegaLabCA", "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        cls.ca, cls.cakey = ca, key
        peer_cert, peer_key = certs(folder, "omega-peer", ca, key, "serverAuth")
        cli_cert, cli_key = certs(folder, "omega-client", ca, key, "clientAuth")
        other_cert, other_key = certs(folder, "other-peer", ca, key, "serverAuth")
        cls.peer_identity = lab.Identity(ca, peer_cert, peer_key, "", "omega-client")
        cls.client_identity = lab.Identity(ca, cli_cert, cli_key, "omega-peer", "omega-peer")
        cls.other_identity = lab.Identity(ca, other_cert, other_key, "", "omega-client")
        cls.nonce = b"LAB-ONLY-NO-USER-PAYLOAD"

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.resources = []

    def tearDown(self):
        for r in reversed(self.resources):
            r.close()

    def peer(self, identity=None):
        p = lab.PeerServer(identity or self.peer_identity).start()
        self.resources.append(p)
        return p

    def relay(self, upstream, **kwargs):
        r = lab.BlindRelay(upstream, **kwargs).start()
        self.resources.append(r)
        return r

    def test_direct_authenticated_tls_probe(self):
        peer = self.peer()
        result = lab.probe(peer.endpoint, None, self.client_identity, self.nonce)
        self.assertEqual(result.path, "direct")
        self.assertEqual(result.response, b"ACK:" + self.nonce)
        self.assertEqual(result.peer_common_name, "omega-peer")
        self.assertEqual(result.tls_version, "TLSv1.3")
        self.assertEqual(peer.authenticated_clients, 1)

    def test_relay_fallback_preserves_end_to_end_tls(self):
        peer = self.peer()
        relay = self.relay(peer.endpoint)
        missing_direct = lab.Endpoint("127.0.0.1", unused_port())
        result = lab.probe(missing_direct, relay.endpoint,
                           self.client_identity, self.nonce)
        self.assertEqual(result.path, "relay")
        self.assertEqual(result.response, b"ACK:" + self.nonce)
        self.assertGreater(relay.bytes_forwarded, len(self.nonce))
        self.assertNotIn(self.nonce, bytes(relay.wire_sample),
                         "The relay must only see TLS records, not synthetic plaintext")

    def test_relay_can_handle_multiple_authenticated_sessions(self):
        peer = self.peer()
        relay = self.relay(peer.endpoint)
        offline = lab.Endpoint("127.0.0.1", unused_port())
        self.assertEqual(lab.probe(offline, relay.endpoint,
                         self.client_identity, self.nonce).path, "relay")
        self.assertEqual(lab.probe(offline, relay.endpoint,
                         self.client_identity, self.nonce + b"2").path, "relay")
        self.assertEqual(peer.authenticated_clients, 2)

    def test_no_path_does_not_degrade_to_direct_internet(self):
        closed = lab.Endpoint("127.0.0.1", unused_port())
        with self.assertRaises(lab.NoAuthenticatedPath):
            lab.probe(closed, None, self.client_identity, self.nonce)

    def test_both_paths_down_fail_closed(self):
        a = lab.Endpoint("127.0.0.1", unused_port())
        b = lab.Endpoint("127.0.0.1", unused_port())
        with self.assertRaises(lab.NoAuthenticatedPath):
            lab.probe(a, b, self.client_identity, self.nonce)

    def test_malicious_discovery_wrong_peer_certificate_fails(self):
        spoof = self.peer(self.other_identity)
        relay = self.relay(spoof.endpoint)
        with self.assertRaises(lab.PeerAuthenticationError):
            lab.probe(spoof.endpoint, relay.endpoint,
                      self.client_identity, self.nonce)
        self.assertEqual(relay.bytes_forwarded, 0,
                         "Never retry an authenticated identity failure via relay")

    def test_relay_tampering_detected_by_tls(self):
        peer = self.peer()
        relay = self.relay(peer.endpoint, corrupt_handshake=True)
        closed = lab.Endpoint("127.0.0.1", unused_port())
        with self.assertRaises(lab.PeerAuthenticationError):
            lab.probe(closed, relay.endpoint, self.client_identity, self.nonce)

    def test_bad_client_without_certificate_cannot_send_probe(self):
        peer = self.peer()
        with socket.create_connection((peer.endpoint.ip, peer.endpoint.port)) as raw:
            context = __import__("ssl").create_default_context(
                cafile=str(self.client_identity.ca))
            context.minimum_version = __import__("ssl").TLSVersion.TLSv1_3
            with context.wrap_socket(raw, server_hostname="omega-peer") as s:
                with self.assertRaises((OSError, EOFError)):
                    lab._send_frame(s, self.nonce)
                    lab._read_frame(s)
        self.assertEqual(peer.authenticated_clients, 0)

    def test_safety_guard_rejects_public_destinations(self):
        with self.assertRaises(ValueError):
            lab.Endpoint("8.8.8.8", 443)
        with self.assertRaises(ValueError):
            lab.Endpoint("127.0.0.1", 0)
        with self.assertRaises(ValueError):
            lab.probe(lab.Endpoint("127.0.0.1", unused_port()), None,
                      self.client_identity, b"tiny")


if __name__ == "__main__":
    unittest.main()
