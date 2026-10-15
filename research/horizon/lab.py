"""Ω Horizon transport feasibility lab. Loopback only; NO Internet egress or VPN data.

This is not an anonymity system, NAT traversal, Tor replacement, or production crypto.
It uses Python's OpenSSL-backed mutual TLS with ephemeral lab certificates.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
import select
import socket
import ssl
import struct
import threading
import time

MAX_PROBE = 128


class PeerAuthenticationError(RuntimeError):
    """TLS or peer-identity failure. Never downgrade to an unauthenticated path."""


class NoAuthenticatedPath(RuntimeError):
    """No candidate path established an authenticated session."""


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int

    def __post_init__(self) -> None:
        # Safety boundary: this experiment must never probe third-party IPs.
        if not ip_address(self.ip).is_loopback or not 1 <= self.port <= 65535:
            raise ValueError("lab endpoints must use loopback IP and valid port")


@dataclass(frozen=True)
class Identity:
    ca: Path
    cert: Path
    key: Path
    peer_dns_name: str
    peer_common_name: str


def _server_context(identity: Identity) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(identity.cert, identity.key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(identity.ca))
    return ctx


def _client_context(identity: Identity) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(identity.ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(identity.cert, identity.key)
    return ctx


def _common_name(cert: dict) -> str | None:
    for rdn in cert.get("subject", []):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def _read_exact(sock: ssl.SSLSocket, length: int) -> bytes:
    pieces: list[bytes] = []
    while length:
        chunk = sock.recv(length)
        if not chunk:
            raise EOFError("closed before complete framed test probe")
        pieces.append(chunk)
        length -= len(chunk)
    return b"".join(pieces)


def _read_frame(sock: ssl.SSLSocket) -> bytes:
    length = struct.unpack("!H", _read_exact(sock, 2))[0]
    if not 1 <= length <= MAX_PROBE:
        raise ValueError("invalid lab probe length")
    return _read_exact(sock, length)


def _send_frame(sock: ssl.SSLSocket, value: bytes) -> None:
    if not 1 <= len(value) <= MAX_PROBE:
        raise ValueError("invalid lab probe length")
    sock.sendall(struct.pack("!H", len(value)) + value)


@dataclass(frozen=True)
class ProbeResult:
    path: str
    response: bytes
    elapsed_ms: float
    peer_common_name: str
    tls_version: str


def probe(direct: Endpoint, relay: Endpoint | None, identity: Identity,
          nonce: bytes, timeout: float = 1.0) -> ProbeResult:
    """Prefer direct; fall back ONLY on connection failure, never authentication failure.

    The only allowed payload is a short synthetic test nonce. No TUN packets.
    """
    if not 8 <= len(nonce) <= MAX_PROBE - len(b"ACK:"):
        raise ValueError("synthetic nonce must be 8..124 bytes")
    if not 0 < timeout <= 5:
        raise ValueError("bounded timeouts only")

    context = _client_context(identity)
    errors: list[str] = []
    for path, endpoint in (("direct", direct), ("relay", relay)):
        if endpoint is None:
            continue
        before = time.monotonic()
        try:
            with socket.create_connection((endpoint.ip, endpoint.port), timeout=timeout) as raw:
                raw.settimeout(timeout)
                with context.wrap_socket(raw, server_hostname=identity.peer_dns_name) as secure:
                    name = _common_name(secure.getpeercert())
                    if name != identity.peer_common_name:
                        raise PeerAuthenticationError("server peer identity mismatch")
                    _send_frame(secure, nonce)
                    answer = _read_frame(secure)
                    if answer != b"ACK:" + nonce:
                        raise PeerAuthenticationError("unexpected authenticated peer response")
                    return ProbeResult(path=path, response=answer,
                                       elapsed_ms=(time.monotonic() - before) * 1000,
                                       peer_common_name=name,
                                       tls_version=secure.version())
        except (ssl.SSLError, PeerAuthenticationError) as exc:
            # A forged directory or relay must never induce a plaintext fallback.
            raise PeerAuthenticationError("TLS/identity check failed") from exc
        except (OSError, EOFError, ValueError) as exc:
            # A peer that fails after TLS establishment also fails closed; this
            # simple lab may try the relay, but never changes crypto settings.
            errors.append(f"{path}:{type(exc).__name__}")
    raise NoAuthenticatedPath("no authenticated path (" + ", ".join(errors) + ")")


class PeerServer:
    """Lab responder: authenticated client, bounded nonce, no user traffic."""

    def __init__(self, identity: Identity):
        self.identity = identity
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.15)
        self.endpoint = Endpoint("127.0.0.1", self._listener.getsockname()[1])
        self.stop_event = threading.Event()
        self.authenticated_clients = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "PeerServer":
        self._thread.start()
        return self

    def close(self) -> None:
        self.stop_event.set()
        self._listener.close()
        self._thread.join(timeout=3)

    def _serve(self) -> None:
        ctx = _server_context(self.identity)
        while not self.stop_event.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                connection.settimeout(2)
                with ctx.wrap_socket(connection, server_side=True) as secure:
                    if _common_name(secure.getpeercert()) != self.identity.peer_common_name:
                        continue
                    self.authenticated_clients += 1
                    _send_frame(secure, b"ACK:" + _read_frame(secure))
            except (ssl.SSLError, OSError, EOFError, ValueError):
                connection.close()


class BlindRelay:
    """Synthetic TCP relay. Does NOT terminate TLS, identify sites, or serve as exit."""

    def __init__(self, upstream: Endpoint, *, corrupt_handshake: bool = False):
        self.upstream = upstream
        self.corrupt_handshake = corrupt_handshake
        self.bytes_forwarded = 0
        # Lab-only capped copy of TLS records, never plaintext application data.
        self.wire_sample = bytearray()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.15)
        self.endpoint = Endpoint("127.0.0.1", self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "BlindRelay":
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=3)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                downstream, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with downstream, socket.create_connection(
                    (self.upstream.ip, self.upstream.port), timeout=2
                ) as upstream:
                    downstream.settimeout(2)
                    upstream.settimeout(2)
                    sockets = (downstream, upstream)
                    corrupted = False
                    alive = True
                    while alive and not self._stop.is_set():
                        ready, _, _ = select.select(sockets, [], [], 2)
                        if not ready:
                            break
                        for source in ready:
                            data = source.recv(4096)
                            if not data:
                                alive = False
                                break
                            # Tampering test: relay cannot modify authenticated TLS.
                            if self.corrupt_handshake and source is upstream and not corrupted:
                                data = bytes([data[0] ^ 0xFF]) + data[1:]
                                corrupted = True
                            target = downstream if source is upstream else upstream
                            target.sendall(data)
                            if len(self.wire_sample) < 16384:
                                self.wire_sample.extend(data[:16384 - len(self.wire_sample)])
                            self.bytes_forwarded += len(data)
            except (OSError, ValueError):
                pass
