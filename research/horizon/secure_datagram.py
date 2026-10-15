"""Ω Horizon G2 research datagram record layer. LABORATORY ONLY.

Uses vetted cryptography primitives: HKDF-SHA256 and ChaCha20-Poly1305.
A 32-byte *pre-shared* test secret is provisioned out of band to two peers.
No authenticated key exchange, PFS, post-compromise recovery, multi-user
discovery, production key storage, VPN/TUN, or real Internet exit is provided.

Do not use this proof-of-concept as a new production VPN protocol.
"""

from __future__ import annotations

import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"OHG2"
VERSION = 1
HEADER = struct.Struct("!4sB16sQ")
TAG_BYTES = 16
MAX_PLAINTEXT = 256
REPLAY_WINDOW = 128
KEY_BYTES = 32
SESSION_BYTES = 16
MAX_SEQUENCE = (1 << 64) - 1
CONTEXT = b"omega-horizon-isolated-research-g2/aead/v1"


class RecordRejected(ValueError):
    """Invalid ciphertext, invalid peer session or unknown protocol version."""


class ReplayRejected(RecordRejected):
    """Authenticated message has already been accepted or is too old."""


class RecordSession:
    """Directional lab-only AEAD state.

    Client creates random session_id; peer accepts only the first *valid*
    session id and pins it. Path (direct vs relay) is NOT part of AAD, allowing
    identical authenticated identity across path migration. A relay cannot
    construct a valid AEAD record without the out-of-band test key.

    No persistent anti-replay across peer restarts. NO forward secrecy.
    """

    def __init__(self, role: str, shared_secret: bytes,
                 session_id: bytes | None = None) -> None:
        if role not in ("client", "peer"):
            raise ValueError("unknown lab role")
        if not isinstance(shared_secret, bytes) or len(shared_secret) != KEY_BYTES:
            raise ValueError("lab secret must contain exactly 32 bytes")
        if session_id is not None and (
            not isinstance(session_id, bytes) or len(session_id) != SESSION_BYTES
        ):
            raise ValueError("session id must contain 16 bytes")
        if role == "client" and session_id is None:
            session_id = os.urandom(SESSION_BYTES)
        self.role = role
        self._shared_secret = shared_secret
        self.session_id = session_id
        self.next_sequence = 0
        self.max_received: int | None = None
        self.received_bitmap = 0
        self._send: ChaCha20Poly1305 | None = None
        self._recv: ChaCha20Poly1305 | None = None
        if session_id is not None:
            self._derive(session_id)

    def _derive(self, session_id: bytes) -> None:
        keys = HKDF(algorithm=hashes.SHA256(), length=64,
                    salt=session_id, info=CONTEXT).derive(self._shared_secret)
        send_key, recv_key = ((keys[:32], keys[32:])
                              if self.role == "client"
                              else (keys[32:], keys[:32]))
        self._send = ChaCha20Poly1305(send_key)
        self._recv = ChaCha20Poly1305(recv_key)

    @staticmethod
    def _nonce(sequence: int) -> bytes:
        # The directional key is unique within a session; an 8-byte sequence
        # suffix is never reused by one sender until the session is destroyed.
        return b"\0" * 4 + sequence.to_bytes(8, "big")

    def seal(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes) or not 1 <= len(plaintext) <= MAX_PLAINTEXT:
            raise ValueError("only short non-empty synthetic lab payloads")
        if self.session_id is None or self._send is None:
            raise RecordRejected("peer cannot respond before valid first record")
        if self.next_sequence > MAX_SEQUENCE:
            raise RecordRejected("session requires rotation before sequence wrap")
        sequence = self.next_sequence
        self.next_sequence += 1
        header = HEADER.pack(MAGIC, VERSION, self.session_id, sequence)
        # Entire header (including identity and sequence) is AEAD-authenticated.
        encrypted = self._send.encrypt(self._nonce(sequence), plaintext,
                                        CONTEXT + header)
        return header + encrypted

    def open(self, wire: bytes) -> bytes:
        if not isinstance(wire, bytes) or not (
            HEADER.size + TAG_BYTES + 1 <= len(wire) <=
            HEADER.size + TAG_BYTES + MAX_PLAINTEXT
        ):
            raise RecordRejected("invalid record length")
        try:
            magic, version, session, sequence = HEADER.unpack_from(wire)
        except struct.error as exc:
            raise RecordRejected("invalid header") from exc
        if magic != MAGIC or version != VERSION:
            raise RecordRejected("unsupported lab record version")
        if self.session_id is not None and session != self.session_id:
            raise RecordRejected("record belongs to a different pinned session")
        if self.max_received is not None:
            if sequence <= self.max_received:
                distance = self.max_received - sequence
                if distance >= REPLAY_WINDOW or (self.received_bitmap >> distance) & 1:
                    raise ReplayRejected("record replayed or expired")

        derived = self._recv
        if derived is None:
            # Bootstrap peer with the first *authenticated* record only.
            material = HKDF(algorithm=hashes.SHA256(), length=64,
                            salt=session, info=CONTEXT).derive(self._shared_secret)
            derived = ChaCha20Poly1305(material[:32]) if self.role == "peer" else \
                      ChaCha20Poly1305(material[32:])
        try:
            plaintext = derived.decrypt(self._nonce(sequence),
                                        wire[HEADER.size:], CONTEXT + wire[:HEADER.size])
        except InvalidTag as exc:
            raise RecordRejected("record AEAD authentication failed") from exc
        if not plaintext:
            raise RecordRejected("empty payload")

        if self.session_id is None:
            self.session_id = session
            self._derive(session)

        # Update replay tracking *only after successful AEAD authentication*.
        if self.max_received is None:
            self.max_received = sequence
            self.received_bitmap = 1
        elif sequence > self.max_received:
            shift = sequence - self.max_received
            self.received_bitmap = ((self.received_bitmap << shift) | 1) & (
                (1 << REPLAY_WINDOW) - 1)
            self.max_received = sequence
        else:
            self.received_bitmap |= 1 << (self.max_received - sequence)
        return plaintext
