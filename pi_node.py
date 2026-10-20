#!/usr/bin/env python3
"""Runnable two-Raspberry-Pi secure communication node.

This file is the *signed artifact*: it performs mutual device authentication,
ECDH + HKDF key establishment, and ASCON-128a message exchange. Secure boot
(artifact hash/signature verification) is performed by ``secure_launcher.py``
before this module is executed, so nothing here reads the manufacturer key or
the artifact signature.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ECC_Integration.ASCON_Encryption import ASCONEncryption
from ECC_Integration.ECC_Core import ECCCore

PROTOCOL_VERSION = 2
MAX_FRAME_SIZE = 64 * 1024
HANDSHAKE_LABEL = b"ECC-RPI-SECURE-CHANNEL-v1"

HELLO_FIELDS = ("version", "node_id", "ecdh_public_key", "signature")
MESSAGE_FIELDS = ("version", "type", "sender", "sequence", "nonce", "ciphertext", "tag")


class ProtocolError(ValueError):
    """Raised for any malformed, replayed, or unauthenticated wire input."""


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def is_int(value: Any) -> bool:
    """True only for a real integer; ``bool`` is explicitly excluded."""
    return isinstance(value, int) and not isinstance(value, bool)


def send_frame(stream: socket.SocketIO, message: dict[str, Any]) -> None:
    encoded = json.dumps(message, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > MAX_FRAME_SIZE:
        raise ValueError("frame exceeds maximum size")
    stream.write(encoded + b"\n")
    stream.flush()


def receive_frame(stream: socket.SocketIO) -> dict[str, Any]:
    line = stream.readline(MAX_FRAME_SIZE + 1)
    if not line:
        raise ConnectionError("peer closed the connection")
    if len(line) > MAX_FRAME_SIZE or not line.endswith(b"\n"):
        raise ValueError("invalid or oversized frame")
    value = json.loads(line)  # invalid UTF-8/JSON raises ValueError
    if not isinstance(value, dict):
        raise ValueError("frame must contain a JSON object")
    return value


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def public_key_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def tamper_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Flip one bit of a packet so the peer's ASCON integrity check must fail.

    Falls back to the authentication tag when the ciphertext is empty (for
    example an empty ``--message``), so an empty payload cannot crash the flip.
    """
    ciphertext = unb64(packet["ciphertext"])
    if ciphertext:
        packet["ciphertext"] = b64(bytes([ciphertext[0] ^ 1]) + ciphertext[1:])
        return packet
    tag = unb64(packet["tag"])
    if not tag:
        raise ValueError("cannot tamper: packet carries no ciphertext or tag")
    packet["tag"] = b64(bytes([tag[0] ^ 1]) + tag[1:])
    return packet


class SecurePiNode:
    # Class-level default so tests that build a node with ``__new__`` still see
    # a live session unless they explicitly terminate it.
    session_valid: bool = True

    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.config = json.loads((config_dir / "node.json").read_text())
        self.node_id = self.config["node_id"]
        self.expected_peer_id = self.config["peer_id"]
        self.identity_private = load_private_key(
            config_dir / self.config["identity_private_key"]
        )
        self.peer_identity_public = load_public_key(
            config_dir / self.config["peer_identity_public_key"]
        )
        self.ecdh = ECCCore()
        self.session_key: bytes | None = None
        self.session_valid = True
        self.send_sequence = 0
        self.receive_sequence = 0

    def close(self) -> None:
        """Zeroize the session key and ECDH state at end of session (stage 7)."""
        self.session_key = None
        self.session_valid = False
        self.ecdh.clear_sensitive_data()

    def _hello(self) -> dict[str, Any]:
        self.ecdh.generate_keypair()
        hello = {
            "version": PROTOCOL_VERSION,
            "node_id": self.node_id,
            "ecdh_public_key": b64(self.ecdh.get_public_key_bytes()),
        }
        signed = HANDSHAKE_LABEL + canonical_json(hello)
        hello["signature"] = b64(
            self.identity_private.sign(signed, ec.ECDSA(hashes.SHA256()))
        )
        return hello

    def _verify_hello(self, hello: dict[str, Any]) -> bytes:
        if not isinstance(hello, dict):
            raise ProtocolError("handshake must be a JSON object")
        if set(hello) != set(HELLO_FIELDS):
            raise ProtocolError("handshake contains unexpected or missing fields")
        if not is_int(hello["version"]):
            raise ProtocolError("handshake version must be an integer")
        for field in ("node_id", "ecdh_public_key", "signature"):
            if not isinstance(hello[field], str):
                raise ProtocolError(f"handshake field {field!r} must be a string")
        if hello["version"] != PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")
        if hello["node_id"] != self.expected_peer_id:
            raise ProtocolError("unexpected peer identity")

        unsigned = {key: hello[key] for key in HELLO_FIELDS if key != "signature"}
        try:
            signature = unb64(hello["signature"])
        except ValueError as error:
            raise ProtocolError("handshake signature is not valid base64") from error
        try:
            self.peer_identity_public.verify(
                signature,
                HANDSHAKE_LABEL + canonical_json(unsigned),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature as error:
            raise ProtocolError("peer identity signature verification failed") from error
        return unb64(hello["ecdh_public_key"])

    def establish_session(self, stream: socket.SocketIO, is_server: bool) -> None:
        local_hello = self._hello()
        if is_server:
            peer_hello = receive_frame(stream)
            peer_ecdh = self._verify_hello(peer_hello)
            send_frame(stream, local_hello)
        else:
            send_frame(stream, local_hello)
            peer_hello = receive_frame(stream)
            peer_ecdh = self._verify_hello(peer_hello)

        transcript = canonical_json(
            {
                "client": local_hello if not is_server else peer_hello,
                "server": local_hello if is_server else peer_hello,
            }
        )
        peer_public = self.ecdh.load_peer_public_key(peer_ecdh)
        shared_secret = self.ecdh.compute_shared_secret(peer_public)
        self.session_key = self.ecdh.derive_session_key(
            shared_secret, salt=hashlib.sha256(transcript).digest()
        )
        print(
            json.dumps(
                {
                    "event": "secure_channel",
                    "status": "ESTABLISHED",
                    "peer": self.expected_peer_id,
                    "key": "ECDH + HKDF-SHA256 + ASCON-128a",
                }
            )
        )

    def encrypt(self, message: str) -> dict[str, Any]:
        if self.session_key is None:
            raise RuntimeError("secure session is not established")
        if not self.session_valid:
            raise ProtocolError(
                "secure session was terminated after a previous failure"
            )
        self.send_sequence += 1
        packet = {
            "version": PROTOCOL_VERSION,
            "type": "message",
            "sender": self.node_id,
            "sequence": self.send_sequence,
        }
        aad = canonical_json(packet)
        nonce, ciphertext, tag = ASCONEncryption(self.session_key).encrypt(
            message.encode(), associated_data=aad
        )
        packet.update({"nonce": b64(nonce), "ciphertext": b64(ciphertext), "tag": b64(tag)})
        return packet

    def decrypt(self, packet: dict[str, Any]) -> str:
        if self.session_key is None:
            raise RuntimeError("secure session is not established")
        if not self.session_valid:
            raise ProtocolError(
                "secure session was terminated after a previous failure"
            )
        try:
            return self._decrypt(packet)
        except ValueError:
            # Any failed decryption may have desynchronized the sequence state,
            # so the session is terminated rather than silently continuing.
            self.session_valid = False
            raise

    def _decrypt(self, packet: dict[str, Any]) -> str:
        if not isinstance(packet, dict):
            raise ProtocolError("message packet must be a JSON object")
        if set(packet) != set(MESSAGE_FIELDS):
            raise ProtocolError("message packet has unexpected or missing fields")
        if not is_int(packet["version"]):
            raise ProtocolError("message version must be an integer")
        if not is_int(packet["sequence"]):
            raise ProtocolError("message sequence must be an integer")
        for field in ("type", "sender", "nonce", "ciphertext", "tag"):
            if not isinstance(packet[field], str):
                raise ProtocolError(f"message field {field!r} must be a string")

        metadata = {key: packet[key] for key in ("version", "type", "sender", "sequence")}
        if metadata["version"] != PROTOCOL_VERSION or metadata["type"] != "message":
            raise ProtocolError("unsupported message packet")
        if metadata["sender"] != self.expected_peer_id:
            raise ProtocolError("message sender is not the authenticated peer")
        sequence = metadata["sequence"]
        if sequence != self.receive_sequence + 1:
            raise ProtocolError("replayed or out-of-order message")

        try:
            nonce = unb64(packet["nonce"])
            ciphertext = unb64(packet["ciphertext"])
            tag = unb64(packet["tag"])
        except ValueError as error:
            # binascii.Error is a ValueError; normalize it the same way the
            # handshake path normalizes a malformed signature.
            raise ProtocolError("message packet contains invalid base64") from error

        try:
            plaintext = ASCONEncryption(self.session_key).decrypt(
                nonce,
                ciphertext,
                tag,
                associated_data=canonical_json(metadata),
            )
        except ValueError:
            # Expected ASCON integrity failure: keep the backend's message.
            raise
        except Exception as error:  # defensive: normalize any backend error
            raise ProtocolError("message could not be decrypted") from error
        self.receive_sequence = sequence
        return plaintext.decode("utf-8")


def open_server(host: str, port: int, timeout: float) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(timeout)
    print(json.dumps({"event": "listening", "host": host, "port": port}), flush=True)
    try:
        connection, address = server.accept()
    except socket.timeout as error:
        raise ValueError(
            f"no client connected within {timeout} seconds"
        ) from error
    finally:
        server.close()
    print(json.dumps({"event": "connected", "peer": address[0]}), flush=True)
    return connection


def run(args: argparse.Namespace) -> int:
    node = SecurePiNode(Path(args.config).resolve())
    try:
        connection = (
            open_server(args.host, args.port, args.timeout)
            if args.role == "server"
            else socket.create_connection((args.host, args.port), timeout=args.timeout)
        )
        connection.settimeout(args.timeout)
        with connection:
            with connection.makefile("rwb") as stream:
                node.establish_session(stream, args.role == "server")
                if args.role == "server":
                    packet = receive_frame(stream)
                    message = node.decrypt(packet)
                    print(json.dumps({"event": "received", "plaintext": message}))
                    reply = node.encrypt(args.reply)
                    send_frame(stream, reply)
                    print(json.dumps({"event": "sent", "sequence": reply["sequence"]}))
                else:
                    packet = node.encrypt(args.message)
                    if args.tamper:
                        packet = tamper_packet(packet)
                    send_frame(stream, packet)
                    print(
                        json.dumps(
                            {
                                "event": "sent",
                                "sequence": packet["sequence"],
                                "tampered": args.tamper,
                            }
                        )
                    )
                    try:
                        reply = receive_frame(stream)
                    except (OSError, ValueError) as error:
                        detail = (
                            "peer rejected the packet (ASCON authentication failed) "
                            "or closed the connection"
                        )
                        if args.tamper:
                            detail += "; this is the expected outcome of --tamper"
                        raise ValueError(f"{detail}: {error}") from error
                    print(json.dumps({"event": "received", "plaintext": node.decrypt(reply)}))
        return 0
    finally:
        node.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Secure Raspberry Pi communication node")
    result.add_argument("--config", required=True, help="provisioned node directory")
    result.add_argument("--role", choices=("server", "client"), required=True)
    result.add_argument("--host", required=True, help="server bind address or peer address")
    result.add_argument("--port", type=int, default=8765)
    result.add_argument("--timeout", type=float, default=15)
    result.add_argument("--message", default="Authenticated message from Raspberry Pi A")
    result.add_argument("--reply", default="Reply authenticated by Raspberry Pi B")
    result.add_argument("--tamper", action="store_true", help="flip ciphertext before sending")
    return result


if __name__ == "__main__":
    try:
        raise SystemExit(run(parser().parse_args()))
    except (OSError, ValueError, KeyError, AttributeError, TypeError, IndexError, AssertionError) as error:
        print(json.dumps({"event": "error", "message": str(error)}), file=sys.stderr)
        raise SystemExit(1)
