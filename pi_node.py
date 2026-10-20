#!/usr/bin/env python3
"""Runnable two-Raspberry-Pi secure communication node."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ECC_Integration.ASCON_Encryption import ASCONEncryption
from ECC_Integration.ECC_Core import ECCCore
from ECC_Integration.Secure_Boot import SecureBoot

PROTOCOL_VERSION = 1
MAX_FRAME_SIZE = 64 * 1024
HANDSHAKE_LABEL = b"ECC-RPI-SECURE-CHANNEL-v1"


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


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
    value = json.loads(line)
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


def verify_firmware(config: dict[str, Any], config_dir: Path) -> str:
    firmware = config_dir / config["firmware"]
    signature = config_dir / config["firmware_signature"]
    manufacturer_key = config_dir / config["manufacturer_public_key"]
    if not firmware.is_file() or not signature.is_file():
        raise FileNotFoundError("firmware or firmware signature is missing")
    secure_boot = SecureBoot(str(firmware), str(signature))
    secure_boot.load_signature_from_file()
    valid, digest = secure_boot.verify_firmware(load_public_key(manufacturer_key))
    if not valid:
        raise ValueError("secure boot rejected the firmware artifact")
    return digest.hex()


class SecurePiNode:
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
        self.send_sequence = 0
        self.receive_sequence = 0

    def secure_boot(self) -> str:
        digest = verify_firmware(self.config, self.config_dir)
        print(json.dumps({"event": "secure_boot", "status": "PASS", "sha256": digest}))
        return digest

    def _hello(self) -> dict[str, Any]:
        self.ecdh.generate_keypair()
        challenge = __import__("secrets").token_bytes(32)
        hello = {
            "version": PROTOCOL_VERSION,
            "node_id": self.node_id,
            "ecdh_public_key": b64(self.ecdh.get_public_key_bytes()),
            "challenge": b64(challenge),
        }
        signed = HANDSHAKE_LABEL + canonical_json(hello)
        hello["signature"] = b64(
            self.identity_private.sign(signed, ec.ECDSA(hashes.SHA256()))
        )
        return hello

    def _verify_hello(self, hello: dict[str, Any]) -> bytes:
        required = {"version", "node_id", "ecdh_public_key", "challenge", "signature"}
        if set(hello) != required:
            raise ValueError("handshake contains unexpected or missing fields")
        if hello["version"] != PROTOCOL_VERSION:
            raise ValueError("unsupported protocol version")
        if hello["node_id"] != self.expected_peer_id:
            raise ValueError("unexpected peer identity")
        unsigned = {key: hello[key] for key in required if key != "signature"}
        signature = unb64(hello["signature"])
        self.peer_identity_public.verify(
            signature,
            HANDSHAKE_LABEL + canonical_json(unsigned),
            ec.ECDSA(hashes.SHA256()),
        )
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
        metadata = {
            key: packet[key] for key in ("version", "type", "sender", "sequence")
        }
        if metadata["version"] != PROTOCOL_VERSION or metadata["type"] != "message":
            raise ValueError("unsupported message packet")
        if metadata["sender"] != self.expected_peer_id:
            raise ValueError("message sender is not the authenticated peer")
        sequence = metadata["sequence"]
        if not isinstance(sequence, int) or sequence != self.receive_sequence + 1:
            raise ValueError("replayed or out-of-order message")
        plaintext = ASCONEncryption(self.session_key).decrypt(
            unb64(packet["nonce"]),
            unb64(packet["ciphertext"]),
            unb64(packet["tag"]),
            associated_data=canonical_json(metadata),
        )
        self.receive_sequence = sequence
        return plaintext.decode("utf-8")


def open_server(host: str, port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(json.dumps({"event": "listening", "host": host, "port": port}), flush=True)
    connection, address = server.accept()
    print(json.dumps({"event": "connected", "peer": address[0]}), flush=True)
    server.close()
    return connection


def run(args: argparse.Namespace) -> int:
    node = SecurePiNode(Path(args.config).resolve())
    node.secure_boot()
    connection = (
        open_server(args.host, args.port)
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
                    packet["ciphertext"] = b64(
                        bytes([unb64(packet["ciphertext"])[0] ^ 1])
                        + unb64(packet["ciphertext"])[1:]
                    )
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
                reply = receive_frame(stream)
                print(json.dumps({"event": "received", "plaintext": node.decrypt(reply)}))
    return 0


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
    except (OSError, ValueError, ConnectionError) as error:
        print(json.dumps({"event": "error", "message": str(error)}), file=sys.stderr)
        raise SystemExit(1)
