"""Regression tests for the wire protocol implemented by ``pi_node.py``.

Two groups of defects are locked down here:

* hostile or malformed input used to escape the top-level handler as a raw
  ``KeyError``/``AttributeError``/``IndexError``/``TypeError``/``InvalidSignature``
  traceback instead of a clean ``ProtocolError``; and
* session bookkeeping (sequence numbers, termination after a failed decrypt,
  the ``accept()`` timeout, and key zeroization on ``close()``).

Everything is in-process: no sockets are opened except by the single
``open_server`` timeout test, and no file is ever written.
"""

import contextlib
import hashlib
import io
import json
import os
import socket
import sys
import time
import unittest

# Make the suite runnable from ANY working directory: ``unittest discover -s
# <dir>`` puts the *start* directory on sys.path, not the repository root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from ECC_Integration.ECC_Core import ECCCore  # noqa: E402
from pi_node import (  # noqa: E402
    HANDSHAKE_LABEL,
    MAX_FRAME_SIZE,
    MESSAGE_FIELDS,
    PROTOCOL_VERSION,
    ProtocolError,
    SecurePiNode,
    b64,
    canonical_json,
    open_server,
    receive_frame,
    send_frame,
    tamper_packet,
    unb64,
)

# Exceptions that a hostile packet must NEVER be allowed to leak. None of them
# is a subclass of ValueError, so the old top-level handler let them through.
FORBIDDEN_EXCEPTIONS = (
    KeyError,
    AttributeError,
    IndexError,
    TypeError,
    InvalidSignature,
)


def new_node(node_id="pi-a", peer_id="pi-b", key=None):
    """Build a node without touching the filesystem (as the tests always did)."""
    node = SecurePiNode.__new__(SecurePiNode)
    node.node_id = node_id
    node.expected_peer_id = peer_id
    node.session_key = key if key is not None else hashlib.sha256(b"node-key").digest()[:16]
    node.send_sequence = 0
    node.receive_sequence = 0
    node.session_valid = True
    return node


def flip(value):
    """Return base64 of *value* with its first byte flipped."""
    raw = bytearray(unb64(value))
    raw[0] ^= 1
    return b64(bytes(raw))


class RejectionMixin:
    """Assert that hostile input is rejected cleanly."""

    def assert_rejected(self, label, call, strict=True):
        """*call* must be rejected and must never leak a raw Python exception.

        With ``strict`` (the default) the rejection must be a ``ProtocolError``.
        With ``strict=False`` any ``ValueError`` is accepted -- ``binascii.Error``
        from base64 decoding is a ``ValueError``, so the node still reports a
        clean ``{"event": "error"}`` line and exits non-zero.
        """
        try:
            call()
        except FORBIDDEN_EXCEPTIONS as error:  # pragma: no cover - the bug being locked down
            self.fail(f"{label} leaked a raw {type(error).__name__}: {error}")
        except ValueError as error:
            self.assertIsInstance(
                error, ValueError, f"{label} did not raise a ValueError"
            )
            if strict:
                self.assertIsInstance(
                    error,
                    ProtocolError,
                    f"{label} raised {type(error).__name__} instead of ProtocolError: {error}",
                )
            for forbidden in FORBIDDEN_EXCEPTIONS:
                self.assertNotIsInstance(
                    error,
                    forbidden,
                    f"{label} leaked {forbidden.__name__} instead of ProtocolError",
                )
            return
        except Exception as error:  # noqa: BLE001 - deliberately broad
            self.fail(
                f"{label} raised {type(error).__name__} instead of ProtocolError: {error}"
            )
        self.fail(f"{label} was accepted")


class TestPiNodePackets(unittest.TestCase):
    def setUp(self):
        self.sender = SecurePiNode.__new__(SecurePiNode)
        self.receiver = SecurePiNode.__new__(SecurePiNode)
        key = hashlib.sha256(b"packet-test-key").digest()[:16]
        for node, node_id, peer_id in (
            (self.sender, "pi-a", "pi-b"),
            (self.receiver, "pi-b", "pi-a"),
        ):
            node.node_id = node_id
            node.expected_peer_id = peer_id
            node.session_key = key
            node.send_sequence = 0
            node.receive_sequence = 0

    def test_packet_round_trip(self):
        packet = self.sender.encrypt("authenticated payload")
        self.assertEqual(self.receiver.decrypt(packet), "authenticated payload")

    def test_ciphertext_tampering_is_rejected(self):
        packet = self.sender.encrypt("authenticated payload")
        ciphertext = bytearray(unb64(packet["ciphertext"]))
        ciphertext[0] ^= 1
        packet["ciphertext"] = b64(bytes(ciphertext))
        with self.assertRaises(ValueError):
            self.receiver.decrypt(packet)

    def test_replayed_sequence_is_rejected(self):
        packet = self.sender.encrypt("authenticated payload")
        self.receiver.decrypt(packet)
        with self.assertRaises(ValueError):
            self.receiver.decrypt(packet)


class TestHostilePackets(RejectionMixin, unittest.TestCase):
    """Malformed message packets must raise ProtocolError, never crash the node."""

    def setUp(self):
        self.sender = new_node("pi-a", "pi-b")
        self.receiver = new_node("pi-b", "pi-a")

    def valid_packet(self):
        """A packet that decrypts cleanly, to be mutated by the tests below."""
        return self.sender.encrypt("payload")

    def test_missing_sequence_field_is_rejected(self):
        """A packet without 'sequence' must not raise KeyError"""
        packet = self.valid_packet()
        del packet["sequence"]
        self.assert_rejected(
            "packet missing 'sequence'", lambda: self.receiver.decrypt(packet)
        )

    def test_extra_field_is_rejected(self):
        """An unexpected extra field must be rejected, not silently ignored"""
        packet = self.valid_packet()
        packet["admin"] = True
        self.assert_rejected("packet with extra field", lambda: self.receiver.decrypt(packet))

    def test_packet_that_is_not_a_dict_is_rejected(self):
        """Non-object JSON values must be rejected without AttributeError/TypeError"""
        for value in (["not", "a", "dict"], "a string", 42, None, True):
            with self.subTest(value=value):
                self.assert_rejected(
                    f"packet {value!r}", lambda value=value: self.receiver.decrypt(value)
                )

    def test_boolean_sequence_is_rejected(self):
        """`true` is a bool, and bool subclasses int: it must still be rejected"""
        packet = self.valid_packet()
        packet["sequence"] = True
        self.assert_rejected("boolean sequence", lambda: self.receiver.decrypt(packet))

    def test_float_sequence_is_rejected(self):
        """A float sequence must be rejected rather than accepted as an int"""
        packet = self.valid_packet()
        packet["sequence"] = 1.0
        self.assert_rejected("float sequence", lambda: self.receiver.decrypt(packet))

    def test_non_string_nonce_is_rejected(self):
        """A list nonce must not reach base64 decoding (AttributeError/TypeError)"""
        packet = self.valid_packet()
        packet["nonce"] = []
        self.assert_rejected("list nonce", lambda: self.receiver.decrypt(packet))

    def test_non_string_ciphertext_and_tag_are_rejected(self):
        """Non-string ciphertext/tag/sender/type must all be rejected cleanly"""
        for field in ("ciphertext", "tag", "sender", "type"):
            for value in ([], 0, None, {"nested": 1}):
                with self.subTest(field=field, value=value):
                    packet = self.valid_packet()
                    packet[field] = value
                    self.assert_rejected(
                        f"{field}={value!r}",
                        lambda packet=packet: self.receiver.decrypt(packet),
                    )

    def test_missing_fields_are_rejected_one_by_one(self):
        """Dropping any single required field must be a clean rejection"""
        for field in MESSAGE_FIELDS:
            with self.subTest(field=field):
                packet = self.valid_packet()
                del packet[field]
                self.assert_rejected(
                    f"packet missing {field!r}",
                    lambda packet=packet: self.receiver.decrypt(packet),
                )

    def test_wrong_sender_is_rejected(self):
        """A packet claiming to come from a third node must be rejected"""
        intruder = new_node("pi-c", "pi-b", key=self.receiver.session_key)
        packet = intruder.encrypt("payload")
        self.assert_rejected("packet from pi-c", lambda: self.receiver.decrypt(packet))

    def test_unsupported_version_is_rejected(self):
        """A v1 packet must be rejected cleanly"""
        packet = self.valid_packet()
        packet["version"] = 1
        self.assert_rejected("packet with version 1", lambda: self.receiver.decrypt(packet))

    def test_non_base64_payload_is_rejected(self):
        """Invalid base64 must be a clean ValueError, not a raw crash.

        ``binascii.Error`` is itself a ``ValueError``, so ``run()``'s handler
        still prints ``{"event": "error", ...}`` and exits non-zero; it is not
        normalised to ``ProtocolError`` the way the handshake signature is.
        """
        for field in ("ciphertext", "tag", "nonce"):
            with self.subTest(field=field):
                packet = self.valid_packet()
                packet[field] = "!!! not base64 !!!"
                self.assert_rejected(
                    f"non-base64 {field}",
                    lambda packet=packet: self.receiver.decrypt(packet),
                    strict=False,
                )


class TestHostileHandshakes(RejectionMixin, unittest.TestCase):
    """Hostile hello frames must fail authentication cleanly."""

    def setUp(self):
        # The pinned peer identity for the node under test.
        self.trusted_private = ec.generate_private_key(ec.SECP256R1())
        self.attacker_private = ec.generate_private_key(ec.SECP256R1())

        self.node = new_node("pi-b", "pi-a")
        self.node.peer_identity_public = self.trusted_private.public_key()
        self.node.ecdh = ECCCore()

    def hello(self, private_key=None, **overrides):
        """Build a well-formed hello, optionally signed by another key."""
        ephemeral = ECCCore()
        ephemeral.generate_keypair()
        hello = {
            "version": PROTOCOL_VERSION,
            "node_id": "pi-a",
            "ecdh_public_key": b64(ephemeral.get_public_key_bytes()),
        }
        signer = private_key if private_key is not None else self.trusted_private
        hello["signature"] = b64(
            signer.sign(
                HANDSHAKE_LABEL + canonical_json(hello), ec.ECDSA(hashes.SHA256())
            )
        )
        hello.update(overrides)
        return hello

    def test_well_formed_hello_is_accepted(self):
        """Positive control: a correctly signed hello still verifies"""
        hello = self.hello()
        peer_ecdh = self.node._verify_hello(hello)
        self.assertEqual(len(peer_ecdh), 65, "uncompressed P-256 point expected")

    def test_non_string_signature_is_rejected(self):
        """`signature: 0` must be rejected before any base64/ECDSA work"""
        hello = self.hello(signature=0)
        self.assert_rejected("non-string signature", lambda: self.node._verify_hello(hello))

    def test_hello_signed_by_the_wrong_key_is_rejected(self):
        """A well-formed hello from an unpinned key must fail authentication"""
        hello = self.hello(private_key=self.attacker_private)
        self.assert_rejected(
            "hello signed by the wrong key", lambda: self.node._verify_hello(hello)
        )

    def test_random_signature_is_rejected(self):
        """A random 64-byte signature must be a clean auth failure"""
        hello = self.hello(signature=b64(os.urandom(64)))
        self.assert_rejected(
            "random 64-byte signature", lambda: self.node._verify_hello(hello)
        )

    def test_non_base64_signature_is_rejected(self):
        """A signature that is not base64 must be a clean rejection"""
        hello = self.hello(signature="this is not base64 !!")
        self.assert_rejected(
            "non-base64 signature", lambda: self.node._verify_hello(hello)
        )

    def test_unexpected_extra_field_is_rejected(self):
        """The old v1 `challenge` field must be rejected, not ignored"""
        hello = self.hello(challenge="deadbeef")
        self.assert_rejected("hello with extra 'challenge'", lambda: self.node._verify_hello(hello))

    def test_missing_field_is_rejected(self):
        """A hello missing any required field must be rejected cleanly"""
        for field in ("version", "node_id", "ecdh_public_key", "signature"):
            with self.subTest(field=field):
                hello = self.hello()
                del hello[field]
                self.assert_rejected(
                    f"hello missing {field!r}", lambda hello=hello: self.node._verify_hello(hello)
                )

    def test_non_string_fields_are_rejected(self):
        """Non-string node_id/ecdh_public_key must be rejected cleanly"""
        for field in ("node_id", "ecdh_public_key"):
            for value in (0, [], None, {"a": 1}):
                with self.subTest(field=field, value=value):
                    hello = self.hello(**{field: value})
                    self.assert_rejected(
                        f"hello {field}={value!r}",
                        lambda hello=hello: self.node._verify_hello(hello),
                    )

    def test_non_dict_hello_is_rejected(self):
        """A hello that is not a JSON object must be rejected cleanly"""
        for value in (["pi-a"], "hello", 7, None):
            with self.subTest(value=value):
                self.assert_rejected(
                    f"hello {value!r}", lambda value=value: self.node._verify_hello(value)
                )

    def test_boolean_version_is_rejected(self):
        """`version: true` must not pass the integer check"""
        hello = self.hello(version=True)
        self.assert_rejected("boolean version", lambda: self.node._verify_hello(hello))

    def test_wrong_peer_identity_is_rejected(self):
        """A hello from a node that is not the pinned peer must be rejected"""
        hello = self.hello(node_id="pi-z")
        self.assert_rejected("hello from pi-z", lambda: self.node._verify_hello(hello))

    def test_unsupported_version_is_rejected(self):
        """A hello claiming protocol v1 must be rejected"""
        hello = self.hello(version=1)
        self.assert_rejected("hello with version 1", lambda: self.node._verify_hello(hello))


class TestReceiveFrame(unittest.TestCase):
    """Bytes on the wire must never produce an unhandled exception."""

    def test_invalid_utf8_is_a_value_error(self):
        """Raw invalid UTF-8 must raise ValueError, not UnicodeDecodeError escaping"""
        with self.assertRaises(ValueError):
            receive_frame(io.BytesIO(b"\xff\xfe\x00 not utf-8 \n"))

    def test_non_json_is_a_value_error(self):
        """A non-JSON line must raise ValueError"""
        with self.assertRaises(ValueError):
            receive_frame(io.BytesIO(b"definitely not json\n"))

    def test_json_that_is_not_an_object_is_rejected(self):
        """A JSON array, string or number is not an acceptable frame"""
        for payload in (b"[1, 2, 3]\n", b'"a string"\n', b"42\n", b"null\n"):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    receive_frame(io.BytesIO(payload))

    def test_oversized_frame_is_rejected(self):
        """A frame larger than MAX_FRAME_SIZE must be refused"""
        payload = b"x" * (MAX_FRAME_SIZE + 2)
        with self.assertRaises(ValueError):
            receive_frame(io.BytesIO(payload))

    def test_closed_stream_is_a_connection_error(self):
        """An empty stream means the peer closed the connection"""
        with self.assertRaises(ConnectionError):
            receive_frame(io.BytesIO(b""))

    def test_well_formed_frame_round_trips(self):
        """Positive control: send_frame and receive_frame agree"""
        stream = io.BytesIO()
        send_frame(stream, {"event": "ping", "sequence": 1})
        stream.seek(0)
        self.assertEqual(receive_frame(stream), {"event": "ping", "sequence": 1})


class TestTamperPacket(unittest.TestCase):
    """`tamper_packet` must always flip something, even for an empty message."""

    def setUp(self):
        self.sender = new_node("pi-a", "pi-b")
        self.receiver = new_node("pi-b", "pi-a")

    def test_empty_ciphertext_flips_the_tag(self):
        """Regression: an empty message has no ciphertext, so the tag is flipped"""
        packet = self.sender.encrypt("")
        self.assertEqual(unb64(packet["ciphertext"]), b"", "expected an empty ciphertext")
        original_tag = unb64(packet["tag"])

        tampered = tamper_packet(packet)

        self.assertEqual(
            len(unb64(tampered["tag"])), 16, "the tag must stay 16 bytes long"
        )
        self.assertNotEqual(unb64(tampered["tag"]), original_tag, "the tag was not flipped")
        self.assertEqual(tampered["ciphertext"], packet["ciphertext"])

    def test_empty_ciphertext_packet_is_rejected_by_the_peer(self):
        """The tampered empty-message packet must fail ASCON authentication"""
        packet = tamper_packet(self.sender.encrypt(""))
        with self.assertRaises(ValueError) as context:
            self.receiver.decrypt(packet)
        self.assertNotIsInstance(context.exception, IndexError)

    def test_non_empty_ciphertext_flips_the_ciphertext(self):
        """Regression: a normal packet has its ciphertext flipped, not its tag"""
        packet = self.sender.encrypt("a real message")
        original_ciphertext = unb64(packet["ciphertext"])
        original_tag = unb64(packet["tag"])
        self.assertNotEqual(original_ciphertext, b"")

        tampered = tamper_packet(packet)

        self.assertNotEqual(
            unb64(tampered["ciphertext"]), original_ciphertext, "ciphertext was not flipped"
        )
        self.assertEqual(
            len(unb64(tampered["ciphertext"])),
            len(original_ciphertext),
            "flipping must not change the ciphertext length",
        )
        self.assertEqual(unb64(tampered["tag"]), original_tag, "the tag must be untouched")

    def test_non_empty_ciphertext_packet_is_rejected_by_the_peer(self):
        """The tampered packet must fail ASCON authentication"""
        packet = tamper_packet(self.sender.encrypt("a real message"))
        with self.assertRaises(ValueError) as context:
            self.receiver.decrypt(packet)
        self.assertNotIsInstance(context.exception, IndexError)

    def test_untamperable_packet_raises_value_error_not_index_error(self):
        """A packet with neither ciphertext nor tag must raise ValueError"""
        packet = self.sender.encrypt("")
        packet["tag"] = b64(b"")
        try:
            tamper_packet(packet)
        except IndexError as error:
            self.fail(f"tamper_packet raised IndexError: {error}")
        except ValueError:
            pass
        else:
            self.fail("tamper_packet accepted a packet it cannot tamper")


class TestSequenceHandling(unittest.TestCase):
    """Sequence bookkeeping and session termination after any failure."""

    def setUp(self):
        self.sender = new_node("pi-a", "pi-b")
        self.receiver = new_node("pi-b", "pi-a")

    def test_duplicate_sequence_is_rejected(self):
        """Replaying the same packet must be refused"""
        packet = self.sender.encrypt("first")
        self.receiver.decrypt(packet)
        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(packet)

    def test_skipped_sequence_is_rejected(self):
        """A gap in the sequence must be refused, not silently accepted"""
        first, second, third = (self.sender.encrypt(text) for text in ("one", "two", "three"))
        self.assertEqual(self.receiver.decrypt(first), "one")
        self.assertEqual(second["sequence"], 2)

        with self.assertRaises(ProtocolError) as context:
            self.receiver.decrypt(third)
        self.assertIn(
            "out-of-order",
            str(context.exception),
            "a skipped sequence must be reported as an ordering failure",
        )

    def test_future_sequence_is_rejected(self):
        """A packet from the future must be refused"""
        packets = [self.sender.encrypt(f"message {index}") for index in range(1, 5)]
        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(packets[3])

    def test_failed_decrypt_terminates_the_session(self):
        """Regression: a failed decrypt must not leave a desynchronized session"""
        good = self.sender.encrypt("first")
        self.receiver.decrypt(good)

        bad = self.sender.encrypt("second")
        bad["tag"] = flip(bad["tag"])
        with self.assertRaises(ValueError):
            self.receiver.decrypt(bad)

        self.assertFalse(
            self.receiver.session_valid,
            "the session must be terminated after a failed decryption",
        )

        follow_up = self.sender.encrypt("third")
        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(follow_up)

    def test_encrypt_is_refused_after_a_failed_decrypt(self):
        """A terminated session must not keep sending"""
        bad = self.sender.encrypt("first")
        bad["ciphertext"] = flip(bad["ciphertext"])
        with self.assertRaises(ValueError):
            self.receiver.decrypt(bad)

        with self.assertRaises(ProtocolError):
            self.receiver.encrypt("should not be sent")

    def test_malformed_packet_also_terminates_the_session(self):
        """A structural rejection terminates the session too, not just ASCON"""
        packet = self.sender.encrypt("first")
        del packet["sequence"]
        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(packet)

        self.assertFalse(self.receiver.session_valid)
        with self.assertRaises(ProtocolError):
            self.receiver.encrypt("should not be sent")

    def test_sequence_advances_only_on_success(self):
        """A rejected packet must not advance the receiver's sequence counter"""
        first = self.sender.encrypt("one")
        dropped = self.sender.encrypt("two")
        third = self.sender.encrypt("three")
        self.assertEqual(dropped["sequence"], 2)

        self.receiver.decrypt(first)
        self.assertEqual(self.receiver.receive_sequence, 1)

        with self.assertRaises(ProtocolError):
            self.receiver.decrypt(third)
        self.assertEqual(
            self.receiver.receive_sequence,
            1,
            "a rejected packet must not move the receive sequence",
        )


class TestOpenServerTimeout(unittest.TestCase):
    """Regression: accept() used to block forever with no client."""

    def test_server_without_a_client_raises_value_error(self):
        """A server with a short timeout must raise ValueError, not hang"""
        buffer = io.StringIO()
        started = time.monotonic()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(ValueError) as context:
                open_server("127.0.0.1", 0, 1.0)
        elapsed = time.monotonic() - started

        self.assertNotIsInstance(
            context.exception,
            socket.timeout,
            "socket.timeout must be converted to ValueError",
        )
        self.assertIn("no client connected", str(context.exception))
        self.assertLess(elapsed, 10, "the accept timeout must be honoured promptly")

    def test_listening_event_is_reported_before_accepting(self):
        """The server announces the port it bound before it blocks in accept()"""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with self.assertRaises(ValueError):
                open_server("127.0.0.1", 0, 1.0)

        events = [
            json.loads(line)
            for line in buffer.getvalue().splitlines()
            if line.strip().startswith("{")
        ]
        self.assertTrue(events, "the server printed no listening event")
        self.assertEqual(events[0]["event"], "listening")


class TestSessionTeardown(unittest.TestCase):
    """Regression: close() must zeroize the session and print nothing."""

    def make_node_with_a_live_session(self):
        node = new_node("pi-a", "pi-b")
        node.ecdh = ECCCore()
        node.ecdh.generate_keypair()
        peer = ECCCore()
        peer.generate_keypair()
        node.ecdh.compute_shared_secret(
            node.ecdh.load_peer_public_key(peer.get_public_key_bytes())
        )
        node.session_key = hashlib.sha256(b"live-session").digest()[:16]
        node.session_valid = True
        return node

    def test_close_zeroizes_the_session_and_prints_nothing(self):
        """close() clears the key, invalidates the session and says nothing"""
        node = self.make_node_with_a_live_session()
        self.assertIsNotNone(node.ecdh.private_key)
        self.assertIsNotNone(node.ecdh.shared_secret)

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            node.close()

        self.assertEqual(
            buffer.getvalue(), "", "close() must not print anything"
        )
        self.assertIsNone(node.session_key, "the session key must be cleared")
        self.assertFalse(node.session_valid, "the session must be marked invalid")
        self.assertIsNone(
            node.ecdh.private_key, "the ECDH private key must be cleared"
        )
        self.assertIsNone(
            node.ecdh.shared_secret, "the ECDH shared secret must be cleared"
        )

    def test_close_is_idempotent_and_still_silent(self):
        """Calling close() twice is safe and still prints nothing"""
        node = self.make_node_with_a_live_session()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            node.close()
            node.close()

        self.assertEqual(buffer.getvalue(), "")
        self.assertIsNone(node.session_key)
        self.assertFalse(node.session_valid)

    def test_no_crypto_after_close(self):
        """A closed node must refuse to encrypt or decrypt"""
        node = self.make_node_with_a_live_session()
        packet = node.encrypt("before close")
        node.close()

        with self.assertRaises((RuntimeError, ProtocolError)):
            node.encrypt("after close")
        with self.assertRaises((RuntimeError, ProtocolError)):
            node.decrypt(packet)


if __name__ == "__main__":
    unittest.main()
