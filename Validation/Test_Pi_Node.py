import hashlib
import unittest

from pi_node import SecurePiNode, b64, unb64


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


if __name__ == "__main__":
    unittest.main()
