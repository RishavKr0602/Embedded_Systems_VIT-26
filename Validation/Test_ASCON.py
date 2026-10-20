"""
ASCON-128a Validation Tests

Verifies the pure-Python ASCON-128a implementation in
ECC_Integration/ASCON_Encryption.py against the official known-answer vectors
published with the ascon-c reference implementation, and covers round-trip,
tamper-detection and input-validation behaviour.

Known-answer vectors are taken verbatim from:
    https://github.com/ascon/ascon-c  (branch v1.2)
    crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt

That file uses the official Count/Key/Nonce/AD/PT/CT/Tag format, except that
the published `CT` line contains ciphertext || tag concatenated (the `Tag`
line is therefore redundant and omitted here).  Each vector below is stored
as (label, Key, Nonce, AD, PT, CT) with every field hex-encoded, and the test
splits CT into ciphertext and tag at len(PT).

Run with:
    python3 -m unittest Validation.Test_ASCON -v
"""

import os
import re
import sys
import unittest
from pathlib import Path

# Make the repository root importable regardless of the working directory or
# the unittest top-level directory. `discover -s Validation` sets the top-level
# directory to Validation/ itself, which would otherwise hide ECC_Integration,
# pi_node and provision from the test modules.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ECC_Integration.ASCON_Encryption import ASCONEncryption  # noqa: E402


# ---------------------------------------------------------------------------
# Official Ascon-128a known-answer vectors (ascon-c v1.2, LWC_AEAD_KAT_128_128.txt)
#
# (label, Key, Nonce, AD, PT, CT) - CT includes the trailing 16-byte tag.
# ---------------------------------------------------------------------------

EMPTY_AD_EMPTY_PT = (
    "Count 1",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "",
    "",
    "7A834E6F09210957067B10FD831F0078",
)

EMPTY_AD_NONEMPTY_PT = (
    "Count 34",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "",
    "00",
    "6E652B55BFDC8CAD2EC43815B1666B1A3A",
)

NONEMPTY_AD_EMPTY_PT = (
    "Count 2",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "00",
    "",
    "AF3031B07B129EC84153373DDCABA528",
)

NONEMPTY_AD_NONEMPTY_PT = (
    "Count 35",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "00",
    "00",
    "E9C2813CC8C6DD2F245F3BB976DA566E9D",
)

# AD spans several blocks, no plaintext at all.
MULTIBLOCK_AD_EMPTY_PT = (
    "Count 33",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "",
    "2FDEE642B4C31C2F205DCC8B3DAD4542",
)

# AD length 17: not a multiple of the 16-byte rate.
NON_ALIGNED_AD_EMPTY_PT = (
    "Count 18",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F10",
    "",
    "917D530F34157158CF8CA49D01AF44F0",
)

# Plaintext length 17: one full block plus a partial final block.
NON_ALIGNED_PT = (
    "Count 562",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "",
    "000102030405060708090A0B0C0D0E0F10",
    "6E490CFED5B3546767350CD83C4ACFBD4C24A6876D90D20C110E12F5A5BE51967D",
)

# Plaintext exactly one block, AD not block aligned.
ONE_BLOCK_PT_ALIGNED_AD = (
    "Count 537",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "0001020304050607",
    "000102030405060708090A0B0C0D0E0F",
    "34D3B7EDB89B1D5067C4EC9EB8052962522E547863AC130D032A06927D4261DB",
)

# Both AD and plaintext multi-block, plaintext not block aligned.
MULTIBLOCK_AD_NON_ALIGNED_PT = (
    "Count 586",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F1011121314151617",
    "000102030405060708090A0B0C0D0E0F10",
    "8E2F9F14257FC5F035225857D43DCADA7F0BC2022E4EF3A3DA2DC7763BFCBF6A8D",
)

# Plaintext exactly two full blocks: exercises the rule that Ascon-128a applies
# NO p^8 after the final plaintext block (an extra padding-only block follows).
EXACT_TWO_BLOCK_PT = (
    "Count 1057",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "6E490CFED5B3546767350CD83C4ACFBD4CFB4BD07ABF5BC24D4B104645717C1E"
    "513ABFD1335ACFD296C49A35E0D54B73",
)

# Longest published vector: multi-block AD and multi-block plaintext.
MULTIBLOCK_AD_AND_PT = (
    "Count 1089",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "A55236AC020DBDA74CE6CCD10C68C4D8514450A382BC87C68946D86A921DD88E"
    "2ADDDFBBE77D4112830E01960B9D38D5",
)

ALL_KAT_VECTORS = (
    EMPTY_AD_EMPTY_PT,
    EMPTY_AD_NONEMPTY_PT,
    NONEMPTY_AD_EMPTY_PT,
    NONEMPTY_AD_NONEMPTY_PT,
    MULTIBLOCK_AD_EMPTY_PT,
    NON_ALIGNED_AD_EMPTY_PT,
    NON_ALIGNED_PT,
    ONE_BLOCK_PT_ALIGNED_AD,
    MULTIBLOCK_AD_NON_ALIGNED_PT,
    EXACT_TWO_BLOCK_PT,
    MULTIBLOCK_AD_AND_PT,
)


def split_vector(vector):
    """Split a KAT tuple into (label, key, nonce, ad, pt, ct, tag) as bytes."""
    label, key, nonce, ad, pt, ct = vector
    key = bytes.fromhex(key)
    nonce = bytes.fromhex(nonce)
    ad = bytes.fromhex(ad)
    pt = bytes.fromhex(pt)
    ct_with_tag = bytes.fromhex(ct)
    # ascon-c publishes ciphertext || tag on the CT line.
    return label, key, nonce, ad, pt, ct_with_tag[:len(pt)], ct_with_tag[len(pt):]


class TestOfficialKnownAnswerVectors(unittest.TestCase):
    """Verify the implementation against the official ascon-c KAT vectors"""

    def _assert_vector(self, vector):
        label, key, nonce, ad, pt, ct, tag = split_vector(vector)
        enc = ASCONEncryption(key)

        got_nonce, got_ct, got_tag = enc.encrypt(pt, associated_data=ad, nonce=nonce)
        self.assertEqual(got_nonce, nonce, f"{label}: nonce not returned unchanged")
        self.assertEqual(got_ct.hex().upper(), ct.hex().upper(), f"{label}: ciphertext")
        self.assertEqual(got_tag.hex().upper(), tag.hex().upper(), f"{label}: tag")

        self.assertEqual(enc.decrypt(nonce, ct, tag, associated_data=ad), pt,
                         f"{label}: decryption")

    def test_kat_empty_ad_empty_pt(self):
        """KAT: empty associated data and empty plaintext"""
        self._assert_vector(EMPTY_AD_EMPTY_PT)

    def test_kat_empty_ad_nonempty_pt(self):
        """KAT: empty associated data, non-empty plaintext"""
        self._assert_vector(EMPTY_AD_NONEMPTY_PT)

    def test_kat_nonempty_ad_empty_pt(self):
        """KAT: non-empty associated data, empty plaintext"""
        self._assert_vector(NONEMPTY_AD_EMPTY_PT)

    def test_kat_nonempty_ad_nonempty_pt(self):
        """KAT: non-empty associated data and non-empty plaintext"""
        self._assert_vector(NONEMPTY_AD_NONEMPTY_PT)

    def test_kat_non_block_aligned_plaintext(self):
        """KAT: plaintext lengths that are not multiples of the 16-byte rate"""
        for vector in (NON_ALIGNED_PT, MULTIBLOCK_AD_NON_ALIGNED_PT):
            self._assert_vector(vector)

    def test_kat_multi_block_ad(self):
        """KAT: associated data spanning more than one rate block"""
        for vector in (MULTIBLOCK_AD_EMPTY_PT, NON_ALIGNED_AD_EMPTY_PT,
                       MULTIBLOCK_AD_AND_PT):
            self._assert_vector(vector)

    def test_kat_exact_block_multiple_plaintext(self):
        """
        KAT: plaintext that is an exact multiple of the rate.

        This is the case where Ascon-128a must NOT apply p^8 after the final
        plaintext block; getting that wrong is the classic Ascon-128a bug.
        """
        self._assert_vector(EXACT_TWO_BLOCK_PT)
        self._assert_vector(MULTIBLOCK_AD_AND_PT)

    def test_kat_all_vectors_encrypt_and_decrypt(self):
        """Every hard-coded official vector round-trips and matches exactly"""
        self.assertGreaterEqual(len(ALL_KAT_VECTORS), 4)
        for vector in ALL_KAT_VECTORS:
            self._assert_vector(vector)

    def test_kat_ciphertext_excludes_tag(self):
        """The returned ciphertext must exclude the tag (length == plaintext)"""
        for vector in ALL_KAT_VECTORS:
            _, key, nonce, ad, pt, ct, tag = split_vector(vector)
            _, got_ct, got_tag = ASCONEncryption(key).encrypt(
                pt, associated_data=ad, nonce=nonce
            )
            self.assertEqual(len(got_ct), len(pt))
            self.assertEqual(len(got_tag), ASCONEncryption.TAG_SIZE)
            self.assertNotEqual(got_ct + got_tag, got_ct)


class TestRoundTrip(unittest.TestCase):
    """Encrypt/decrypt round-trip behaviour over many shapes and sizes"""

    def setUp(self):
        self.key = bytes(range(16))
        self.ascon = ASCONEncryption(self.key)

    def test_roundtrip_various_lengths(self):
        """Round-trip plaintexts of every length 0..64 bytes"""
        for length in range(65):
            with self.subTest(length=length):
                plaintext = os.urandom(length)
                ad = os.urandom(length % 24)
                nonce, ct, tag = self.ascon.encrypt(plaintext, associated_data=ad)
                self.assertEqual(self.ascon.decrypt(nonce, ct, tag, associated_data=ad),
                                 plaintext)

    def test_roundtrip_random_key_nonce_ad_plaintext(self):
        """Round-trip with randomly generated keys, nonces, AD and plaintexts"""
        for _ in range(50):
            key = os.urandom(16)
            nonce = os.urandom(16)
            ad = os.urandom(int.from_bytes(os.urandom(1), "big") % 40)
            plaintext = os.urandom(int.from_bytes(os.urandom(2), "big") % 200)
            enc = ASCONEncryption(key)
            got_nonce, ct, tag = enc.encrypt(plaintext, associated_data=ad, nonce=nonce)
            self.assertEqual(got_nonce, nonce)
            self.assertEqual(enc.decrypt(nonce, ct, tag, associated_data=ad), plaintext)

    def test_roundtrip_empty_plaintext(self):
        """Empty plaintext still produces a 16-byte tag and decrypts to b''"""
        nonce, ct, tag = self.ascon.encrypt(b"")
        self.assertEqual(ct, b"")
        self.assertEqual(len(tag), 16)
        self.assertEqual(self.ascon.decrypt(nonce, ct, tag), b"")

    def test_roundtrip_empty_associated_data(self):
        """Empty AD is the default and must round-trip"""
        nonce, ct, tag = self.ascon.encrypt(b"payload", associated_data=b"")
        self.assertEqual(self.ascon.decrypt(nonce, ct, tag, associated_data=b""),
                         b"payload")

    def test_roundtrip_large_message(self):
        """Round-trip a message much larger than one rate block"""
        plaintext = os.urandom(4096)
        ad = os.urandom(100)
        nonce, ct, tag = self.ascon.encrypt(plaintext, associated_data=ad)
        self.assertEqual(len(ct), len(plaintext))
        self.assertEqual(self.ascon.decrypt(nonce, ct, tag, associated_data=ad),
                         plaintext)

    def test_generated_nonce_is_random_and_returned(self):
        """A fresh 16-byte nonce is generated per call when none is supplied"""
        _, _, _ = self.ascon.encrypt(b"a")
        nonce1, _, _ = self.ascon.encrypt(b"a")
        nonce2, _, _ = self.ascon.encrypt(b"a")
        self.assertEqual(len(nonce1), ASCONEncryption.NONCE_SIZE)
        self.assertEqual(len(nonce2), ASCONEncryption.NONCE_SIZE)
        self.assertNotEqual(nonce1, nonce2)

    def test_supplied_nonce_is_used_verbatim(self):
        """A caller-supplied nonce is used as-is and returned unchanged"""
        nonce = bytes(range(16))
        got_nonce, ct, tag = self.ascon.encrypt(b"hello", nonce=nonce)
        self.assertEqual(got_nonce, nonce)
        # Same nonce must reproduce the same ciphertext and tag (deterministic).
        again = self.ascon.encrypt(b"hello", nonce=nonce)
        self.assertEqual((ct, tag), (again[1], again[2]))

    def test_utf8_string_helper_roundtrip(self):
        """send_encrypted_message encodes str as UTF-8 and round-trips"""
        message = "Secure boot: ECDH + HKDF + ASCON-128a"
        nonce, ct, tag = self.ascon.send_encrypted_message(message)
        self.assertEqual(self.ascon.decrypt(nonce, ct, tag),
                         message.encode("utf-8"))

    def test_utf8_string_helper_accepts_unused_public_key_argument(self):
        """The legacy recipient_public_key argument is still accepted"""
        nonce, ct, tag = self.ascon.send_encrypted_message("hi", recipient_public_key=b"\x02")
        self.assertEqual(self.ascon.decrypt(nonce, ct, tag), b"hi")


class TestAuthenticationFailures(unittest.TestCase):
    """Tampering, mismatched context and wrong keys must all raise ValueError"""

    def setUp(self):
        self.key = bytes(range(16))
        self.ascon = ASCONEncryption(self.key)
        self.plaintext = b"firmware image header and payload"
        self.ad = b"pi-node-01"
        self.nonce, self.ct, self.tag = self.ascon.encrypt(
            self.plaintext, associated_data=self.ad
        )

    def _assert_rejected(self, *args, **kwargs):
        with self.assertRaises(ValueError):
            self.ascon.decrypt(*args, **kwargs)

    def test_tampered_ciphertext_rejected(self):
        """Flipping any ciphertext byte must be detected"""
        for index in range(len(self.ct)):
            tampered = bytearray(self.ct)
            tampered[index] ^= 0x01
            with self.subTest(index=index):
                self._assert_rejected(self.nonce, bytes(tampered), self.tag,
                                      associated_data=self.ad)

    def test_tampered_tag_rejected(self):
        """Flipping any tag byte must be detected"""
        for index in range(len(self.tag)):
            tampered = bytearray(self.tag)
            tampered[index] ^= 0x80
            with self.subTest(index=index):
                self._assert_rejected(self.nonce, self.ct, bytes(tampered),
                                      associated_data=self.ad)

    def test_truncated_ciphertext_rejected(self):
        """Dropping ciphertext bytes must be detected"""
        self._assert_rejected(self.nonce, self.ct[:-1], self.tag,
                              associated_data=self.ad)

    def test_extended_ciphertext_rejected(self):
        """Appending ciphertext bytes must be detected"""
        self._assert_rejected(self.nonce, self.ct + b"\x00", self.tag,
                              associated_data=self.ad)

    def test_aad_mismatch_rejected(self):
        """Different associated data must fail authentication"""
        self._assert_rejected(self.nonce, self.ct, self.tag,
                              associated_data=b"pi-node-02")

    def test_aad_dropped_rejected(self):
        """Omitting associated data that was authenticated must fail"""
        self._assert_rejected(self.nonce, self.ct, self.tag, associated_data=b"")

    def test_aad_added_rejected(self):
        """Supplying AD where none was authenticated must fail"""
        nonce, ct, tag = self.ascon.encrypt(self.plaintext)
        self._assert_rejected(nonce, ct, tag, associated_data=b"unexpected")

    def test_wrong_key_rejected(self):
        """A different session key must fail authentication"""
        other = ASCONEncryption(bytes([0xFF] * 16))
        with self.assertRaises(ValueError):
            other.decrypt(self.nonce, self.ct, self.tag, associated_data=self.ad)

    def test_wrong_nonce_rejected(self):
        """A different nonce must fail authentication"""
        self._assert_rejected(bytes(16), self.ct, self.tag,
                              associated_data=self.ad)

    def test_all_zero_key_rejected(self):
        """An all-zero key is a different key and must fail"""
        with self.assertRaises(ValueError):
            ASCONEncryption(bytes(16)).decrypt(
                self.nonce, self.ct, self.tag, associated_data=self.ad
            )

    def test_valid_context_still_accepted(self):
        """Sanity check: the untampered inputs are accepted"""
        self.assertEqual(
            self.ascon.decrypt(self.nonce, self.ct, self.tag,
                               associated_data=self.ad),
            self.plaintext,
        )


class TestInputValidation(unittest.TestCase):
    """Length validation must raise ValueError (never assert/AssertionError)"""

    def test_constructor_rejects_wrong_key_lengths(self):
        """Session key must be exactly 16 bytes"""
        for length in (0, 1, 15, 17, 32, 64):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    ASCONEncryption(bytes(length))

    def test_constructor_accepts_16_byte_key(self):
        """A 16-byte key is accepted"""
        self.assertEqual(ASCONEncryption(bytes(16)).KEY_SIZE, 16)

    def test_encrypt_rejects_bad_nonce_length(self):
        """A nonce that is not 16 bytes raises ValueError, not AssertionError"""
        ascon = ASCONEncryption(bytes(16))
        for length in (0, 1, 8, 12, 15, 17, 32):
            with self.subTest(length=length):
                with self.assertRaises(ValueError) as ctx:
                    ascon.encrypt(b"data", nonce=bytes(length))
                self.assertNotIsInstance(ctx.exception, AssertionError)

    def test_decrypt_rejects_bad_nonce_length(self):
        """A bad nonce length on decrypt raises ValueError, not AssertionError"""
        ascon = ASCONEncryption(bytes(16))
        nonce, ct, tag = ascon.encrypt(b"data")
        for length in (0, 15, 17, 32):
            with self.subTest(length=length):
                with self.assertRaises(ValueError) as ctx:
                    ascon.decrypt(bytes(length), ct, tag)
                self.assertNotIsInstance(ctx.exception, AssertionError)

    def test_decrypt_rejects_bad_tag_length(self):
        """A tag that is not 16 bytes raises ValueError, not AssertionError"""
        ascon = ASCONEncryption(bytes(16))
        nonce, ct, tag = ascon.encrypt(b"data")
        for length in (0, 1, 8, 15, 17, 32):
            with self.subTest(length=length):
                with self.assertRaises(ValueError) as ctx:
                    ascon.decrypt(nonce, ct, bytes(length))
                self.assertNotIsInstance(ctx.exception, AssertionError)

    def test_validation_survives_python_optimised_mode(self):
        """
        Validation must not depend on `assert` statements.

        `assert` is stripped under `python -O`, which would silently disable
        length checks, so the module must use explicit raises.  Asserting that
        the exception type is exactly ValueError (not AssertionError) proves
        the checks are real, and this test additionally guards the source
        against a bare `assert` statement being reintroduced.
        """
        module_path = ASCONEncryption.__module__.replace(".", os.sep) + ".py"
        module_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            module_path,
        )
        with open(module_file, encoding="utf-8") as handle:
            source = handle.read()

        assert_statements = [
            line.strip()
            for line in source.splitlines()
            if re.match(r"^\s*assert\s", line)
        ]
        self.assertEqual(
            assert_statements, [],
            f"ASCON_Encryption.py must not validate with assert: {assert_statements}",
        )

    def test_failure_message_mentions_integrity(self):
        """Authentication failures raise a descriptive ValueError"""
        ascon = ASCONEncryption(bytes(16))
        nonce, ct, tag = ascon.encrypt(b"data")
        with self.assertRaises(ValueError) as ctx:
            ascon.decrypt(nonce, ct, bytes(16))
        self.assertIn("integrity", str(ctx.exception).lower())


class TestModuleContract(unittest.TestCase):
    """The public interface other modules depend on must stay stable"""

    def test_class_constants(self):
        """Class constants match the Ascon-128a parameter set"""
        self.assertEqual(ASCONEncryption.VARIANT, "Ascon-128a")
        self.assertEqual(ASCONEncryption.KEY_SIZE, 16)
        self.assertEqual(ASCONEncryption.NONCE_SIZE, 16)
        self.assertEqual(ASCONEncryption.TAG_SIZE, 16)

    def test_no_third_party_dependency(self):
        """The module must not import the third-party `ascon` package"""
        import ECC_Integration.ASCON_Encryption as module

        with open(module.__file__, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("import ascon", source)
        self.assertFalse(
            any(
                line.strip() == "import ascon" or line.strip().startswith("from ascon")
                for line in source.splitlines()
            )
        )

    def test_encrypt_returns_three_tuple(self):
        """encrypt returns (nonce, ciphertext, tag)"""
        result = ASCONEncryption(bytes(16)).encrypt(b"data")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        nonce, ct, tag = result
        self.assertIsInstance(nonce, bytes)
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(tag, bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
