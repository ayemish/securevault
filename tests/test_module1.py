"""
tests/test_module1.py - Unit Tests for Module 1: Classical Ciphers
===================================================================
5 tests covering Caesar, ROT-13, Vigenere, OTP, Substitution, Columnar.
Run with: python -m unittest tests/test_module1.py
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module1_classical import (
    caesar_encrypt, caesar_decrypt,
    rot13,
    vigenere_encrypt, vigenere_decrypt,
    otp_encrypt, otp_decrypt,
    substitution_encrypt, substitution_decrypt,
    columnar_encrypt, columnar_decrypt
)


class TestCaesarCipher(unittest.TestCase):
    """Test 1 — Caesar Cipher encrypt and decrypt."""

    def test_encrypt_basic(self):
        self.assertEqual(caesar_encrypt("HELLO", 3), "KHOOR")

    def test_decrypt_reverses_encrypt(self):
        original = "Hello World"
        encrypted = caesar_encrypt(original, 7)
        decrypted = caesar_decrypt(encrypted, 7)
        self.assertEqual(decrypted, original)

    def test_non_alpha_unchanged(self):
        result = caesar_encrypt("Hi, 123!", 5)
        self.assertIn(",", result)
        self.assertIn("1", result)

    def test_shift_wraps_around(self):
        # Z shifted by 1 should be A
        self.assertEqual(caesar_encrypt("Z", 1), "A")

    def test_zero_shift(self):
        self.assertEqual(caesar_encrypt("HELLO", 0), "HELLO")


class TestROT13(unittest.TestCase):
    """Test 2 — ROT-13 is self-inverse."""

    def test_rot13_basic(self):
        self.assertEqual(rot13("HELLO"), "URYYB")

    def test_rot13_double_returns_original(self):
        original = "SecureVault"
        self.assertEqual(rot13(rot13(original)), original)

    def test_rot13_preserves_case(self):
        result = rot13("Hello")
        self.assertEqual(result[0], result[0].upper())

    def test_rot13_non_alpha_unchanged(self):
        result = rot13("Hello, World! 123")
        self.assertIn(",", result)
        self.assertIn("1", result)

    def test_rot13_equals_caesar_13(self):
        msg = "TESTING"
        self.assertEqual(rot13(msg), caesar_encrypt(msg, 13))


class TestVigenereCipher(unittest.TestCase):
    """Test 3 — Vigenere encrypt and decrypt."""

    def test_encrypt_basic(self):
        result = vigenere_encrypt("HELLO", "KEY")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 5)

    def test_decrypt_reverses_encrypt(self):
        original = "HELLOWORLD"
        key = "SECRET"
        encrypted = vigenere_encrypt(original, key)
        decrypted = vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, original)

    def test_different_keys_give_different_output(self):
        msg = "HELLO"
        self.assertNotEqual(
            vigenere_encrypt(msg, "KEY"),
            vigenere_encrypt(msg, "ABC")
        )

    def test_invalid_key_raises(self):
        with self.assertRaises(ValueError):
            vigenere_encrypt("HELLO", "KEY123")

    def test_preserves_non_alpha(self):
        result = vigenere_encrypt("HI THERE", "KEY")
        self.assertIn(" ", result)


class TestOTP(unittest.TestCase):
    """Test 4 — One-Time Pad encrypt and decrypt."""

    def test_encrypt_returns_hex(self):
        ct_hex, key_hex = otp_encrypt("Hello")
        self.assertTrue(all(c in '0123456789abcdef' for c in ct_hex))

    def test_decrypt_reverses_encrypt(self):
        original = "SecureVault OTP"
        ct_hex, key_hex = otp_encrypt(original)
        decrypted = otp_decrypt(ct_hex, key_hex)
        self.assertEqual(decrypted, original)

    def test_ciphertext_length_matches_plaintext(self):
        msg = "Hello"
        ct_hex, _ = otp_encrypt(msg)
        # Each byte = 2 hex chars
        self.assertEqual(len(ct_hex), len(msg.encode('utf-8')) * 2)

    def test_two_encryptions_differ(self):
        msg = "Hello"
        ct1, _ = otp_encrypt(msg)
        ct2, _ = otp_encrypt(msg)
        # Random keys — ciphertexts should (almost always) differ
        self.assertNotEqual(ct1, ct2)

    def test_wrong_key_gives_wrong_plaintext(self):
        msg = "Hello"
        ct_hex, key_hex = otp_encrypt(msg)
        _, wrong_key = otp_encrypt(msg)  # different random key
        result = otp_decrypt(ct_hex, wrong_key)
        self.assertNotEqual(result, msg)


class TestSubstitutionAndColumnar(unittest.TestCase):
    """Test 5 — Substitution and Columnar Transposition."""

    SUB_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"

    def test_substitution_encrypt_decrypt(self):
        original = "HELLO"
        enc = substitution_encrypt(original, self.SUB_KEY)
        dec = substitution_decrypt(enc, self.SUB_KEY)
        self.assertEqual(dec, original)

    def test_substitution_invalid_key_raises(self):
        with self.assertRaises(ValueError):
            substitution_encrypt("HELLO", "TOOSHORT")

    def test_substitution_output_differs_from_input(self):
        enc = substitution_encrypt("ABCDE", self.SUB_KEY)
        self.assertNotEqual(enc, "ABCDE")

    def test_columnar_encrypt_decrypt(self):
        original = "HELLOWORLD"
        enc = columnar_encrypt(original, "KEY")
        dec = columnar_decrypt(enc, "KEY")
        self.assertIn("HELLOWORLD", dec)

    def test_columnar_different_keys_differ(self):
        msg = "HELLOWORLD"
        enc1 = columnar_encrypt(msg, "KEY")
        enc2 = columnar_encrypt(msg, "ABC")
        self.assertNotEqual(enc1, enc2)


if __name__ == '__main__':
    unittest.main(verbosity=2)