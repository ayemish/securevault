"""
tests/test_module3.py - Unit Tests for Module 3: Hash & Authentication
=======================================================================
5 tests covering hash functions, HMAC, PBKDF2, file integrity, birthday.
Run with: python -m unittest tests/test_module3.py
"""

import unittest
import os
import sys
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module3_hash import (
    hash_message,
    hmac_sha256, verify_hmac,
    hash_password, verify_password,
    hash_file
)


class TestHashFunctions(unittest.TestCase):
    """Test 1 — Hash functions produce correct and consistent output."""

    def test_sha256_known_value(self):
        # Known SHA-256 of "hello"
        result = hash_message("hello", "sha256")
        self.assertEqual(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_md5_known_value(self):
        result = hash_message("hello", "md5")
        self.assertEqual(result, "5d41402abc4b2a76b9719d911017c592")

    def test_same_input_same_hash(self):
        h1 = hash_message("SecureVault", "sha256")
        h2 = hash_message("SecureVault", "sha256")
        self.assertEqual(h1, h2)

    def test_different_inputs_different_hashes(self):
        h1 = hash_message("hello", "sha256")
        h2 = hash_message("hello!", "sha256")
        self.assertNotEqual(h1, h2)

    def test_unsupported_algorithm_raises(self):
        with self.assertRaises(ValueError):
            hash_message("hello", "md99")


class TestHMAC(unittest.TestCase):
    """Test 2 — HMAC-SHA256 manual construction."""

    def test_hmac_returns_string(self):
        result = hmac_sha256("key", "message")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # SHA-256 hex = 64 chars

    def test_same_key_message_same_hmac(self):
        h1 = hmac_sha256("secret", "hello")
        h2 = hmac_sha256("secret", "hello")
        self.assertEqual(h1, h2)

    def test_different_key_different_hmac(self):
        h1 = hmac_sha256("key1", "hello")
        h2 = hmac_sha256("key2", "hello")
        self.assertNotEqual(h1, h2)

    def test_verify_hmac_correct(self):
        key = "mysecret"
        msg = "important message"
        mac = hmac_sha256(key, msg)
        self.assertTrue(verify_hmac(key, msg, mac))

    def test_verify_hmac_tampered_message(self):
        key = "mysecret"
        msg = "important message"
        mac = hmac_sha256(key, msg)
        self.assertFalse(verify_hmac(key, "tampered message", mac))


class TestPBKDF2(unittest.TestCase):
    """Test 3 — PBKDF2 password hashing and verification."""

    def test_hash_password_returns_json(self):
        import json
        stored = hash_password("mypassword", iterations=1000)
        parsed = json.loads(stored)
        self.assertIn("salt", parsed)
        self.assertIn("hash", parsed)
        self.assertIn("iterations", parsed)

    def test_verify_correct_password(self):
        stored = hash_password("correcthorse", iterations=1000)
        self.assertTrue(verify_password("correcthorse", stored))

    def test_verify_wrong_password(self):
        stored = hash_password("correcthorse", iterations=1000)
        self.assertFalse(verify_password("wrongpassword", stored))

    def test_two_hashes_of_same_password_differ(self):
        # Different salts each time
        s1 = hash_password("mypassword", iterations=1000)
        s2 = hash_password("mypassword", iterations=1000)
        self.assertNotEqual(s1, s2)

    def test_low_iterations_raises(self):
        with self.assertRaises(ValueError):
            hash_password("mypassword", iterations=500)


class TestFileIntegrity(unittest.TestCase):
    """Test 4 — File hashing and integrity detection."""

    def setUp(self):
        # Create a temp file for testing
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        self.tmp.write(b"SecureVault test file content.")
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_hash_file_returns_hex(self):
        digest = hash_file(self.tmp.name)
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in digest))

    def test_same_file_same_hash(self):
        d1 = hash_file(self.tmp.name)
        d2 = hash_file(self.tmp.name)
        self.assertEqual(d1, d2)

    def test_modified_file_different_hash(self):
        original = hash_file(self.tmp.name)
        with open(self.tmp.name, 'ab') as f:
            f.write(b" MODIFIED")
        modified = hash_file(self.tmp.name)
        self.assertNotEqual(original, modified)

    def test_nonexistent_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            hash_file("/nonexistent/path/file.txt")

    def test_empty_file_has_known_hash(self):
        tmp2 = tempfile.NamedTemporaryFile(delete=False)
        tmp2.close()
        digest = hash_file(tmp2.name)
        # SHA-256 of empty string is known
        self.assertEqual(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        os.unlink(tmp2.name)


class TestBirthdayAttack(unittest.TestCase):
    """Test 5 — Birthday attack finds collisions quickly on small hash spaces."""

    def test_collision_found_8_bits(self):
        from module3_hash import birthday_attack
        result = birthday_attack(bits=8, max_attempts=10000)
        self.assertTrue(result['found'])

    def test_collision_attempts_less_than_brute_force(self):
        from module3_hash import birthday_attack
        result = birthday_attack(bits=8, max_attempts=10000)
        # Should find collision well before 256 (2^8) attempts
        self.assertLess(result['attempts'], 256)

    def test_two_inputs_differ(self):
        from module3_hash import birthday_attack
        result = birthday_attack(bits=8, max_attempts=10000)
        if result['found']:
            self.assertNotEqual(result['input1'], result['input2'])

    def test_hash_values_match_on_collision(self):
        import hashlib
        from module3_hash import birthday_attack
        result = birthday_attack(bits=8, max_attempts=10000)
        if result['found']:
            bits = 8
            hex_chars = bits // 4
            h1 = hashlib.sha256(result['input1'].encode()).hexdigest()[:hex_chars]
            h2 = hashlib.sha256(result['input2'].encode()).hexdigest()[:hex_chars]
            self.assertEqual(h1, h2)

    def test_returns_dict_with_expected_keys(self):
        from module3_hash import birthday_attack
        result = birthday_attack(bits=8, max_attempts=10000)
        self.assertIn('found', result)
        self.assertIn('attempts', result)


if __name__ == '__main__':
    unittest.main(verbosity=2)