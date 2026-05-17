"""
tests/test_module2.py - Unit Tests for Module 2: Stream & Block Cipher
=======================================================================
5 tests covering LCG, Stream Cipher, Block Cipher, Avalanche, Frequency.
Run with: python -m unittest tests/test_module2.py
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module2_stream import (
    LCG,
    stream_encrypt, stream_decrypt,
    block_encrypt, block_decrypt,
    count_bit_differences
)


class TestLCG(unittest.TestCase):
    """Test 1 — LCG produces deterministic output from same seed."""

    def test_same_seed_same_output(self):
        lcg1 = LCG(seed=42)
        lcg2 = LCG(seed=42)
        self.assertEqual(
            [lcg1.next_value() for _ in range(10)],
            [lcg2.next_value() for _ in range(10)]
        )

    def test_different_seeds_different_output(self):
        lcg1 = LCG(seed=42)
        lcg2 = LCG(seed=99)
        self.assertNotEqual(lcg1.next_value(), lcg2.next_value())

    def test_next_byte_in_range(self):
        lcg = LCG(seed=123)
        for _ in range(100):
            b = lcg.next_byte()
            self.assertGreaterEqual(b, 0)
            self.assertLessEqual(b, 255)

    def test_generate_bytes_length(self):
        lcg = LCG(seed=1)
        result = lcg.generate_bytes(16)
        self.assertEqual(len(result), 16)

    def test_generate_bytes_returns_bytes(self):
        lcg = LCG(seed=7)
        result = lcg.generate_bytes(8)
        self.assertIsInstance(result, bytes)


class TestStreamCipher(unittest.TestCase):
    """Test 2 — Stream cipher encrypt and decrypt."""

    def test_encrypt_returns_hex(self):
        ct = stream_encrypt("Hello", 42)
        self.assertIsInstance(ct, str)
        self.assertTrue(all(c in '0123456789abcdef' for c in ct))

    def test_decrypt_reverses_encrypt(self):
        original = "Stream cipher test"
        ct = stream_encrypt(original, 12345)
        pt = stream_decrypt(ct, 12345)
        self.assertEqual(pt, original)

    def test_different_seeds_give_different_ciphertext(self):
        msg = "Hello"
        ct1 = stream_encrypt(msg, 1)
        ct2 = stream_encrypt(msg, 2)
        self.assertNotEqual(ct1, ct2)

    def test_wrong_seed_gives_wrong_plaintext(self):
        msg = "Hello"
        ct = stream_encrypt(msg, 100)
        wrong = stream_decrypt(ct, 999)
        self.assertNotEqual(wrong, msg)

    def test_empty_string(self):
        ct = stream_encrypt("", 1)
        pt = stream_decrypt(ct, 1)
        self.assertEqual(pt, "")


class TestBlockCipher(unittest.TestCase):
    """Test 3 — Block cipher encrypt and decrypt."""

    def test_encrypt_returns_hex(self):
        ct = block_encrypt("Hello!!", 42)
        self.assertIsInstance(ct, str)

    def test_decrypt_reverses_encrypt(self):
        original = "BlockTest"
        ct = block_encrypt(original, 999)
        pt = block_decrypt(ct, 999)
        self.assertEqual(pt, original)

    def test_different_seeds_give_different_output(self):
        msg = "HelloWorld"
        ct1 = block_encrypt(msg, 1)
        ct2 = block_encrypt(msg, 2)
        self.assertNotEqual(ct1, ct2)

    def test_output_multiple_of_8_bytes(self):
        ct = block_encrypt("Hi", 1)
        # hex string length / 2 = byte count, must be multiple of 8
        self.assertEqual((len(ct) // 2) % 8, 0)

    def test_wrong_seed_fails_decrypt(self):
        original = "TestBlock"
        ct = block_encrypt(original, 50)
        wrong = block_decrypt(ct, 51)
        self.assertNotEqual(wrong, original)


class TestAvalancheEffect(unittest.TestCase):
    """Test 4 — Avalanche effect: 1-bit change causes significant output change."""

    def test_bit_difference_detected(self):
        b1 = bytes([0b10101010])
        b2 = bytes([0b10101011])  # 1 bit different
        diff = count_bit_differences(b1, b2)
        self.assertEqual(diff, 1)

    def test_identical_bytes_zero_difference(self):
        b = bytes([0xFF, 0x00, 0xAA])
        self.assertEqual(count_bit_differences(b, b), 0)

    def test_block_cipher_avalanche(self):
        msg1 = "HelloWorld"
        msg2 = "IelloWorld"  # 1 char different
        ct1 = bytes.fromhex(block_encrypt(msg1, 42))
        ct2 = bytes.fromhex(block_encrypt(msg2, 42))
        diff = count_bit_differences(ct1, ct2)
        total = len(ct1) * 8
        # At least 10% of bits should change
        self.assertGreater(diff / total, 0.10)

    def test_all_different_bytes(self):
        b1 = bytes([0x00])
        b2 = bytes([0xFF])
        self.assertEqual(count_bit_differences(b1, b2), 8)

    def test_same_seed_same_ciphertext(self):
        msg = "Consistent"
        ct1 = block_encrypt(msg, 77)
        ct2 = block_encrypt(msg, 77)
        self.assertEqual(ct1, ct2)


class TestFrequencyTest(unittest.TestCase):
    """Test 5 — LCG output passes basic frequency test."""

    def test_frequency_roughly_balanced(self):
        lcg = LCG(seed=42)
        data = lcg.generate_bytes(1000)
        total = 8000
        ones = sum(bin(b).count('1') for b in data)
        ratio = ones / total
        # Should be between 40% and 60%
        self.assertGreater(ratio, 0.40)
        self.assertLess(ratio, 0.60)

    def test_lcg_output_not_all_zeros(self):
        lcg = LCG(seed=1)
        data = lcg.generate_bytes(100)
        self.assertNotEqual(data, bytes(100))

    def test_lcg_output_not_all_same(self):
        lcg = LCG(seed=5)
        values = [lcg.next_byte() for _ in range(50)]
        self.assertGreater(len(set(values)), 1)

    def test_period_restarts_with_same_seed(self):
        lcg1 = LCG(seed=999)
        lcg2 = LCG(seed=999)
        seq1 = [lcg1.next_value() for _ in range(20)]
        seq2 = [lcg2.next_value() for _ in range(20)]
        self.assertEqual(seq1, seq2)

    def test_large_output_generation(self):
        lcg = LCG(seed=100)
        data = lcg.generate_bytes(10000)
        self.assertEqual(len(data), 10000)


if __name__ == '__main__':
    unittest.main(verbosity=2)