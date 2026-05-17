"""
tests/test_module4.py - Unit Tests for Module 4: Key Exchange & Number Theory
=============================================================================
5 tests covering GCD, modular inverse, CRT, Miller-Rabin, and DH.
Run with: python -m unittest tests/test_module4.py
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module4_keyx import (
    gcd, extended_gcd, modular_inverse,
    euler_totient, crt, miller_rabin,
    mod_pow,
    dh_generate_private_key,
    dh_compute_public_key,
    dh_compute_shared_secret,
    DH_PRIME_512, DH_GENERATOR
)


class TestGCDAndExtendedGCD(unittest.TestCase):
    """Test 1 — GCD and Extended Euclidean Algorithm."""

    def test_gcd_basic(self):
        self.assertEqual(gcd(48, 18), 6)

    def test_gcd_coprime(self):
        self.assertEqual(gcd(13, 7), 1)

    def test_gcd_one_zero(self):
        self.assertEqual(gcd(5, 0), 5)

    def test_extended_gcd_bezout(self):
        a, b = 35, 15
        g, x, y = extended_gcd(a, b)
        self.assertEqual(g, gcd(a, b))
        self.assertEqual(a * x + b * y, g)

    def test_extended_gcd_coprime(self):
        a, b = 17, 13
        g, x, y = extended_gcd(a, b)
        self.assertEqual(g, 1)
        self.assertEqual(a * x + b * y, 1)


class TestModularInverse(unittest.TestCase):
    """Test 2 — Modular inverse."""

    def test_basic_inverse(self):
        inv = modular_inverse(3, 11)
        self.assertEqual((3 * inv) % 11, 1)

    def test_inverse_verify(self):
        a, m = 7, 26
        inv = modular_inverse(a, m)
        self.assertEqual((a * inv) % m, 1)

    def test_no_inverse_raises(self):
        # gcd(6, 9) = 3 != 1, so inverse doesn't exist
        with self.assertRaises(ValueError):
            modular_inverse(6, 9)

    def test_inverse_of_1(self):
        self.assertEqual(modular_inverse(1, 7), 1)

    def test_mod_pow_basic(self):
        # 2^10 mod 1000 = 24
        self.assertEqual(mod_pow(2, 10, 1000), 24)


class TestEulerTotientAndCRT(unittest.TestCase):
    """Test 3 — Euler's totient and Chinese Remainder Theorem."""

    def test_totient_prime(self):
        # φ(7) = 6 for prime 7
        self.assertEqual(euler_totient(7), 6)

    def test_totient_10(self):
        # φ(10) = 4  (1,3,7,9)
        self.assertEqual(euler_totient(10), 4)

    def test_totient_1(self):
        self.assertEqual(euler_totient(1), 0)

    def test_crt_basic(self):
        # x ≡ 2 mod 3, x ≡ 3 mod 5, x ≡ 2 mod 7 → x = 23
        result = crt([2, 3, 2], [3, 5, 7])
        self.assertEqual(result % 3, 2)
        self.assertEqual(result % 5, 3)
        self.assertEqual(result % 7, 2)

    def test_crt_two_congruences(self):
        result = crt([1, 2], [3, 5])
        self.assertEqual(result % 3, 1)
        self.assertEqual(result % 5, 2)


class TestMillerRabin(unittest.TestCase):
    """Test 4 — Miller-Rabin primality test."""

    def test_small_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23]:
            self.assertTrue(miller_rabin(p), f"{p} should be prime")

    def test_small_composites(self):
        for n in [4, 6, 8, 9, 10, 15, 25, 100]:
            self.assertFalse(miller_rabin(n), f"{n} should not be prime")

    def test_large_prime(self):
        # Known large prime
        self.assertTrue(miller_rabin(999999999999999877))

    def test_one_is_not_prime(self):
        self.assertFalse(miller_rabin(1))

    def test_zero_is_not_prime(self):
        self.assertFalse(miller_rabin(0))


class TestDiffieHellman(unittest.TestCase):
    """Test 5 — Diffie-Hellman key exchange."""

    def test_shared_secrets_match(self):
        p, g = DH_PRIME_512, DH_GENERATOR
        a = dh_generate_private_key(p)
        b = dh_generate_private_key(p)
        A = dh_compute_public_key(a, g, p)
        B = dh_compute_public_key(b, g, p)
        alice_secret = dh_compute_shared_secret(B, a, p)
        bob_secret   = dh_compute_shared_secret(A, b, p)
        self.assertEqual(alice_secret, bob_secret)

    def test_private_key_in_range(self):
        p = DH_PRIME_512
        key = dh_generate_private_key(p)
        self.assertGreater(key, 1)
        self.assertLess(key, p)

    def test_public_key_in_range(self):
        p, g = DH_PRIME_512, DH_GENERATOR
        priv = dh_generate_private_key(p)
        pub  = dh_compute_public_key(priv, g, p)
        self.assertGreater(pub, 0)
        self.assertLess(pub, p)

    def test_different_private_keys_different_public(self):
        p, g = DH_PRIME_512, DH_GENERATOR
        a = dh_generate_private_key(p)
        b = dh_generate_private_key(p)
        A = dh_compute_public_key(a, g, p)
        B = dh_compute_public_key(b, g, p)
        self.assertNotEqual(A, B)

    def test_small_dh_correct(self):
        # Small known DH: p=23, g=5, a=6, b=15
        p, g = 23, 5
        a, b = 6, 15
        A = mod_pow(g, a, p)   # 5^6 mod 23 = 8
        B = mod_pow(g, b, p)   # 5^15 mod 23 = 19
        s1 = mod_pow(B, a, p)  # 19^6 mod 23
        s2 = mod_pow(A, b, p)  # 8^15 mod 23
        self.assertEqual(s1, s2)


if __name__ == '__main__':
    unittest.main(verbosity=2)