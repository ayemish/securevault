"""
module4_keyx.py - Key Exchange & Number Theory Engine for SecureVault
=====================================================================
Covers:
  - Extended Euclidean Algorithm
  - Modular Inverse
  - Euler's Totient Function
  - Chinese Remainder Theorem (CRT)
  - Miller-Rabin Primality Test
  - Diffie-Hellman Key Exchange (512-bit prime)
  - Brute-force discrete log attack on small DH
  - Timing side-channel demo

Rules:
  - All number theory functions hand-coded from scratch.
  - No sympy or any math library for core algorithms.
  - Standard library only: math, time, os, random
"""

import math
import time
import os
import random

from utils import print_separator, generate_random_int, mod_pow



#  PART 1: NUMBER THEORY LIBRARY


def gcd(a, b):
    """
    Compute the Greatest Common Divisor of a and b.
    Uses the Euclidean algorithm.

    Parameters:
        a (int): First integer.
        b (int): Second integer.

    Returns:
        int: GCD of a and b.

    Example:
        gcd(48, 18) -> 6
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Finds gcd, x, y such that: a*x + b*y = gcd(a, b)

    Used to compute modular inverses.

    Parameters:
        a (int): First integer.
        b (int): Second integer.

    Returns:
        tuple: (gcd, x, y)

    Example:
        extended_gcd(35, 15) -> (5, 1, -2)
        Check: 35*1 + 15*(-2) = 35 - 30 = 5 ✓
    """
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modular_inverse(a, m):
    """
    Find the modular inverse of a mod m.
    Returns x such that: (a * x) % m == 1

    Uses Extended Euclidean Algorithm.
    Only exists if gcd(a, m) == 1.

    Parameters:
        a (int): The number to invert.
        m (int): The modulus.

    Returns:
        int: Modular inverse of a mod m.

    Raises:
        ValueError: If inverse does not exist (gcd != 1).

    Example:
        modular_inverse(3, 11) -> 4
        Check: (3 * 4) % 11 = 12 % 11 = 1 ✓
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse of {a} mod {m} does not exist (gcd={g}).")
    return x % m


def euler_totient(n):
    """
    Compute Euler's Totient Function φ(n).
    Counts integers from 1 to n-1 that are coprime with n.

    Formula for prime p: φ(p) = p - 1
    Formula for p*q:     φ(p*q) = (p-1)*(q-1)

    Parameters:
        n (int): The input number.

    Returns:
        int: φ(n)

    Example:
        euler_totient(10) -> 4   (1, 3, 7, 9 are coprime with 10)
        euler_totient(7)  -> 6   (7 is prime, so φ(7) = 6)
    """
    result = 0
    for i in range(1, n):
        if gcd(i, n) == 1:
            result += 1
    return result


def crt(remainders, moduli):
    """
    Chinese Remainder Theorem (CRT) Solver.
    Given a system of congruences:
        x ≡ r0 (mod m0)
        x ≡ r1 (mod m1)
        ...
    Find the unique x in range [0, M) where M = m0 * m1 * ...

    All moduli must be pairwise coprime.

    Parameters:
        remainders (list): List of remainders [r0, r1, ...].
        moduli     (list): List of moduli [m0, m1, ...].

    Returns:
        int: The unique solution x.

    Raises:
        ValueError: If moduli are not pairwise coprime.

    Example:
        crt([2, 3, 2], [3, 5, 7]) -> 23
        Check: 23%3=2 ✓  23%5=3 ✓  23%7=2 ✓
    """
    M = 1
    for m in moduli:
        M *= m

    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        inv = modular_inverse(Mi, m)
        x += r * Mi * inv

    return x % M


def miller_rabin(n, rounds=10):
    """
    Miller-Rabin Primality Test.
    Probabilistic test — more rounds = more confidence.
    Much faster than trial division for large numbers.

    Parameters:
        n      (int): Number to test for primality.
        rounds (int): Number of test rounds (default 10).

    Returns:
        bool: True if probably prime, False if definitely composite.

    Example:
        miller_rabin(17)  -> True
        miller_rabin(100) -> False
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Test with random witnesses
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # definitely composite

    return True  # probably prime


def demo_number_theory():
    """
    Demonstrate all number theory functions with concrete examples.
    Shows Extended GCD, Modular Inverse, Euler Totient, and CRT.

    Returns:
        None
    """
    print_separator()
    print("  NUMBER THEORY DEMO")
    print_separator()

    # Extended GCD
    a, b = 35, 15
    g, x, y = extended_gcd(a, b)
    print(f"  Extended GCD({a}, {b})")
    print(f"    gcd = {g},  x = {x},  y = {y}")
    print(f"    Verify: {a}*{x} + {b}*{y} = {a*x + b*y}  (should be {g})")

    print()

    # Modular Inverse
    a, m = 3, 11
    inv = modular_inverse(a, m)
    print(f"  Modular Inverse of {a} mod {m} = {inv}")
    print(f"    Verify: ({a} * {inv}) % {m} = {(a * inv) % m}  (should be 1)")

    print()

    # Euler's Totient
    n = 10
    phi = euler_totient(n)
    print(f"  Euler Totient φ({n}) = {phi}")
    print(f"    (Numbers coprime to {n}: {[i for i in range(1,n) if gcd(i,n)==1]})")

    print()

    # CRT
    remainders = [2, 3, 2]
    moduli = [3, 5, 7]
    result = crt(remainders, moduli)
    print(f"  CRT: x ≡ {remainders[0]} (mod {moduli[0]}), "
          f"x ≡ {remainders[1]} (mod {moduli[1]}), "
          f"x ≡ {remainders[2]} (mod {moduli[2]})")
    print(f"    Solution: x = {result}")
    print(f"    Verify: {result}%{moduli[0]}={result%moduli[0]}, "
          f"{result}%{moduli[1]}={result%moduli[1]}, "
          f"{result}%{moduli[2]}={result%moduli[2]}")

    print_separator()


#  PART 2: DIFFIE-HELLMAN KEY EXCHANGE


# A well-known 512-bit safe prime for DH (from RFC standards)
DH_PRIME_512 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16
)
DH_GENERATOR = 2  # standard generator


def dh_generate_private_key(prime):
    """
    Generate a random private key for Diffie-Hellman.
    Must be in range [2, prime-2].

    Parameters:
        prime (int): The DH prime p.

    Returns:
        int: A random private key.
    """
    return random.randrange(2, prime - 1)


def dh_compute_public_key(private_key, generator, prime):
    """
    Compute the DH public key: public = generator^private mod prime

    Parameters:
        private_key (int): The private key.
        generator   (int): The generator g.
        prime       (int): The prime p.

    Returns:
        int: The public key.
    """
    return mod_pow(generator, private_key, prime)


def dh_compute_shared_secret(their_public, my_private, prime):
    """
    Compute the shared DH secret: secret = their_public^my_private mod prime

    Parameters:
        their_public (int): The other party's public key.
        my_private   (int): Your own private key.
        prime        (int): The prime p.

    Returns:
        int: The shared secret (same for both Alice and Bob).
    """
    return mod_pow(their_public, my_private, prime)


def dh_full_demo():
    """
    Full simulation of Diffie-Hellman key exchange between Alice and Bob.
    Uses the 512-bit prime. Shows public channel communication.
    Derives a shared session key and uses XOR to encrypt a short message.

    Returns:
        None
    """
    print_separator()
    print("  DIFFIE-HELLMAN KEY EXCHANGE DEMO")
    print_separator()

    p = DH_PRIME_512
    g = DH_GENERATOR

    print(f"  [Public] Generator g = {g}")
    print(f"  [Public] Prime p     = (512-bit prime)")
    print()

    # Alice generates her keys
    alice_private = dh_generate_private_key(p)
    alice_public = dh_compute_public_key(alice_private, g, p)
    print(f"  Alice private key: ...{str(alice_private)[-10:]} (kept secret)")
    print(f"  Alice public key : ...{str(alice_public)[-10:]} (sent to Bob)")

    print()

    # Bob generates his keys
    bob_private = dh_generate_private_key(p)
    bob_public = dh_compute_public_key(bob_private, g, p)
    print(f"  Bob private key  : ...{str(bob_private)[-10:]} (kept secret)")
    print(f"  Bob public key   : ...{str(bob_public)[-10:]} (sent to Alice)")

    print()

    # Both compute shared secret
    alice_secret = dh_compute_shared_secret(bob_public, alice_private, p)
    bob_secret = dh_compute_shared_secret(alice_public, bob_private, p)

    print(f"  Alice's shared secret: ...{str(alice_secret)[-10:]}")
    print(f"  Bob's shared secret  : ...{str(bob_secret)[-10:]}")
    print(f"  Secrets match        : {alice_secret == bob_secret}")

    print()

    # Derive a simple session key (first 16 bytes of secret)
    byte_length = (alice_secret.bit_length() + 7) // 8
    secret_bytes = alice_secret.to_bytes(byte_length, byteorder='big')
    session_key = secret_bytes[:16]
    print(f"  Session key (hex): {session_key.hex()}")

    # Encrypt a short message using XOR with session key
    message = "SecureVault!"
    msg_bytes = message.encode('utf-8')
    key_repeated = (session_key * ((len(msg_bytes) // len(session_key)) + 1))[:len(msg_bytes)]
    encrypted = bytes(a ^ b for a, b in zip(msg_bytes, key_repeated))
    decrypted = bytes(a ^ b for a, b in zip(encrypted, key_repeated))

    print(f"  Message           : {message}")
    print(f"  Encrypted (hex)   : {encrypted.hex()}")
    print(f"  Decrypted         : {decrypted.decode('utf-8')}")
    print_separator()


def dh_validate_parameters(p, g):
    """
    Validate Diffie-Hellman parameters.
    Checks that p is prime and g is in valid range.

    Parameters:
        p (int): The prime modulus.
        g (int): The generator.

    Returns:
        bool: True if valid.

    Raises:
        ValueError: With description if invalid.
    """
    if not miller_rabin(p):
        raise ValueError(f"p={p} is not prime.")
    if g < 2 or g >= p:
        raise ValueError(f"Generator g must be in range [2, p-1].")
    return True


#  PART 3: BRUTE-FORCE DISCRETE LOG ATTACK


def brute_force_discrete_log(public_key, generator, prime):
    """
    Brute-force the discrete logarithm problem for small DH parameters.
    Finds private key x such that: generator^x ≡ public_key (mod prime)

    Only feasible for small primes (p < 1000).
    Demonstrates WHY large primes are essential in real DH.

    Parameters:
        public_key (int): The public key to attack.
        generator  (int): The generator g.
        prime      (int): The small prime p.

    Returns:
        int or None: The private key if found, None if not found.
    """
    print_separator()
    print("  BRUTE-FORCE DISCRETE LOG ATTACK")
    print_separator()
    print(f"  Target public key : {public_key}")
    print(f"  Generator g       : {generator}")
    print(f"  Prime p           : {prime}")
    print(f"  Searching for x where {generator}^x mod {prime} = {public_key}...")
    print()

    start = time.time()
    current = 1

    for x in range(1, prime):
        current = (current * generator) % prime
        if current == public_key:
            elapsed = time.time() - start
            print(f"  [+] FOUND! Private key x = {x}")
            print(f"  [+] Verify: {generator}^{x} mod {prime} = {mod_pow(generator, x, prime)}")
            print(f"  [+] Time taken: {elapsed:.4f} seconds")
            print(f"  [!] With a 512-bit prime this would take longer than the universe's age!")
            print_separator()
            return x

    print("  [-] Private key not found.")
    print_separator()
    return None


def dh_small_demo():
    """
    Run a full DH exchange with small parameters, then attack it.
    Shows the contrast between small (insecure) and large (secure) primes.

    Returns:
        None
    """
    # Small insecure parameters
    p = 23   # small prime
    g = 5    # generator

    print_separator()
    print("  SMALL DH PARAMETERS DEMO (Insecure — for education only)")
    print_separator()
    print(f"  p = {p}, g = {g}")

    alice_private = random.randint(2, p - 2)
    bob_private = random.randint(2, p - 2)

    alice_public = mod_pow(g, alice_private, p)
    bob_public = mod_pow(g, bob_private, p)

    shared = mod_pow(bob_public, alice_private, p)

    print(f"  Alice private: {alice_private}  Alice public: {alice_public}")
    print(f"  Bob private  : {bob_private}  Bob public  : {bob_public}")
    print(f"  Shared secret: {shared}")
    print_separator()

    # Now attack Alice's private key
    brute_force_discrete_log(alice_public, g, p)


#  PART 4: TIMING SIDE-CHANNEL DEMO

def timing_demo():
    """
    Measure how long modular exponentiation takes for increasing exponent sizes.
    Larger exponents = more time. Shows timing as a potential side-channel.

    Returns:
        None
    """
    print_separator()
    print("  TIMING SIDE-CHANNEL DEMO — Modular Exponentiation")
    print_separator()
    print(f"  {'Exponent Bits':<16} {'Time (seconds)'}")
    print_separator('-', 40)

    base = 2
    modulus = DH_PRIME_512

    for bits in [8, 16, 32, 64, 128, 256, 512]:
        exponent = random.getrandbits(bits)
        start = time.time()
        # Run multiple times for measurable timing
        for _ in range(100):
            mod_pow(base, exponent, modulus)
        elapsed = (time.time() - start) / 100

        print(f"  {bits:<16} {elapsed:.6f}s")

    print_separator()
    print("  [!] Timing differences can leak info about exponent size.")
    print("      Real systems use constant-time implementations.")
    print_separator()



#  MODULE MENU

def module4_menu():

    while True:
        print_separator()
        print("  MODULE 4 — Key Exchange & Number Theory")
        print_separator()
        print("  1. Number Theory Demo (GCD, Inverse, Totient, CRT)")
        print("  2. Diffie-Hellman Full Demo (512-bit prime)")
        print("  3. DH Small Parameters + Brute Force Attack")
        print("  4. Timing Side-Channel Demo")
        print("  5. Miller-Rabin Primality Test")
        print("  0. Back to Main Menu")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            demo_number_theory()

        elif choice == '2':
            dh_full_demo()

        elif choice == '3':
            dh_small_demo()

        elif choice == '4':
            timing_demo()

        elif choice == '5':
            n = int(input("  Enter a number to test: "))
            result = miller_rabin(n)
            print(f"\n  {n} is {'PRIME' if result else 'NOT PRIME'} (Miller-Rabin)\n")

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option. Try again.")