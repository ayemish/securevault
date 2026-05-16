"""
bonus_rsa.py - RSA Implementation for SecureVault (+3 Bonus Marks)
==================================================================
Implements RSA from scratch using the number theory library in module4_keyx.py.

Covers:
  - RSA key generation (512-bit primes)
  - RSA encryption and decryption
  - RSA digital signature and verification
  - Integration with Module 4 number theory

Rules:
  - No cryptography libraries.
  - Uses only: module4_keyx, utils, random, hashlib
"""

import random
import hashlib

from module4_keyx import miller_rabin, modular_inverse, mod_pow
from utils import print_separator


# ─────────────────────────────────────────────
#  PART 1: PRIME GENERATION
# ─────────────────────────────────────────────

def generate_prime(bits=512):
    """
    Generate a random prime number of the given bit size.
    Keeps picking random odd numbers and testing with Miller-Rabin
    until a prime is found.

    Parameters:
        bits (int): Bit length of the prime. Default 512.

    Returns:
        int: A large prime number.

    Example:
        generate_prime(512) -> a 512-bit prime integer
    """
    while True:
        # Pick a random odd number of the right bit size
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1)  # ensure top bit is set (correct bit length)
        candidate |= 1                 # ensure it is odd

        if miller_rabin(candidate, rounds=20):
            return candidate


# ─────────────────────────────────────────────
#  PART 2: RSA KEY GENERATION
# ─────────────────────────────────────────────

def rsa_keygen(bits=512):
    """
    Generate an RSA public/private key pair.

    Steps:
      1. Generate two distinct primes p and q of given bit size.
      2. Compute n = p * q  (the modulus).
      3. Compute phi = (p-1) * (q-1)  (Euler's totient).
      4. Set e = 65537  (standard public exponent, prime, widely used).
      5. Compute d = modular_inverse(e, phi)  (private exponent).

    Parameters:
        bits (int): Bit size of each prime. Default 512 (gives 1024-bit key).

    Returns:
        tuple: (public_key, private_key)
               public_key  = (e, n)
               private_key = (d, n)

    Example:
        pub, priv = rsa_keygen(512)
        # pub  = (65537, <large n>)
        # priv = (<large d>, <same n>)
    """
    print("  [*] Generating primes p and q...", end=' ', flush=True)

    # Generate two distinct primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    print("done.")

    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 65537  # standard public exponent

    # Ensure gcd(e, phi) == 1
    from math import gcd
    if gcd(e, phi) != 1:
        # Very rare — just regenerate
        return rsa_keygen(bits)

    d = modular_inverse(e, phi)

    public_key  = (e, n)
    private_key = (d, n)

    return public_key, private_key


# ─────────────────────────────────────────────
#  PART 3: RSA ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────

def rsa_encrypt(message, public_key):
    """
    Encrypt a short message using RSA public key.
    Converts message to integer, then computes c = m^e mod n.

    Note: RSA can only encrypt messages smaller than n.
    For longer messages, use hybrid encryption (RSA + AES).

    Parameters:
        message    (str): The plaintext message (keep short, < 50 chars).
        public_key (tuple): (e, n)

    Returns:
        int: The RSA ciphertext as an integer.

    Raises:
        ValueError: If message is too long for the key size.

    Example:
        ct = rsa_encrypt("Hello", pub)
    """
    e, n = public_key
    message_bytes = message.encode('utf-8')
    m = int.from_bytes(message_bytes, byteorder='big')

    if m >= n:
        raise ValueError("Message too long for this key size. Use a shorter message.")

    ciphertext = mod_pow(m, e, n)
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    """
    Decrypt an RSA ciphertext using the private key.
    Computes m = c^d mod n, then converts back to string.

    Parameters:
        ciphertext  (int): The RSA ciphertext integer.
        private_key (tuple): (d, n)

    Returns:
        str: The decrypted plaintext message.

    Example:
        pt = rsa_decrypt(ct, priv)
    """
    d, n = private_key
    m = mod_pow(ciphertext, d, n)

    # Convert integer back to bytes then to string
    byte_length = (m.bit_length() + 7) // 8
    message_bytes = m.to_bytes(byte_length, byteorder='big')
    return message_bytes.decode('utf-8')


# ─────────────────────────────────────────────
#  PART 4: RSA DIGITAL SIGNATURE
# ─────────────────────────────────────────────

def rsa_sign(message, private_key):
    """
    Sign a message using RSA private key.

    Process:
      1. SHA-256 hash the message.
      2. Convert hash to integer.
      3. Sign: sig = hash^d mod n

    Parameters:
        message     (str): The message to sign.
        private_key (tuple): (d, n)

    Returns:
        int: The digital signature as an integer.

    Example:
        sig = rsa_sign("Hello", priv)
    """
    d, n = private_key

    # Hash the message first
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    hash_int = int.from_bytes(digest, byteorder='big')

    # Sign with private key
    signature = mod_pow(hash_int, d, n)
    return signature


def rsa_verify(message, signature, public_key):
    """
    Verify an RSA digital signature using the public key.

    Process:
      1. Recover hash: recovered = sig^e mod n
      2. Recompute SHA-256 hash of the message.
      3. Compare — if equal, signature is valid.

    Parameters:
        message    (str): The original message.
        signature  (int): The signature integer to verify.
        public_key (tuple): (e, n)

    Returns:
        bool: True if signature is valid, False otherwise.

    Example:
        rsa_verify("Hello", sig, pub) -> True
    """
    e, n = public_key

    # Recover hash from signature
    recovered_hash_int = mod_pow(signature, e, n)

    # Recompute hash from message
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    expected_hash_int = int.from_bytes(digest, byteorder='big')

    return recovered_hash_int == expected_hash_int


# ─────────────────────────────────────────────
#  PART 5: FULL DEMO
# ─────────────────────────────────────────────

def rsa_full_demo():
    """
    Full RSA demo: keygen, encrypt, decrypt, sign, verify.

    Returns:
        None
    """
    print_separator()
    print("  RSA FULL DEMO")
    print_separator()

    # Key generation
    print("  Generating 512-bit RSA key pair...")
    pub, priv = rsa_keygen(bits=512)
    e, n = pub
    d, _ = priv

    print(f"  Public key  e = {e}")
    print(f"  Modulus     n = ...{str(n)[-20:]} ({n.bit_length()} bits)")
    print(f"  Private key d = ...{str(d)[-20:]}")
    print()

    # Encryption / Decryption
    message = input("  Enter a short message to encrypt (max ~40 chars): ").strip()

    print("\n  [*] Encrypting...")
    try:
        ct = rsa_encrypt(message, pub)
        print(f"  Ciphertext = ...{str(ct)[-30:]}")

        print("\n  [*] Decrypting...")
        pt = rsa_decrypt(ct, priv)
        print(f"  Decrypted  = {pt}")
        print(f"  Match      = {pt == message}")
    except ValueError as err:
        print(f"  [!] {err}")
        return

    print()

    # Signature
    print("  [*] Signing message with private key...")
    sig = rsa_sign(message, priv)
    print(f"  Signature  = ...{str(sig)[-30:]}")

    print("\n  [*] Verifying signature with public key...")
    valid = rsa_verify(message, sig, pub)
    print(f"  Valid      = {valid}")

    # Tamper test
    print("\n  [*] Verifying with TAMPERED message...")
    tamper_valid = rsa_verify(message + "!", sig, pub)
    print(f"  Valid (tampered) = {tamper_valid}  (should be False)")

    print_separator()


# ─────────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────────

def rsa_menu():
    """
    RSA bonus module menu.
    Can be called from main.py as an extra menu option.

    Returns:
        None
    """
    while True:
        print_separator()
        print("  BONUS — RSA Implementation")
        print_separator()
        print("  1. Full RSA Demo (keygen + encrypt + sign)")
        print("  2. Generate Key Pair only")
        print("  3. Encrypt a message")
        print("  4. Decrypt a message")
        print("  5. Sign & Verify")
        print("  0. Back")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            rsa_full_demo()

        elif choice == '2':
            print("\n  Generating RSA key pair (512-bit)...")
            pub, priv = rsa_keygen(512)
            e, n = pub
            d, _ = priv
            print(f"  e = {e}")
            print(f"  n = ...{str(n)[-20:]}")
            print(f"  d = ...{str(d)[-20:]}\n")

        elif choice == '3':
            msg = input("  Message (short): ").strip()
            print("  Generating keys...")
            pub, priv = rsa_keygen(512)
            ct = rsa_encrypt(msg, pub)
            print(f"  Ciphertext: ...{str(ct)[-30:]}")
            pt = rsa_decrypt(ct, priv)
            print(f"  Decrypted : {pt}")

        elif choice == '4':
            print("  [!] Paste ciphertext as integer and provide key components.")
            ct  = int(input("  Ciphertext (int): "))
            d   = int(input("  Private key d   : "))
            n   = int(input("  Modulus n       : "))
            pt  = rsa_decrypt(ct, (d, n))
            print(f"  Decrypted: {pt}")

        elif choice == '5':
            msg = input("  Message to sign: ").strip()
            print("  Generating keys...")
            pub, priv = rsa_keygen(512)
            sig = rsa_sign(msg, priv)
            print(f"  Signature : ...{str(sig)[-30:]}")
            valid = rsa_verify(msg, sig, pub)
            print(f"  Valid     : {valid}")

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option.")