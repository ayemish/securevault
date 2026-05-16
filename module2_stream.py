"""
module2_stream.py - Stream & Block Cipher Layer for SecureVault
===============================================================
Covers:
  - LCG-Based PRNG (Linear Congruential Generator)
  - Stream Cipher using LCG keystream
  - Custom 2-round Block Cipher with S-box and P-box
  - Avalanche Effect demonstration
  - Statistical Frequency Test on LCG output

Rules:
  - All implemented from scratch — no cryptography libraries.
  - Only standard library: os, struct
"""

import os
import struct

from utils import xor_bytes, print_separator


#  PART 1: LINEAR CONGRUENTIAL GENERATOR (LCG)


class LCG:
    """
    Linear Congruential Generator (PRNG).

    Formula: next = (multiplier * current + increment) % modulus

    Parameters:
        seed       (int): Starting value. Same seed = same sequence.
        multiplier (int): Multiplier constant.
        increment  (int): Increment constant.
        modulus    (int): Modulus (caps the output range).
    """

    def __init__(self, seed, multiplier=1664525, increment=1013904223, modulus=2**32):
        """
        Initialize the LCG with given parameters.
        Default values are classic Numerical Recipes constants.

        Example:
            lcg = LCG(seed=42)
        """
        self.state = seed
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus

    def next_value(self):
        """
        Generate the next value in the LCG sequence.

        Returns:
            int: Next pseudorandom integer in range [0, modulus).
        """
        self.state = (self.multiplier * self.state + self.increment) % self.modulus
        return self.state

    def next_byte(self):
        """
        Generate the next pseudorandom byte (0-255).

        Returns:
            int: A value between 0 and 255.
        """
        return self.next_value() & 0xFF

    def generate_bytes(self, n):
        """
        Generate n pseudorandom bytes.

        Parameters:
            n (int): Number of bytes to generate.

        Returns:
            bytes: Sequence of n pseudorandom bytes.

        Example:
            lcg.generate_bytes(8) -> b'\\x3f\\xa1...'
        """
        return bytes(self.next_byte() for _ in range(n))

    def visualize(self, count=20):
        """
        Print the first 'count' values from this LCG sequence.
        Useful for verifying determinism — same seed = same output.

        Parameters:
            count (int): How many values to show.

        Returns:
            None
        """
        print_separator()
        print(f"  LCG OUTPUT — seed={self.state}, first {count} values")
        print_separator()
        for i in range(count):
            val = self.next_value()
            bar = '#' * (val * 20 // self.modulus)
            print(f"  [{i+1:>2}] {val:>12}  {bar}")
        print_separator()


#  PART 2: STREAM CIPHER


def stream_encrypt(plaintext, seed):
    """
    Encrypt plaintext using a stream cipher.
    Uses LCG to generate a keystream, then XORs with plaintext bytes.

    Parameters:
        plaintext (str): The message to encrypt.
        seed      (int): The secret seed for the LCG keystream.

    Returns:
        str: Ciphertext as a hex string.

    Example:
        stream_encrypt("Hello", 12345) -> "3f2a1b..."
    """
    plaintext_bytes = plaintext.encode('utf-8')
    lcg = LCG(seed=seed)
    keystream = lcg.generate_bytes(len(plaintext_bytes))
    ciphertext = xor_bytes(plaintext_bytes, keystream)
    return ciphertext.hex()


def stream_decrypt(ciphertext_hex, seed):
    """
    Decrypt a stream cipher ciphertext using the same seed.
    XOR is its own inverse — same operation as encryption.

    Parameters:
        ciphertext_hex (str): Hex string of the ciphertext.
        seed           (int): The same seed used during encryption.

    Returns:
        str: Decrypted plaintext.

    Example:
        stream_decrypt("3f2a1b...", 12345) -> "Hello"
    """
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    lcg = LCG(seed=seed)
    keystream = lcg.generate_bytes(len(ciphertext_bytes))
    plaintext_bytes = xor_bytes(ciphertext_bytes, keystream)
    return plaintext_bytes.decode('utf-8')


def stream_key_reuse_demo(message1, message2, seed):
    """
    Show what happens when the same seed (key) is reused for two messages.
    C1 XOR C2 = M1 XOR M2 — attacker learns XOR of both plaintexts.

    Parameters:
        message1 (str): First plaintext.
        message2 (str): Second plaintext.
        seed     (int): The reused seed.

    Returns:
        None
    """
    length = min(len(message1), len(message2))
    m1 = message1[:length].encode('utf-8')
    m2 = message2[:length].encode('utf-8')

    lcg1 = LCG(seed=seed)
    ks1 = lcg1.generate_bytes(length)
    c1 = xor_bytes(m1, ks1)

    lcg2 = LCG(seed=seed)   # same seed — reused!
    ks2 = lcg2.generate_bytes(length)
    c2 = xor_bytes(m2, ks2)

    xored = xor_bytes(c1, c2)
    m1_xor_m2 = xor_bytes(m1, m2)

    print_separator()
    print("  STREAM CIPHER KEY REUSE DEMO")
    print_separator()
    print(f"  Message 1  : {message1[:length]}")
    print(f"  Message 2  : {message2[:length]}")
    print(f"  C1         : {c1.hex()}")
    print(f"  C2         : {c2.hex()}")
    print(f"  C1 XOR C2  : {xored.hex()}")
    print(f"  M1 XOR M2  : {m1_xor_m2.hex()}")
    print(f"  Match      : {xored == m1_xor_m2}")
    print("  [!] Reusing seed leaks XOR of both messages!")
    print_separator()



#  PART 3: CUSTOM BLOCK CIPHER


# S-Box: a fixed 256-byte substitution table
# Each index maps to a different byte value (simple shuffle)
SBOX = [
    99,124,119,123,242,107,111,197, 48,  1,103, 43,254,215,171,118,
    202,130,201,125,250, 89, 71,240,173,212,162,175,156,164,114,192,
    183,253,147, 38, 54, 63,247,204, 52,165,229,241,113,216, 49, 21,
     4,199, 35,195, 24,150,  5,154,  7, 18,128,226,235, 39,178,117,
     9,131, 44, 26, 27,110, 90,160, 82, 59,214,179, 41,227, 47,132,
    83,209,  0,237, 32,252,177, 91,106,203,190, 57,74, 76, 88,207,
    208,239,170,251, 67, 77, 51,133, 69,249,  2,127, 80, 60,159,168,
    81,163, 64,143,146,157, 56,245,188,182,218, 33, 16,255,243,210,
    205, 12, 19,236, 95,151, 68, 23,196,167,126, 61,100, 93, 25,115,
     96,129, 79,220, 34, 42,144,136, 70,238,184, 20,222, 94, 11,219,
    224, 50, 58, 10, 73,  6, 36, 92,194,211,172, 98,145,149,228,121,
    231,200, 55,109,141,213, 78,169,108, 86,244,234,101,122,174,  8,
    186,120, 37, 46, 28,166,180,198,232,221,116, 31, 75,189,139,138,
    112, 62,181,102, 72,  3,246, 14, 97, 53, 87,185,134,193, 29,158,
    225,248,152, 17,105,217,142,148,155, 30,135,233,206, 85, 40,223,
    140,161,137, 13,191,230, 66,104, 65,153, 45, 15,176, 84,187, 22
]

# P-Box: defines how to rearrange the 8 bytes of a block
# PBOX[i] = j means byte at position i goes to position j
PBOX = [2, 5, 0, 7, 3, 6, 1, 4]


def sbox_substitute(block):
    """
    Apply S-Box substitution to an 8-byte block.
    Each byte is replaced with the value at SBOX[byte].

    Parameters:
        block (bytes): Exactly 8 bytes.

    Returns:
        bytes: 8 bytes after substitution.
    """
    return bytes(SBOX[b] for b in block)


def pbox_permute(block):
    """
    Apply P-Box permutation to an 8-byte block.
    Rearranges the bytes according to PBOX mapping.

    Parameters:
        block (bytes): Exactly 8 bytes.

    Returns:
        bytes: 8 bytes after permutation.
    """
    result = [0] * 8
    for i, b in enumerate(block):
        result[PBOX[i]] = b
    return bytes(result)


def block_encrypt(plaintext, key_seed):
    """
    Encrypt plaintext using the custom 2-round block cipher.

    Process:
        1. Pad plaintext to multiple of 8 bytes.
        2. Split into 8-byte blocks.
        3. For each block, apply 2 rounds of: S-box then P-box.
        4. XOR with a keystream byte derived from the seed.

    Parameters:
        plaintext (str): The message to encrypt.
        key_seed  (int): Seed for LCG keystream generation.

    Returns:
        str: Ciphertext as a hex string.

    Example:
        block_encrypt("Hello!!", 999) -> "3f2a..."
    """
    data = plaintext.encode('utf-8')

    # Pad to multiple of 8
    remainder = len(data) % 8
    if remainder != 0:
        data += b'X' * (8 - remainder)

    lcg = LCG(seed=key_seed)
    ciphertext = b''

    for i in range(0, len(data), 8):
        block = data[i:i+8]

        # Round 1
        block = sbox_substitute(block)
        block = pbox_permute(block)

        # Round 2
        block = sbox_substitute(block)
        block = pbox_permute(block)

        # XOR with keystream byte (simple key mixing)
        key_byte = lcg.next_byte()
        block = xor_bytes(block, bytes([key_byte] * 8))

        ciphertext += block

    return ciphertext.hex()


def block_decrypt(ciphertext_hex, key_seed):
    """
    Decrypt a block cipher ciphertext.
    Reverses the XOR, then reverses P-box and S-box for each round.

    Parameters:
        ciphertext_hex (str): Hex string of the ciphertext.
        key_seed       (int): Same seed used during encryption.

    Returns:
        str: Decrypted plaintext (may have trailing 'X' padding).
    """
    # Build inverse S-box
    inv_sbox = [0] * 256
    for i, v in enumerate(SBOX):
        inv_sbox[v] = i

    # Build inverse P-box
    inv_pbox = [0] * 8
    for i, v in enumerate(PBOX):
        inv_pbox[v] = i

    def inv_sbox_sub(block):
        return bytes(inv_sbox[b] for b in block)

    def inv_pbox_perm(block):
        result = [0] * 8
        for i, b in enumerate(block):
            result[inv_pbox[i]] = b
        return bytes(result)

    data = bytes.fromhex(ciphertext_hex)
    lcg = LCG(seed=key_seed)
    plaintext = b''

    for i in range(0, len(data), 8):
        block = data[i:i+8]

        # Undo XOR
        key_byte = lcg.next_byte()
        block = xor_bytes(block, bytes([key_byte] * 8))

        # Undo Round 2
        block = inv_pbox_perm(block)
        block = inv_sbox_sub(block)

        # Undo Round 1
        block = inv_pbox_perm(block)
        block = inv_sbox_sub(block)

        plaintext += block

    return plaintext.decode('utf-8').rstrip('X')


#  PART 4: AVALANCHE EFFECT DEMO


def count_bit_differences(bytes1, bytes2):
    """
    Count how many bits differ between two byte sequences.

    Parameters:
        bytes1 (bytes): First byte sequence.
        bytes2 (bytes): Second byte sequence.

    Returns:
        int: Number of bits that differ.
    """
    diff = xor_bytes(bytes1, bytes2)
    return sum(bin(b).count('1') for b in diff)


def avalanche_demo(message, seed):
    """
    Demonstrate the avalanche effect of the block cipher.
    Flips 1 bit in the plaintext and counts how many bits
    change in the resulting ciphertext.

    A good cipher should flip ~50% of output bits.

    Parameters:
        message (str): The original plaintext.
        seed    (int): Key seed for block cipher.

    Returns:
        None
    """
    original_bytes = message.encode('utf-8')

    # Flip the first bit of the first byte
    flipped_first_byte = original_bytes[0] ^ 0x01
    modified_bytes = bytes([flipped_first_byte]) + original_bytes[1:]
    modified_message = modified_bytes.decode('utf-8', errors='replace')

    ct1_hex = block_encrypt(message, seed)
    ct2_hex = block_encrypt(modified_message, seed)

    ct1 = bytes.fromhex(ct1_hex)
    ct2 = bytes.fromhex(ct2_hex)

    total_bits = len(ct1) * 8
    diff_bits = count_bit_differences(ct1, ct2)
    percentage = (diff_bits / total_bits) * 100

    print_separator()
    print("  AVALANCHE EFFECT DEMO")
    print_separator()
    print(f"  Original message  : {message}")
    print(f"  Modified message  : {modified_message}  (1 bit flipped)")
    print(f"  Ciphertext 1      : {ct1_hex}")
    print(f"  Ciphertext 2      : {ct2_hex}")
    print(f"  Total bits        : {total_bits}")
    print(f"  Bits changed      : {diff_bits}")
    print(f"  Change percentage : {percentage:.1f}%")
    if percentage >= 30:
        print("  [+] Good avalanche effect!")
    else:
        print("  [-] Weak avalanche — cipher needs improvement.")
    print_separator()


#  PART 5: STATISTICAL RANDOMNESS TEST


def frequency_test(seed, num_bytes=1000):
    """
    Basic frequency test on LCG output.
    Count 0-bits vs 1-bits. A good PRNG should be roughly 50/50.

    Parameters:
        seed      (int): LCG seed to test.
        num_bytes (int): How many bytes to generate and test.

    Returns:
        dict: {'zeros': int, 'ones': int, 'ratio': float}
    """
    lcg = LCG(seed=seed)
    data = lcg.generate_bytes(num_bytes)

    total_bits = num_bytes * 8
    ones = sum(bin(b).count('1') for b in data)
    zeros = total_bits - ones
    ratio = ones / total_bits

    print_separator()
    print(f"  FREQUENCY TEST — {num_bytes} bytes from LCG (seed={seed})")
    print_separator()
    print(f"  Total bits : {total_bits}")
    print(f"  Ones       : {ones}  ({ones/total_bits*100:.1f}%)")
    print(f"  Zeros      : {zeros}  ({zeros/total_bits*100:.1f}%)")
    print(f"  Ratio (1s) : {ratio:.4f}  (ideal = 0.5000)")

    if 0.45 <= ratio <= 0.55:
        print("  [+] PASS — Output looks reasonably random.")
    else:
        print("  [-] FAIL — Significant bias detected.")
    print_separator()

    return {'zeros': zeros, 'ones': ones, 'ratio': ratio}


#  MODULE MENU

def module2_menu():

    while True:
        print_separator()
        print("  MODULE 2 — Stream & Block Cipher")
        print_separator()
        print("  1. Visualize LCG Output")
        print("  2. Stream Cipher — Encrypt")
        print("  3. Stream Cipher — Decrypt")
        print("  4. Stream Cipher — Key Reuse Demo")
        print("  5. Block Cipher — Encrypt")
        print("  6. Block Cipher — Decrypt")
        print("  7. Avalanche Effect Demo")
        print("  8. Frequency Test (Randomness)")
        print("  0. Back to Main Menu")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            seed = int(input("  Enter seed (any number): "))
            lcg = LCG(seed=seed)
            lcg.visualize()

        elif choice == '2':
            msg = input("  Plaintext : ")
            seed = int(input("  Seed (key): "))
            ct = stream_encrypt(msg, seed)
            print(f"\n  Ciphertext (hex): {ct}\n")

        elif choice == '3':
            ct = input("  Ciphertext (hex): ")
            seed = int(input("  Seed (key)      : "))
            try:
                pt = stream_decrypt(ct, seed)
                print(f"\n  Decrypted: {pt}\n")
            except Exception as e:
                print(f"  [!] Error: {e}")

        elif choice == '4':
            m1 = input("  Message 1 : ")
            m2 = input("  Message 2 : ")
            seed = int(input("  Seed      : "))
            stream_key_reuse_demo(m1, m2, seed)

        elif choice == '5':
            msg = input("  Plaintext : ")
            seed = int(input("  Seed (key): "))
            ct = block_encrypt(msg, seed)
            print(f"\n  Ciphertext (hex): {ct}\n")

        elif choice == '6':
            ct = input("  Ciphertext (hex): ")
            seed = int(input("  Seed (key)      : "))
            try:
                pt = block_decrypt(ct, seed)
                print(f"\n  Decrypted: {pt}\n")
            except Exception as e:
                print(f"  [!] Error: {e}")

        elif choice == '7':
            msg = input("  Message : ")
            seed = int(input("  Seed    : "))
            avalanche_demo(msg, seed)

        elif choice == '8':
            seed = int(input("  Seed (any number): "))
            frequency_test(seed)

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option. Try again.")