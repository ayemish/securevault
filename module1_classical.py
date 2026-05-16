"""
module1_classical.py - Classical Cipher Engine for SecureVault

Covers:
  - Caesar Cipher (arbitrary shift)
  - ROT-13 (Caesar with shift=13)
  - Vigenere Cipher with Index of Coincidence key-length analysis
  - One-Time Pad (XOR with random key)
  - Substitution Cipher (full 26-char alphabet key)
  - Columnar Transposition Cipher

"""

import os
import string
import math
from collections import Counter

from utils import xor_bytes, generate_random_bytes, pad_string, print_separator


#  CIPHER 1: CAESAR CIPHER


def caesar_encrypt(plaintext, shift):
    """
    Only shifts alphabetic characters. Numbers and symbols stay unchanged.
    """
    shift = shift % 26  # normalize shift to 0-25
    result = []

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - base + shift) % 26
            result.append(chr(base + shifted))
        else:
            result.append(char) 

    return ''.join(result)


def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)



#  CIPHER 2: ROT-13


def rot13(text):
    """
    ROT-13 is Caesar with shift=13. It is its own inverse:
    applying it twice returns the original message.
    
    """
    return caesar_encrypt(text, 13)


#  CIPHER 3: VIGENERE CIPHER

def vigenere_encrypt(plaintext, key):
    """
    The key repeats to match the length of the message.
    Only alphabetic characters are shifted; others pass through unchanged.
    """
    if not key.isalpha():
        raise ValueError("Vigenere key must contain only alphabetic characters.")

    key = key.upper()
    result = []
    key_index = 0 

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            shifted = (ord(char) - base + shift) % 26
            result.append(chr(base + shifted))
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def vigenere_decrypt(ciphertext, key):
    """
    Decrypt a Vigenere Cipher ciphertext using the same key.
    """
    if not key.isalpha():
        raise ValueError("Vigenere key must contain only alphabetic characters.")

    key = key.upper()
    result = []
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            shifted = (ord(char) - base - shift) % 26
            result.append(chr(base + shifted))
            key_index += 1
        else:
            result.append(char)

    return ''.join(result)


def index_of_coincidence(text):
    """
    Calculate the Index of Coincidence (IC) of a text.
    IC measures how non-random a text is:
      - Random English text IC ≈ 0.038
      - Normal English text IC ≈ 0.065
    Used to estimate the key length of a Vigenere cipher.

    Parameters:
        text (str): The ciphertext (alphabetic characters only used).

    Returns:
        float: The Index of Coincidence value.

    Example:
        index_of_coincidence("HELLOWORLD") -> ~0.06
    """
    # Extract only alphabetic characters, uppercase
    letters = [c.upper() for c in text if c.isalpha()]
    n = len(letters)

    if n < 2:
        return 0.0

    freq = Counter(letters)
    ic = sum(count * (count - 1) for count in freq.values()) / (n * (n - 1))
    return ic


def vigenere_key_length_analysis(ciphertext, max_key_length=20):
    """
    Estimate the key length of a Vigenere cipher using Index of Coincidence.
    For each candidate key length k, split ciphertext into k groups (every
    k-th character) and compute average IC. Higher IC = more likely key length.

    Parameters:
        ciphertext     (str): The Vigenere ciphertext to analyze.
        max_key_length (int): Maximum key length to test.

    Returns:
        list: Sorted list of (key_length, avg_ic) tuples, best first.

    Example:
        vigenere_key_length_analysis("RIJVSRIJVS", 5) -> [(3, 0.065), ...]
    """
    letters = [c.upper() for c in ciphertext if c.isalpha()]
    results = []

    print_separator()
    print("  VIGENERE KEY LENGTH ANALYSIS (Index of Coincidence)")
    print_separator()
    print(f"  {'Key Length':<12} {'Avg IC':<10} {'Likely?'}")
    print_separator('-', 40)

    for key_len in range(1, max_key_length + 1):
        # Split into key_len groups: chars at positions 0, k, 2k... then 1, k+1, 2k+1...
        groups = [letters[i::key_len] for i in range(key_len)]
        avg_ic = sum(index_of_coincidence(g) for g in groups) / key_len
        results.append((key_len, avg_ic))

        likely = "<-- likely key length" if avg_ic > 0.055 else ""
        print(f"  {key_len:<12} {avg_ic:<10.4f} {likely}")

    print_separator()
    results.sort(key=lambda x: x[1], reverse=True)
    return results


def vigenere_frequency_analysis(ciphertext, sample_size=200):
    """
    Demonstrate Vigenere cipher weakness using frequency analysis.
    Shows the letter frequency distribution of the ciphertext,
    which deviates from uniform random for short keys.

    Parameters:
        ciphertext  (str): The ciphertext to analyze.
        sample_size (int): Minimum characters needed (requirement: >= 200).

    Returns:
        dict: Letter frequencies as percentages.

    Raises:
        ValueError: If ciphertext has fewer than sample_size alphabetic characters.
    """
    letters = [c.upper() for c in ciphertext if c.isalpha()]

    if len(letters) < sample_size:
        raise ValueError(f"Need at least {sample_size} alphabetic characters for analysis.")

    freq = Counter(letters)
    total = len(letters)

    print_separator()
    print("  VIGENERE FREQUENCY ANALYSIS")
    print_separator()

    result = {}
    for letter in string.ascii_uppercase:
        count = freq.get(letter, 0)
        pct = (count / total) * 100
        result[letter] = pct
        bar = '#' * int(pct)
        print(f"  {letter}: {bar:<20} {pct:.2f}%")

    print_separator()
    return result



#  CIPHER 4: ONE-TIME PAD (OTP)


def otp_encrypt(plaintext):
    """
    Encrypt a message using the One-Time Pad (OTP).
    Generates a truly random key the same length as the plaintext.
    Encrypts by XORing plaintext bytes with key bytes.

    Perfect secrecy: without the key, the ciphertext reveals NOTHING
    about the plaintext — every possible plaintext is equally likely.

    Parameters:
        plaintext (str): The message to encrypt.

    Returns:
        tuple: (ciphertext_hex: str, key_hex: str)
               Both returned as hex strings for display/storage.

    Example:
        otp_encrypt("Hi") -> ("3f2a", "7e4b")   # values will differ each run
    """
    plaintext_bytes = plaintext.encode('utf-8')
    key_bytes = generate_random_bytes(len(plaintext_bytes))

    ciphertext_bytes = xor_bytes(plaintext_bytes, key_bytes)

    return ciphertext_bytes.hex(), key_bytes.hex()


def otp_decrypt(ciphertext_hex, key_hex):
    """
    Decrypt a One-Time Pad ciphertext using the original key.
    XOR is its own inverse: (A XOR K) XOR K = A

    Parameters:
        ciphertext_hex (str): Hex string of the ciphertext.
        key_hex        (str): Hex string of the key used during encryption.

    Returns:
        str: The decrypted plaintext.

    Example:
        otp_decrypt("3f2a", "7e4b") -> "Hi"
    """
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    key_bytes = bytes.fromhex(key_hex)

    plaintext_bytes = xor_bytes(ciphertext_bytes, key_bytes)
    return plaintext_bytes.decode('utf-8')


def otp_key_reuse_demo(message1, message2):
    """
    Demonstrate why OTP key reuse is catastrophic.
    If the same key is used for two messages:
        C1 XOR C2 = (M1 XOR K) XOR (M2 XOR K) = M1 XOR M2
    An attacker gets the XOR of both plaintexts — leaking information.

    Parameters:
        message1 (str): First plaintext message.
        message2 (str): Second plaintext message (same key will be reused).

    Returns:
        None
    """
    # Use the shorter message length for both
    length = min(len(message1), len(message2))
    m1 = message1[:length].encode('utf-8')
    m2 = message2[:length].encode('utf-8')

    # Generate ONE key and reuse it (the mistake!)
    key = generate_random_bytes(length)

    c1 = xor_bytes(m1, key)
    c2 = xor_bytes(m2, key)

    # Attacker XORs the two ciphertexts
    xored = xor_bytes(c1, c2)
    # This equals M1 XOR M2 — attacker now has info about both messages
    m1_xor_m2 = xor_bytes(m1, m2)

    print_separator()
    print("  OTP KEY REUSE DEMONSTRATION")
    print_separator()
    print(f"  Message 1      : {message1[:length]}")
    print(f"  Message 2      : {message2[:length]}")
    print(f"  Key (hex)      : {key.hex()}")
    print(f"  Ciphertext 1   : {c1.hex()}")
    print(f"  Ciphertext 2   : {c2.hex()}")
    print(f"  C1 XOR C2      : {xored.hex()}")
    print(f"  M1 XOR M2      : {m1_xor_m2.hex()}")
    print(f"  Match (proves leak): {xored == m1_xor_m2}")
    print("  [!] Key reuse leaks the XOR of both plaintexts!")
    print_separator()


#  CIPHER 5: SUBSTITUTION CIPHER


def validate_substitution_key(key):
    """
    Validate a substitution cipher key.
    Key must be exactly 26 unique alphabetic characters.

    Parameters:
        key (str): The substitution key to validate.

    Returns:
        bool: True if valid.

    Raises:
        ValueError: If key is invalid with a description of the problem.

    Example:
        validate_substitution_key("QWERTYUIOPASDFGHJKLZXCVBNM") -> True
    """
    key = key.upper()
    if len(key) != 26:
        raise ValueError(f"Key must be exactly 26 characters. Got {len(key)}.")
    if not key.isalpha():
        raise ValueError("Key must contain only alphabetic characters.")
    if len(set(key)) != 26:
        raise ValueError("Key must contain each letter exactly once (no duplicates).")
    return True


def substitution_encrypt(plaintext, key):
    """
    Encrypt plaintext using a full 26-character substitution cipher.
    Each letter in the alphabet maps to the corresponding letter in the key.
    A->key[0], B->key[1], ..., Z->key[25]

    Parameters:
        plaintext (str): The message to encrypt.
        key       (str): A 26-character substitution key.

    Returns:
        str: Encrypted ciphertext.

    Example:
        substitution_encrypt("HELLO", "QWERTYUIOPASDFGHJKLZXCVBNM") -> "ITSSG"
    """
    validate_substitution_key(key)
    key = key.upper()
    result = []

    for char in plaintext:
        if char.isalpha():
            index = ord(char.upper()) - ord('A')
            sub = key[index]
            # Preserve original case
            result.append(sub if char.isupper() else sub.lower())
        else:
            result.append(char)

    return ''.join(result)


def substitution_decrypt(ciphertext, key):
    """
    Decrypt a substitution cipher ciphertext using the same key.
    Builds the reverse mapping: key[i] -> alphabet[i]

    Parameters:
        ciphertext (str): The encrypted message.
        key        (str): The 26-character substitution key used during encryption.

    Returns:
        str: Decrypted plaintext.

    Example:
        substitution_decrypt("ITSSG", "QWERTYUIOPASDFGHJKLZXCVBNM") -> "HELLO"
    """
    validate_substitution_key(key)
    key = key.upper()

    # Build reverse mapping: each key letter maps back to original alphabet letter
    reverse_key = [''] * 26
    for i, k in enumerate(key):
        reverse_key[ord(k) - ord('A')] = chr(ord('A') + i)

    result = []
    for char in ciphertext:
        if char.isalpha():
            index = ord(char.upper()) - ord('A')
            original = reverse_key[index]
            result.append(original if char.isupper() else original.lower())
        else:
            result.append(char)

    return ''.join(result)


#  CIPHER 6: COLUMNAR TRANSPOSITION CIPHER

def columnar_encrypt(plaintext, key):
    """
    Encrypt plaintext using Columnar Transposition Cipher.

    How it works:
        1. Write the plaintext in rows under the keyword letters.
        2. Number the columns by alphabetical order of keyword letters.
        3. Read off columns in that numbered order.
        Pad with 'X' if the last row is incomplete.

    Parameters:
        plaintext (str): The message to encrypt (spaces removed automatically).
        key       (str): The keyword to determine column order.

    Returns:
        str: Encrypted ciphertext.

    Example:
        columnar_encrypt("HELLOWORLD", "KEY") -> "LODEHLWLOR" (approx)
    """
    # Remove spaces and uppercase
    plaintext = plaintext.replace(' ', '').upper()
    num_cols = len(key)

    # Pad to fill the grid completely
    plaintext = pad_string(plaintext, num_cols, 'X')
    num_rows = len(plaintext) // num_cols

    # Fill the grid row by row
    grid = []
    for r in range(num_rows):
        row = plaintext[r * num_cols: (r + 1) * num_cols]
        grid.append(list(row))

    # Determine column read order based on alphabetical order of key letters
    key_upper = key.upper()
    col_order = sorted(range(num_cols), key=lambda i: key_upper[i])

    # Read columns in sorted order
    ciphertext = ''
    for col in col_order:
        for row in grid:
            ciphertext += row[col]

    return ciphertext


def columnar_decrypt(ciphertext, key):

    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols

    key_upper = key.upper()
    col_order = sorted(range(num_cols), key=lambda i: key_upper[i])


    col_lengths = [num_rows] * num_cols


    columns = {}
    index = 0
    for col in col_order:
        length = col_lengths[col]
        columns[col] = list(ciphertext[index: index + length])
        index += length

    plaintext = ''
    for r in range(num_rows):
        for c in range(num_cols):
            plaintext += columns[c][r]

    return plaintext

#  COMPARISON

def compare_all_ciphers(message):

    print_separator()
    print("  CIPHER COMPARISON — All 6 Ciphers")
    print_separator()
    print(f"  Original Message : {message}\n")

    results = {}

    # 1. Caesar
    ct = caesar_encrypt(message, 13)
    results['Caesar (shift=13)'] = ct
    print(f"  1. Caesar (shift=13)       : {ct}")

    # 2. ROT-13
    ct = rot13(message)
    results['ROT-13'] = ct
    print(f"  2. ROT-13                  : {ct}")

    # 3. Vigenere
    ct = vigenere_encrypt(message.replace(' ', ''), 'SECRET')
    results['Vigenere (key=SECRET)'] = ct
    print(f"  3. Vigenere (key=SECRET)   : {ct}")

    # 4. OTP
    ct_hex, key_hex = otp_encrypt(message)
    results['OTP'] = ct_hex
    print(f"  4. OTP (hex)               : {ct_hex}")
    print(f"     OTP Key (hex)           : {key_hex}")

    # 5. Substitution
    sub_key = 'QWERTYUIOPASDFGHJKLZXCVBNM'
    ct = substitution_encrypt(message, sub_key)
    results['Substitution'] = ct
    print(f"  5. Substitution            : {ct}")
    print(f"     Key                     : {sub_key}")

    # 6. Columnar Transposition
    ct = columnar_encrypt(message, 'KEY')
    results['Columnar Transposition'] = ct
    print(f"  6. Columnar (key=KEY)      : {ct}")

    print_separator()
    return results

#  MODULE MENU

def module1_menu():

    while True:
        print_separator()
        print("  MODULE 1 — Classical Cipher Engine")
        print_separator()
        print("  1.  Caesar Cipher")
        print("  2.  ROT-13")
        print("  3.  Vigenere Cipher")
        print("  4.  Vigenere Key-Length Analysis")
        print("  5.  Vigenere Frequency Analysis")
        print("  6.  One-Time Pad (OTP) — Encrypt")
        print("  7.  One-Time Pad (OTP) — Decrypt")
        print("  8.  OTP Key Reuse Demo")
        print("  9.  Substitution Cipher")
        print("  10. Columnar Transposition Cipher")
        print("  11. Compare All 6 Ciphers")
        print("  0.  Back to Main Menu")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            msg = input("  Plaintext : ")
            shift = int(input("  Shift     : "))
            enc = caesar_encrypt(msg, shift)
            dec = caesar_decrypt(enc, shift)
            print(f"\n  Encrypted : {enc}")
            print(f"  Decrypted : {dec}\n")

        elif choice == '2':
            msg = input("  Text : ")
            result = rot13(msg)
            print(f"\n  ROT-13    : {result}")
            print(f"  ROT-13 x2 : {rot13(result)}  (should match original)\n")

        elif choice == '3':
            msg = input("  Plaintext : ")
            key = input("  Key       : ")
            enc = vigenere_encrypt(msg, key)
            dec = vigenere_decrypt(enc, key)
            print(f"\n  Encrypted : {enc}")
            print(f"  Decrypted : {dec}\n")

        elif choice == '4':
            msg = input("  Ciphertext (min 40 chars): ")
            vigenere_key_length_analysis(msg)

        elif choice == '5':
            msg = input("  Ciphertext (min 200 chars): ")
            try:
                vigenere_frequency_analysis(msg)
            except ValueError as e:
                print(f"  [!] {e}")

        elif choice == '6':
            msg = input("  Plaintext : ")
            ct_hex, key_hex = otp_encrypt(msg)
            print(f"\n  Ciphertext (hex) : {ct_hex}")
            print(f"  Key (hex)        : {key_hex}")
            print("  [!] Save the key — you need it to decrypt!\n")

        elif choice == '7':
            ct_hex = input("  Ciphertext (hex) : ")
            key_hex = input("  Key (hex)        : ")
            try:
                pt = otp_decrypt(ct_hex, key_hex)
                print(f"\n  Decrypted : {pt}\n")
            except Exception as e:
                print(f"  [!] Error: {e}")

        elif choice == '8':
            m1 = input("  Message 1 : ")
            m2 = input("  Message 2 : ")
            otp_key_reuse_demo(m1, m2)

        elif choice == '9':
            msg = input("  Plaintext : ")
            key = input("  Key (26 unique letters, e.g. QWERTYUIOPASDFGHJKLZXCVBNM): ")
            try:
                enc = substitution_encrypt(msg, key)
                dec = substitution_decrypt(enc, key)
                print(f"\n  Encrypted : {enc}")
                print(f"  Decrypted : {dec}\n")
            except ValueError as e:
                print(f"  [!] {e}")

        elif choice == '10':
            msg = input("  Plaintext : ")
            key = input("  Key       : ")
            enc = columnar_encrypt(msg, key)
            dec = columnar_decrypt(enc, key)
            print(f"\n  Encrypted : {enc}")
            print(f"  Decrypted : {dec}\n")

        elif choice == '11':
            msg = input("  Message to compare: ")
            compare_all_ciphers(msg)

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option. Try again.")