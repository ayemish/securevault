"""
module3_hash.py - Hash & Authentication Module for SecureVault
Covers:
  - Hash functions: MD5, SHA-1, SHA-256, SHA-512
  - HMAC-SHA256 built from scratch (inner/outer pad construction)
  - PBKDF2 password hashing with salt
  - File integrity checker
  - Birthday attack simulator

"""

import hashlib
import json
import os
import time
import base64

from utils import xor_bytes, generate_random_bytes, print_separator, format_hex_output

#  PART 1: HASH FUNCTIONS

def hash_message(message, algorithm='sha256'):
    """
    Hash a message using the specified algorithm.
    Parameters:
        message   (str): The plaintext message to hash.
        algorithm (str): One of 'md5', 'sha1', 'sha256', 'sha512'.

    Returns:
        str: Lowercase hex digest of the hash.

    Example:
        hash_message("hello", "sha256") -> "2cf24db..."
    """
    algorithm = algorithm.lower()
    supported = ['md5', 'sha1', 'sha256', 'sha512']

    if algorithm not in supported:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {supported}")

    h = hashlib.new(algorithm)
    h.update(message.encode('utf-8'))
    return h.hexdigest()


def compare_all_hashes(message):
    """
    Hash the same message with MD5, SHA-1, SHA-256, and SHA-512.
    Displays all results side by side for comparison.
    """
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    results = {}

    print_separator()
    print("  HASH COMPARISON")
    print_separator()
    print(f"  Message : {message}\n")

    for algo in algorithms:
        digest = hash_message(message, algo)
        results[algo] = digest
        digest_size = len(bytes.fromhex(digest)) * 8  # bits
        print(f"  {algo.upper():<8} ({digest_size:>3} bits): {digest}")

    print_separator()
    return results



#  PART 2: HMAC FROM SCRATCH

def hmac_sha256(key, message):
    """
    Compute HMAC-SHA256 using the inner-pad / outer-pad construction.
    Built manually — does NOT call hmac.new() 

    Construction:
        HMAC(K, M) = SHA256( (K XOR opad) || SHA256( (K XOR ipad) || M ) )

    Where:
        ipad = 0x36 repeated 64 times (SHA-256 block size)
        opad = 0x5C repeated 64 times

    Parameters:
        key     (str or bytes): The secret key.
        message (str or bytes): The message to authenticate.

    Returns:
        str: Hex digest of the HMAC.

    Example:
        hmac_sha256("secret", "hello") -> "88aab3..."
    """
    BLOCK_SIZE = 64  

    # Convert to bytes if strings
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Step 1: If key is longer than block size, hash it first
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # Step 2: Pad key to block size with zero bytes
    key = key.ljust(BLOCK_SIZE, b'\x00')

    # Step 3: Create inner and outer pad sequences
    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5C] * BLOCK_SIZE)

    # Step 4: XOR key with ipad and opad
    k_ipad = xor_bytes(key, ipad)
    k_opad = xor_bytes(key, opad)

    # Step 5: Inner hash — SHA256(k_ipad || message)
    inner_hash = hashlib.sha256(k_ipad + message).digest()

    # Step 6: Outer hash — SHA256(k_opad || inner_hash)
    outer_hash = hashlib.sha256(k_opad + inner_hash).hexdigest()

    return outer_hash


def verify_hmac(key, message, expected_hmac):
    """
    Verify that a message matches its expected HMAC.

    Parameters:
        key           (str): The secret key.
        message       (str): The original message.
        expected_hmac (str): The HMAC hex string to compare against.

    Returns:
        bool: True if HMAC matches, False if message was tampered with.

    Example:
        verify_hmac("secret", "hello", "88aab3...") -> True
    """
    computed = hmac_sha256(key, message)
    return computed == expected_hmac


#  PART 3: PBKDF2 PASSWORD HASHING


def hash_password(password, iterations=100000):
    """
    Hash a password securely using PBKDF2-HMAC-SHA256 with a random salt.

    Process:
        1. Generate 16 random bytes as salt.
        2. Run PBKDF2 with SHA-256 for 'iterations' rounds.
        3. Encode salt and hash as base64.
        4. Return as a JSON string: {"salt": "...", "hash": "...", "iterations": N}

    Parameters:
        password   (str): The plaintext password to hash.
        iterations (int): Number of PBKDF2 iterations. Minimum 100,000.

    Returns:
        str: JSON string containing salt, hash, and iteration count.

    Example:
        hash_password("mypassword") -> '{"salt": "abc...", "hash": "def...", "iterations": 100000}'
    """
    if iterations < 100000:
        raise ValueError("Iteration count must be at least 100,000 for security.")

    # Generate a random 16-byte salt
    salt = generate_random_bytes(16)

    # Run PBKDF2
    dk = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=iterations
    )

    # Encode both as base64 strings for safe storage
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    hash_b64 = base64.b64encode(dk).decode('utf-8')

    # Package everything into a JSON string
    stored = json.dumps({
        "salt": salt_b64,
        "hash": hash_b64,
        "iterations": iterations
    })

    return stored


def verify_password(password, stored_json):
    """
    Verify a plaintext password against a stored PBKDF2 hash.

    Process:
        1. Parse the stored JSON to extract salt, hash, and iteration count.
        2. Re-run PBKDF2 with the same salt and iterations.
        3. Compare the result to the stored hash.

    Parameters:
        password    (str): The plaintext password attempt.
        stored_json (str): JSON string returned by hash_password().

    Returns:
        bool: True if password matches, False otherwise.

    Example:
        verify_password("mypassword", stored_json) -> True
        verify_password("wrongpass",  stored_json) -> False
    """
    stored = json.loads(stored_json)

    salt = base64.b64decode(stored['salt'])
    stored_hash = base64.b64decode(stored['hash'])
    iterations = stored['iterations']

    # Re-derive the key with the same parameters
    dk = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=iterations
    )

    return dk == stored_hash


def demo_user_auth():
    """
    Interactive demo: register a user with PBKDF2, then verify login.
    Simulates a real register/login flow.

    Returns:
        None
    """
    print_separator()
    print("  USER AUTHENTICATION DEMO (PBKDF2)")
    print_separator()

    password = input("  Enter a password to register: ")
    print("\n  [*] Hashing password with PBKDF2-SHA256 (100,000 iterations)...")

    start = time.time()
    stored = hash_password(password)
    elapsed = time.time() - start

    print(f"  [+] Password hashed in {elapsed:.3f} seconds.")
    print(f"  [+] Stored value (JSON):\n      {stored}\n")

    attempt = input("  Enter password to verify login: ")
    if verify_password(attempt, stored):
        print("  [+] LOGIN SUCCESS — Password matched!")
    else:
        print("  [-] LOGIN FAILED — Incorrect password.")

    print_separator()


#  PART 4: FILE INTEGRITY CHECKER


def hash_file(filepath):
    """
    Compute the SHA-256 hash of a file's contents.
    Reads the file in chunks to handle large files efficiently.

    Parameters:
        filepath (str): Path to the file to hash.

    Returns:
        str: Hex digest of the file's SHA-256 hash.

    Raises:
        FileNotFoundError: If the file does not exist.

    Example:
        hash_file("report.pdf") -> "3b4c5d..."
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        # Read in 64KB chunks — avoids loading huge files into memory
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)

    return h.hexdigest()


def save_file_digest(filepath, digest_store='data/file_digests.json'):
    """
    Hash a file and save its SHA-256 digest to a JSON store.

    Parameters:
        filepath     (str): Path to the file to check.
        digest_store (str): Path to the JSON file storing known-good hashes.

    Returns:
        str: The hex digest that was saved.

    Example:
        save_file_digest("report.pdf") -> "3b4c5d..."
    """
    digest = hash_file(filepath)

    # Load existing store or start fresh
    if os.path.exists(digest_store):
        with open(digest_store, 'r') as f:
            store = json.load(f)
    else:
        store = {}

    store[filepath] = digest

    with open(digest_store, 'w') as f:
        json.dump(store, f, indent=2)

    print(f"  [+] Digest saved for '{filepath}'")
    print(f"      SHA-256: {digest}")
    return digest


def verify_file_integrity(filepath, digest_store='data/file_digests.json'):
    """
    Recheck a file's SHA-256 hash against its previously saved digest.

    Parameters:
        filepath     (str): Path to the file to verify.
        digest_store (str): Path to the JSON file storing known-good hashes.

    Returns:
        bool: True if file is unchanged, False if tampered.

    Raises:
        KeyError: If the file has no saved digest to compare against.

    Example:
        verify_file_integrity("report.pdf") -> True
    """
    if not os.path.exists(digest_store):
        raise FileNotFoundError(f"No digest store found at '{digest_store}'. Run save_file_digest first.")

    with open(digest_store, 'r') as f:
        store = json.load(f)

    if filepath not in store:
        raise KeyError(f"No saved digest for '{filepath}'. Register it first with save_file_digest().")

    saved_digest = store[filepath]
    current_digest = hash_file(filepath)

    print_separator()
    print("  FILE INTEGRITY CHECK")
    print_separator()
    print(f"  File          : {filepath}")
    print(f"  Saved digest  : {saved_digest}")
    print(f"  Current digest: {current_digest}")

    if saved_digest == current_digest:
        print("  [+] RESULT: File is INTACT — no tampering detected.")
        return True
    else:
        print("  [!] RESULT: TAMPERED — digests do not match!")
        return False


#  PART 5: BIRTHDAY ATTACK SIMULATOR


def birthday_attack(bits=16, max_attempts=500000):
    """
    Demonstrate the birthday paradox using truncated SHA-256 hashes.

    How it works:
        - Truncate SHA-256 output to 'bits' bits (e.g. 16 bits = 65536 possible values).
        - Keep hashing random strings until two inputs produce the same truncated hash.
        - A collision is found much faster than brute force — roughly sqrt(2^bits) attempts.

    Parameters:
        bits         (int): Number of bits to use from SHA-256. Keep between 8 and 24.
        max_attempts (int): Safety cap on number of attempts.

    Returns:
        dict: {'found': bool, 'attempts': int, 'input1': str, 'input2': str, 'hash': str}

    Example:
        birthday_attack(bits=16) -> {'found': True, 'attempts': 312, ...}
    """
    print_separator()
    print(f"  BIRTHDAY ATTACK SIMULATOR ({bits}-bit hash space)")
    print(f"  Possible hash values: {2**bits:,}")
    print(f"  Expected collisions around: ~{int((2**bits)**0.5):,} attempts")
    print_separator()

    seen = {}   # maps truncated_hash -> original input string
    attempts = 0
    start = time.time()

    while attempts < max_attempts:
        # Generate a random-ish string to hash
        random_input = base64.b64encode(os.urandom(8)).decode('utf-8')
        full_hash = hashlib.sha256(random_input.encode()).hexdigest()

        # Truncate to 'bits' bits by taking the first (bits // 4) hex characters
        hex_chars = bits // 4
        truncated = full_hash[:hex_chars]

        if truncated in seen:
            elapsed = time.time() - start
            print(f"  [+] COLLISION FOUND after {attempts:,} attempts ({elapsed:.2f}s)")
            print(f"  Input 1 : {seen[truncated]}")
            print(f"  Input 2 : {random_input}")
            print(f"  Hash    : {truncated} (both produce this {bits}-bit hash)")
            print_separator()
            return {
                'found': True,
                'attempts': attempts,
                'input1': seen[truncated],
                'input2': random_input,
                'hash': truncated
            }

        seen[truncated] = random_input
        attempts += 1

    print(f"  [-] No collision found within {max_attempts:,} attempts.")
    print_separator()
    return {'found': False, 'attempts': attempts}


#  PART 6: TIMING COMPARISON


def timing_comparison(data_mb=1):
    """
    Compare the speed of MD5 vs SHA-256 on a large chunk of data.

    Parameters:
        data_mb (int): Size of test data in megabytes.

    Returns:
        dict: {'md5_time': float, 'sha256_time': float} in seconds.

    Example:
        timing_comparison(2) -> {'md5_time': 0.012, 'sha256_time': 0.031}
    """
    data = os.urandom(data_mb * 1024 * 1024)  # Generate random bytes

    print_separator()
    print(f"  TIMING COMPARISON — MD5 vs SHA-256 on {data_mb}MB of data")
    print_separator()

    # MD5 timing
    start = time.time()
    hashlib.md5(data).hexdigest()
    md5_time = time.time() - start

    # SHA-256 timing
    start = time.time()
    hashlib.sha256(data).hexdigest()
    sha256_time = time.time() - start

    print(f"  MD5    : {md5_time:.4f} seconds")
    print(f"  SHA-256: {sha256_time:.4f} seconds")
    print(f"  SHA-256 is {sha256_time/md5_time:.2f}x slower than MD5")
    print_separator()

    return {'md5_time': md5_time, 'sha256_time': sha256_time}


#  MODULE MENU


def module3_menu():
    """
    Display the Module 3 interactive menu.
    Called from main.py when user selects Module 3.

    Returns:
        None
    """
    while True:
        print_separator()
        print("  MODULE 3 — Hash & Authentication")
        print_separator()
        print("  1. Hash a message (MD5 / SHA-1 / SHA-256 / SHA-512)")
        print("  2. Compare all hash algorithms")
        print("  3. Compute HMAC-SHA256")
        print("  4. User Authentication Demo (PBKDF2)")
        print("  5. File Integrity — Save digest")
        print("  6. File Integrity — Verify file")
        print("  7. Birthday Attack Simulator")
        print("  8. MD5 vs SHA-256 Timing Comparison")
        print("  0. Back to Main Menu")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            msg = input("  Enter message: ")
            algo = input("  Algorithm (md5/sha1/sha256/sha512): ").strip().lower()
            result = hash_message(msg, algo)
            print(f"\n  [{algo.upper()}] {result}\n")

        elif choice == '2':
            msg = input("  Enter message: ")
            compare_all_hashes(msg)

        elif choice == '3':
            key = input("  Enter HMAC key: ")
            msg = input("  Enter message : ")
            result = hmac_sha256(key, msg)
            print(f"\n  HMAC-SHA256: {result}\n")

        elif choice == '4':
            demo_user_auth()

        elif choice == '5':
            path = input("  Enter file path: ").strip()
            try:
                save_file_digest(path)
            except FileNotFoundError as e:
                print(f"  [!] Error: {e}")

        elif choice == '6':
            path = input("  Enter file path: ").strip()
            try:
                verify_file_integrity(path)
            except (FileNotFoundError, KeyError) as e:
                print(f"  [!] Error: {e}")

        elif choice == '7':
            bits = int(input("  Hash bits (8-24, recommended 16): ").strip())
            birthday_attack(bits)

        elif choice == '8':
            mb = int(input("  Data size in MB (e.g. 1): ").strip())
            timing_comparison(mb)

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option. Try again.")