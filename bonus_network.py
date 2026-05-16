"""
bonus_network.py - Network Simulation for SecureVault (+2 Bonus Marks)
======================================================================
Simulates Alice and Bob running on SEPARATE THREADS with a shared
public channel (Queue) demonstrating Diffie-Hellman key exchange
in real time.

Covers:
  - Alice thread: generates keys, sends public key, receives Bob's
  - Bob thread: generates keys, sends public key, receives Alice's
  - Shared Queue simulates the public network channel
  - Both derive the same shared secret independently
  - Eavesdropper thread listens but cannot compute the secret

Rules:
  - Standard library only: threading, queue, time, random
"""

import threading
import queue
import time
import random

from module4_keyx import (
    dh_generate_private_key,
    dh_compute_public_key,
    dh_compute_shared_secret,
    DH_PRIME_512,
    DH_GENERATOR
)
from utils import print_separator


# ─────────────────────────────────────────────
#  SHARED PUBLIC CHANNEL
# ─────────────────────────────────────────────

# Two queues simulate the public channel
# alice_to_bob: Alice sends her public key here, Bob reads it
# bob_to_alice: Bob sends his public key here, Alice reads it
alice_to_bob = queue.Queue()
bob_to_alice = queue.Queue()

# Eavesdropper queue — gets copies of everything on the channel
eavesdropper_log = queue.Queue()

# Lock for clean console printing from multiple threads
print_lock = threading.Lock()


def channel_print(who, message):
    """
    Thread-safe print with a [WHO] prefix.

    Parameters:
        who     (str): Label like 'Alice', 'Bob', 'Eve'.
        message (str): The message to print.
    """
    with print_lock:
        tag = {
            'Alice': '\033[94m[Alice]\033[0m',   # blue
            'Bob'  : '\033[92m[Bob  ]\033[0m',   # green
            'Eve'  : '\033[91m[Eve  ]\033[0m',   # red
        }.get(who, f'[{who}]')
        print(f"  {tag} {message}")


# ─────────────────────────────────────────────
#  ALICE THREAD
# ─────────────────────────────────────────────

def alice_thread(p, g, result_store):
    """
    Alice's thread — performs her side of the DH exchange.

    Steps:
      1. Generate private key a.
      2. Compute public key A = g^a mod p.
      3. Send A over the public channel (alice_to_bob queue).
      4. Wait for Bob's public key B.
      5. Compute shared secret = B^a mod p.

    Parameters:
        p            (int): DH prime.
        g            (int): DH generator.
        result_store (dict): Shared dict to store Alice's secret for comparison.

    Returns:
        None
    """
    channel_print('Alice', "Starting DH key exchange...")
    time.sleep(0.3)  # small delay to simulate network timing

    # Step 1 & 2: Generate keys
    a = dh_generate_private_key(p)
    A = dh_compute_public_key(a, g, p)
    channel_print('Alice', f"Generated private key a = ...{str(a)[-8:]}")
    channel_print('Alice', f"Computed public key  A = ...{str(A)[-8:]}")

    # Step 3: Send public key to Bob (and eavesdropper sees it)
    time.sleep(0.2)
    channel_print('Alice', "Sending public key A to Bob over public channel...")
    alice_to_bob.put(A)
    eavesdropper_log.put(('Alice->Bob', A))

    # Step 4: Wait for Bob's public key
    channel_print('Alice', "Waiting for Bob's public key...")
    B = bob_to_alice.get()
    channel_print('Alice', f"Received Bob's public key B = ...{str(B)[-8:]}")

    # Step 5: Compute shared secret
    secret = dh_compute_shared_secret(B, a, p)
    channel_print('Alice', f"Computed shared secret = ...{str(secret)[-12:]}")

    result_store['alice'] = secret


# ─────────────────────────────────────────────
#  BOB THREAD
# ─────────────────────────────────────────────

def bob_thread(p, g, result_store):
    """
    Bob's thread — performs his side of the DH exchange.

    Steps:
      1. Generate private key b.
      2. Compute public key B = g^b mod p.
      3. Wait for Alice's public key A.
      4. Send B over the public channel (bob_to_alice queue).
      5. Compute shared secret = A^b mod p.

    Parameters:
        p            (int): DH prime.
        g            (int): DH generator.
        result_store (dict): Shared dict to store Bob's secret for comparison.

    Returns:
        None
    """
    channel_print('Bob', "Starting DH key exchange...")
    time.sleep(0.5)  # Bob starts slightly later

    # Step 1 & 2: Generate keys
    b = dh_generate_private_key(p)
    B = dh_compute_public_key(b, g, p)
    channel_print('Bob', f"Generated private key b = ...{str(b)[-8:]}")
    channel_print('Bob', f"Computed public key  B = ...{str(B)[-8:]}")

    # Step 3: Wait for Alice's public key
    channel_print('Bob', "Waiting for Alice's public key...")
    A = alice_to_bob.get()
    channel_print('Bob', f"Received Alice's public key A = ...{str(A)[-8:]}")

    # Step 4: Send public key to Alice (eavesdropper sees it too)
    time.sleep(0.2)
    channel_print('Bob', "Sending public key B to Alice over public channel...")
    bob_to_alice.put(B)
    eavesdropper_log.put(('Bob->Alice', B))

    # Step 5: Compute shared secret
    secret = dh_compute_shared_secret(A, b, p)
    channel_print('Bob', f"Computed shared secret = ...{str(secret)[-12:]}")

    result_store['bob'] = secret


# ─────────────────────────────────────────────
#  EAVESDROPPER THREAD
# ─────────────────────────────────────────────

def eve_thread(p, g):
    """
    Eve's thread — listens on the public channel.
    She sees both public keys A and B, plus p and g.
    But she CANNOT compute the shared secret without solving
    the discrete logarithm problem.

    Parameters:
        p (int): DH prime (public).
        g (int): DH generator (public).

    Returns:
        None
    """
    channel_print('Eve', "Listening on public channel...")
    seen = {}

    # Collect both public keys from the channel log
    while len(seen) < 2:
        try:
            direction, key = eavesdropper_log.get(timeout=10)
            seen[direction] = key
            channel_print('Eve', f"Intercepted {direction}: ...{str(key)[-8:]}")
        except queue.Empty:
            break

    time.sleep(0.5)
    channel_print('Eve', "I have both public keys and know p and g...")
    channel_print('Eve', "But I cannot compute the shared secret without solving")
    channel_print('Eve', "the Discrete Logarithm Problem — computationally infeasible!")
    channel_print('Eve', "Giving up. The exchange is SECURE.")


# ─────────────────────────────────────────────
#  RUN THE SIMULATION
# ─────────────────────────────────────────────

def run_network_simulation():
    """
    Run the full threaded DH network simulation.
    Starts Alice, Bob, and Eve on separate threads simultaneously.
    After all threads finish, compares their shared secrets.

    Returns:
        None
    """
    print_separator()
    print("  NETWORK SIMULATION — Diffie-Hellman over Threaded Channel")
    print_separator()
    print("  Blue  = Alice   Green = Bob   Red = Eve (eavesdropper)")
    print_separator()

    p = DH_PRIME_512
    g = DH_GENERATOR
    result_store = {}  # shared dict to collect secrets from both threads

    # Create threads
    t_alice = threading.Thread(target=alice_thread, args=(p, g, result_store))
    t_bob   = threading.Thread(target=bob_thread,   args=(p, g, result_store))
    t_eve   = threading.Thread(target=eve_thread,   args=(p, g))

    # Start all three simultaneously
    t_alice.start()
    t_bob.start()
    t_eve.start()

    # Wait for all to finish
    t_alice.join()
    t_bob.join()
    t_eve.join()

    # Final result
    print_separator()
    print("  SIMULATION COMPLETE")
    print_separator()
    alice_secret = result_store.get('alice')
    bob_secret   = result_store.get('bob')

    if alice_secret and bob_secret:
        match = alice_secret == bob_secret
        print(f"  Alice's secret : ...{str(alice_secret)[-20:]}")
        print(f"  Bob's secret   : ...{str(bob_secret)[-20:]}")
        print(f"  Secrets match  : {match}")
        if match:
            print("  [+] Key exchange SUCCESS — secure channel established!")
        else:
            print("  [!] Mismatch — something went wrong.")
    print_separator()


# ─────────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────────

def network_menu():
    """
    Network simulation bonus module menu.

    Returns:
        None
    """
    while True:
        print_separator()
        print("  BONUS — Network Simulation (Threaded DH)")
        print_separator()
        print("  1. Run Full Simulation (Alice + Bob + Eve)")
        print("  0. Back")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            # Reset queues for a fresh run
            for q in [alice_to_bob, bob_to_alice, eavesdropper_log]:
                while not q.empty():
                    q.get()
            run_network_simulation()

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option.")