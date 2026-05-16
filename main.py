from utils import display_banner, print_separator, clear_screen

from module1_classical import module1_menu
from module2_stream     import module2_menu
from module3_hash       import module3_menu, hash_message, hmac_sha256
from module4_keyx       import module4_menu, dh_full_demo, dh_generate_private_key, \
                               dh_compute_public_key, dh_compute_shared_secret, DH_PRIME_512, DH_GENERATOR
from module5_blockchain import module5_menu, log_event, get_blockchain

from module1_classical  import vigenere_encrypt, vigenere_decrypt
from bonus_rsa     import rsa_menu
from bonus_network import network_menu
from bonus_merkle  import merkle_menu


def secure_message_workflow():
    """
    End-to-end Secure Message Workflow — ties all 5 modules together.

    Steps:
      1. Alice encrypts a message with Vigenere (Module 1)
      2. Computes SHA-256 hash of ciphertext (Module 3)
      3. Computes HMAC for message authentication (Module 3)
      4. Alice and Bob perform DH key exchange (Module 4)
      5. Verify HMAC on Bob's side (Module 3)
      6. Decrypt ciphertext (Module 1)
      7. Log every step to the blockchain (Module 5)

    Returns:
        None
    """
    print_separator()
    print("  SECURE MESSAGE WORKFLOW — All Modules Combined")
    print_separator()

    message = input("  Enter message to send securely: ")
    key     = input("  Enter Vigenere key (letters only): ")
    hmac_key = input("  Enter HMAC secret key: ")

    print()

    # ── Step 1: Encrypt with Vigenere ──────────────
    print("  [Step 1] Encrypting message with Vigenere Cipher...")
    ciphertext = vigenere_encrypt(message, key)
    print(f"           Ciphertext: {ciphertext}")
    log_event("ENCRYPT", {"module": "Vigenere", "ciphertext": ciphertext})

    # ── Step 2: Hash the ciphertext ────────────────
    print("\n  [Step 2] Hashing ciphertext with SHA-256...")
    digest = hash_message(ciphertext, 'sha256')
    print(f"           SHA-256: {digest}")
    log_event("HASH", {"algorithm": "sha256", "digest": digest[:20] + "..."})

    # ── Step 3: Compute HMAC ───────────────────────
    print("\n  [Step 3] Computing HMAC-SHA256 for authentication...")
    mac = hmac_sha256(hmac_key, ciphertext)
    print(f"           HMAC: {mac}")
    log_event("HMAC", {"hmac": mac[:20] + "..."})

    # ── Step 4: DH Key Exchange ────────────────────
    print("\n  [Step 4] Performing Diffie-Hellman Key Exchange...")
    p = DH_PRIME_512
    g = DH_GENERATOR

    alice_priv = dh_generate_private_key(p)
    alice_pub  = dh_compute_public_key(alice_priv, g, p)

    bob_priv   = dh_generate_private_key(p)
    bob_pub    = dh_compute_public_key(bob_priv, g, p)

    alice_secret = dh_compute_shared_secret(bob_pub, alice_priv, p)
    bob_secret   = dh_compute_shared_secret(alice_pub, bob_priv, p)

    print(f"           Shared secrets match: {alice_secret == bob_secret}")
    log_event("KEY_EXCHANGE", {"method": "Diffie-Hellman", "match": str(alice_secret == bob_secret)})

    # ── Step 5: Verify HMAC ────────────────────────
    print("\n  [Step 5] Bob verifying HMAC...")
    recomputed_mac = hmac_sha256(hmac_key, ciphertext)
    hmac_valid = recomputed_mac == mac
    print(f"           HMAC valid: {hmac_valid}")
    if not hmac_valid:
        print("           [!] Message authentication FAILED. Aborting.")
        return

    # ── Step 6: Decrypt ────────────────────────────
    print("\n  [Step 6] Decrypting ciphertext...")
    decrypted = vigenere_decrypt(ciphertext, key)
    print(f"           Decrypted: {decrypted}")
    log_event("DECRYPT", {"module": "Vigenere", "match": str(decrypted == message)})

    # ── Step 7: Summary ────────────────────────────
    print_separator()
    print("  WORKFLOW COMPLETE")
    print_separator()
    print(f"  Original  : {message}")
    print(f"  Encrypted : {ciphertext}")
    print(f"  Decrypted : {decrypted}")
    print(f"  Integrity : {'OK' if decrypted == message else 'FAILED'}")
    print(f"  All steps logged to blockchain.")
    print_separator()



def show_status():
    """
    Display current system status:
    - Blockchain length and validity
    - All available modules

    Returns:
        None
    """
    bc = get_blockchain()

    print_separator()
    print("  SECUREVAULT SYSTEM STATUS")
    print_separator()
    print(f"  Blockchain blocks : {len(bc.chain)}")
    print(f"  Chain valid       : {bc.validate_chain()}")
    print()
    print("  Modules loaded:")
    print("    [1] Classical Cipher Engine")
    print("    [2] Stream & Block Cipher")
    print("    [3] Hash & Authentication")
    print("    [4] Key Exchange & Number Theory")
    print("    [5] Blockchain Audit Logger")
    print_separator()




def main_menu():
    """
    Display the main SecureVault menu and route to each module.

    Returns:
        None
    """
    # Initialize blockchain on startup
    get_blockchain()

    while True:
        
        display_banner()
        print_separator()
        print("  MAIN MENU")
        print_separator()
        print("  1. Classical Cipher Engine")
        print("  2. Stream & Block Cipher")
        print("  3. Hash & Authentication")
        print("  4. Key Exchange & Number Theory")
        print("  5. Blockchain Audit Logger")
        print("  6. Secure Message Workflow  (all modules)")
        print("  7. System Status")
        print("  8. Bonus — RSA Implementation")
        print("  9. Bonus — Network Simulation")
        print("  10. Bonus — Merkle Tree")
        print("  0. Exit")
        print_separator()

        choice = input("  Select option: ").strip()

        if   choice == '1': module1_menu()
        elif choice == '2': module2_menu()
        elif choice == '3': module3_menu()
        elif choice == '4': module4_menu()
        elif choice == '5': module5_menu()
        elif choice == '6': secure_message_workflow()
        elif choice == '7': show_status()
        elif choice == '8':  rsa_menu()
        elif choice == '9':  network_menu()
        elif choice == '10': merkle_menu()
        elif choice == '0':
            print("\n  Goodbye. Stay secure.\n")
            break
        else:
            print("  [!] Invalid option. Try again.")
            input("  Press Enter to continue...")



if __name__ == "__main__":
    main_menu()