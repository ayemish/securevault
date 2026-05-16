"""
module5_blockchain.py - Blockchain Audit Logger for SecureVault
===============================================================
Covers:
  - Block structure (index, timestamp, event_type, event_data,
    previous_hash, nonce, block_hash)
  - Chain management: add_block(), validate_chain(), get_history()
  - Proof-of-Work with configurable difficulty
  - Tamper detection
  - Persist chain to data/blockchain.json

Rules:
  - Standard library only: hashlib, json, time, os
"""

import hashlib
import json
import os
import time

from utils import print_separator



#  BLOCK


class Block:
    """
    A single block in the blockchain.

    Attributes:
        index         (int): Position in the chain (0 = genesis).
        timestamp     (float): Unix timestamp of creation.
        event_type    (str): e.g. 'ENCRYPT', 'HASH', 'KEY_EXCHANGE'.
        event_data    (dict): Details of the cryptographic operation.
        previous_hash (str): Hash of the previous block.
        nonce         (int): Value found during proof-of-work mining.
        block_hash    (str): SHA-256 hash of this block's contents.
    """

    def __init__(self, index, event_type, event_data, previous_hash):
        """
        Create a new block. block_hash is empty until mine() is called.

        Parameters:
            index         (int): Block number.
            event_type    (str): Type of event being logged.
            event_data    (dict): Event details.
            previous_hash (str): Hash of the previous block.
        """
        self.index = index
        self.timestamp = time.time()
        self.event_type = event_type
        self.event_data = event_data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.block_hash = ""

    def compute_hash(self):
        """
        Compute SHA-256 hash of this block's contents.
        Combines all fields into a single string, then hashes it.

        Returns:
            str: Hex digest of the block's hash.
        """
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)

        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def mine(self, difficulty):
        """
        Perform Proof-of-Work mining.
        Keep incrementing nonce until block_hash starts with
        'difficulty' number of leading zeros.

        Parameters:
            difficulty (int): Number of leading zeros required.

        Returns:
            None (sets self.nonce and self.block_hash)

        Example:
            difficulty=3 → hash must start with "000"
        """
        target = '0' * difficulty
        self.nonce = 0

        while True:
            self.block_hash = self.compute_hash()
            if self.block_hash.startswith(target):
                break
            self.nonce += 1

    def to_dict(self):
        """
        Convert block to a dictionary for JSON storage.

        Returns:
            dict: All block fields as a dictionary.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_data": self.event_data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "block_hash": self.block_hash
        }

    @staticmethod
    def from_dict(data):
        """
        Reconstruct a Block object from a dictionary (loaded from JSON).

        Parameters:
            data (dict): Dictionary with all block fields.

        Returns:
            Block: Reconstructed block object.
        """
        block = Block(
            index=data['index'],
            event_type=data['event_type'],
            event_data=data['event_data'],
            previous_hash=data['previous_hash']
        )
        block.timestamp = data['timestamp']
        block.nonce = data['nonce']
        block.block_hash = data['block_hash']
        return block

    def display(self):
        """
        Print this block's details in a readable format.

        Returns:
            None
        """
        print_separator('-', 50)
        print(f"  Block #{self.index}")
        print(f"  Event     : {self.event_type}")
        print(f"  Data      : {json.dumps(self.event_data)}")
        print(f"  Timestamp : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))}")
        print(f"  Nonce     : {self.nonce}")
        print(f"  Prev Hash : {self.previous_hash[:20]}...")
        print(f"  Hash      : {self.block_hash[:20]}...")
        print_separator('-', 50)



#  BLOCKCHAIN


class Blockchain:
    """
    A simple blockchain used as a tamper-evident audit log.

    Attributes:
        chain      (list): List of Block objects.
        difficulty (int): Proof-of-Work difficulty (leading zeros).
        filepath   (str): Path to JSON file for persistence.
    """

    def __init__(self, difficulty=3, filepath='data/blockchain.json'):
        """
        Initialize the blockchain. Load from file if it exists,
        otherwise create the genesis block.

        Parameters:
            difficulty (int): PoW difficulty. Default 3.
            filepath   (str): JSON file path for persistence.
        """
        self.difficulty = difficulty
        self.filepath = filepath
        self.chain = []

        if os.path.exists(filepath):
            self.load()
            print(f"  [+] Loaded existing chain ({len(self.chain)} blocks) from {filepath}")
        else:
            self._create_genesis_block()
            print("  [+] New blockchain created with genesis block.")

    def _create_genesis_block(self):
        """
        Create the genesis block (block #0).
        Hard-coded with well-defined content — no previous hash.

        Returns:
            None
        """
        genesis = Block(
            index=0,
            event_type="GENESIS",
            event_data={"message": "SecureVault Blockchain Initialized"},
            previous_hash="0" * 64  # no previous block
        )
        genesis.mine(self.difficulty)
        self.chain.append(genesis)
        self.save()

    @property
    def last_block(self):
        """
        Get the most recent block in the chain.

        Returns:
            Block: The last block.
        """
        return self.chain[-1]

    def add_block(self, event_type, event_data):
        """
        Create, mine, and add a new block to the chain.
        Every cryptographic operation in SecureVault calls this.

        Parameters:
            event_type (str): Type of event (e.g. 'ENCRYPT', 'HASH').
            event_data (dict): Details about the operation.

        Returns:
            Block: The newly added block.

        Example:
            blockchain.add_block("HASH", {"algorithm": "sha256", "digest": "abc..."})
        """
        new_block = Block(
            index=len(self.chain),
            event_type=event_type,
            event_data=event_data,
            previous_hash=self.last_block.block_hash
        )

        print(f"  [*] Mining block #{new_block.index} (difficulty={self.difficulty})...", end=' ', flush=True)
        start = time.time()
        new_block.mine(self.difficulty)
        elapsed = time.time() - start
        print(f"done in {elapsed:.2f}s  (nonce={new_block.nonce})")

        self.chain.append(new_block)
        self.save()
        return new_block

    def validate_chain(self):
        """
        Validate the entire blockchain.
        Checks two things for every block:
          1. block_hash matches recomputed hash (data not altered)
          2. previous_hash matches actual hash of previous block (chain intact)

        Returns:
            bool: True if chain is valid, False if tampered.
        """
        print_separator()
        print("  CHAIN VALIDATION")
        print_separator()

        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check 1: recompute hash and compare
            recomputed = current.compute_hash()
            if current.block_hash != recomputed:
                print(f"  [!] TAMPER DETECTED at block #{i}")
                print(f"      Stored hash   : {current.block_hash[:30]}...")
                print(f"      Computed hash : {recomputed[:30]}...")
                print_separator()
                return False

            # Check 2: previous_hash linkage
            if current.previous_hash != previous.block_hash:
                print(f"  [!] CHAIN BROKEN at block #{i}")
                print(f"      previous_hash : {current.previous_hash[:30]}...")
                print(f"      actual prev   : {previous.block_hash[:30]}...")
                print_separator()
                return False

            print(f"  [+] Block #{i} OK")

        print_separator()
        print("  [+] Chain is VALID — no tampering detected.")
        print_separator()
        return True

    def get_history(self):
        """
        Print all blocks in the chain in a readable format.

        Returns:
            None
        """
        print_separator()
        print(f"  BLOCKCHAIN HISTORY — {len(self.chain)} blocks")
        print_separator()
        for block in self.chain:
            block.display()

    def tamper_block(self, index, new_data):
        """
        Deliberately tamper with a block's event_data.
        Used to DEMONSTRATE tamper detection — do not use in production.

        Parameters:
            index    (int): Index of the block to tamper with.
            new_data (dict): Replacement event_data.

        Returns:
            None
        """
        if index <= 0 or index >= len(self.chain):
            print(f"  [!] Cannot tamper genesis block or invalid index.")
            return

        print(f"  [!] Tampering with block #{index}...")
        self.chain[index].event_data = new_data
        # Note: we do NOT recompute the hash — that's what gets detected
        print(f"  [!] Block #{index} data changed. Chain is now corrupt.")

    def demo_pow_difficulty(self):
        """
        Show how mining time increases with difficulty.
        Tests difficulty 1 through 5 and measures time.

        Returns:
            None
        """
        print_separator()
        print("  PROOF-OF-WORK — Mining Time vs Difficulty")
        print_separator()
        print(f"  {'Difficulty':<12} {'Nonce':<12} {'Time (s)'}")
        print_separator('-', 40)

        for diff in range(1, 6):
            test_block = Block(
                index=999,
                event_type="TEST",
                event_data={"test": True},
                previous_hash="0" * 64
            )
            start = time.time()
            test_block.mine(diff)
            elapsed = time.time() - start
            print(f"  {diff:<12} {test_block.nonce:<12} {elapsed:.4f}s")

        print_separator()

    def save(self):
        """
        Save the entire blockchain to a JSON file.

        Returns:
            None
        """
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        data = {
            "difficulty": self.difficulty,
            "chain": [block.to_dict() for block in self.chain]
        }
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load(self):
        """
        Load blockchain from JSON file and reconstruct Block objects.

        Returns:
            None
        """
        with open(self.filepath, 'r') as f:
            data = json.load(f)

        self.difficulty = data['difficulty']
        self.chain = [Block.from_dict(b) for b in data['chain']]


#  GLOBAL INSTANCE (used by other modules)


# Other modules import this to log their events
_blockchain = None


def get_blockchain():
    """
    Get or create the global Blockchain instance.
    All modules use this to log events without creating multiple chains.

    Returns:
        Blockchain: The shared blockchain instance.
    """
    global _blockchain
    if _blockchain is None:
        _blockchain = Blockchain()
    return _blockchain


def log_event(event_type, event_data):
    """
    Log a cryptographic event to the blockchain.
    Called by other modules after each operation.

    Parameters:
        event_type (str): Event type e.g. 'ENCRYPT', 'HASH', 'KEY_EXCHANGE'.
        event_data (dict): Details of the operation.

    Returns:
        Block: The newly added block.

    Example:
        log_event("HASH", {"algorithm": "sha256", "input": "hello"})
    """
    bc = get_blockchain()
    return bc.add_block(event_type, event_data)



#  MODULE MENU


def module5_menu():
    """
    Display the Module 5 interactive menu.
    Called from main.py when the user selects Module 5.

    Returns:
        None
    """
    bc = get_blockchain()

    while True:
        print_separator()
        print("  MODULE 5 — Blockchain Audit Logger")
        print_separator()
        print(f"  Chain length: {len(bc.chain)} blocks")
        print_separator()
        print("  1. View Full Chain History")
        print("  2. Validate Chain")
        print("  3. Add a Manual Event")
        print("  4. Tamper with a Block (then validate)")
        print("  5. Proof-of-Work Difficulty Demo")
        print("  0. Back to Main Menu")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            bc.get_history()

        elif choice == '2':
            bc.validate_chain()

        elif choice == '3':
            etype = input("  Event type (e.g. ENCRYPT, HASH): ").strip().upper()
            edata = input("  Event data (e.g. key=abc, msg=hello): ").strip()
            bc.add_block(etype, {"info": edata})
            print("  [+] Block added and saved.")

        elif choice == '4':
            bc.get_history()
            try:
                idx = int(input("  Enter block index to tamper with: "))
                bc.tamper_block(idx, {"tampered": True, "info": "data was changed"})
                print()
                bc.validate_chain()
            except ValueError:
                print("  [!] Invalid index.")

        elif choice == '5':
            bc.demo_pow_difficulty()

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option. Try again.")