"""
bonus_merkle.py - Merkle Tree for SecureVault (+2 Bonus Marks)
==============================================================
Builds a Merkle Tree from blockchain block hashes.

Covers:
  - Full Merkle Tree construction from leaf hashes
  - Merkle Root computation
  - Merkle Proof generation (prove a block is in the tree)
  - Merkle Proof verification (without needing the full tree)

How it works:
  - Leaves = SHA-256 hashes of each block
  - Each parent = SHA-256(left_child + right_child)
  - Root = single hash at the top representing ALL blocks
  - If ANY block changes, the root changes — instant tamper detection

Rules:
  - Standard library only: hashlib
"""

import hashlib

from module5_blockchain import get_blockchain
from utils import print_separator


# ─────────────────────────────────────────────
#  HASH HELPER
# ─────────────────────────────────────────────

def sha256_pair(left, right):
    """
    Hash two hex strings together: SHA256(left + right).
    This is how parent nodes are computed in the Merkle Tree.

    Parameters:
        left  (str): Left child hash (hex string).
        right (str): Right child hash (hex string).

    Returns:
        str: SHA-256 hex digest of their concatenation.

    Example:
        sha256_pair("aaa...", "bbb...") -> "ccc..."
    """
    combined = left + right
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


# ─────────────────────────────────────────────
#  MERKLE TREE
# ─────────────────────────────────────────────

class MerkleTree:
    """
    A Merkle Tree built from a list of data items (block hashes).

    Attributes:
        leaves (list): SHA-256 hashes of each input item.
        tree   (list): All levels of the tree, bottom to top.
                       tree[0] = leaves, tree[-1] = [root]
        root   (str):  The Merkle root hash.
    """

    def __init__(self, data_items):
        """
        Build the Merkle Tree from a list of strings or hashes.

        Parameters:
            data_items (list): List of strings to build tree from.
                               Each item is SHA-256 hashed to form a leaf.

        Raises:
            ValueError: If data_items is empty.

        Example:
            tree = MerkleTree(["block0hash", "block1hash", "block2hash"])
        """
        if not data_items:
            raise ValueError("Cannot build Merkle Tree from empty list.")

        # Hash each item to form the leaves
        self.leaves = [
            hashlib.sha256(item.encode('utf-8')).hexdigest()
            for item in data_items
        ]

        self.tree = []
        self.root = self._build()

    def _build(self):
        """
        Build the full Merkle Tree level by level.

        Process:
          - Start with leaf hashes.
          - Pair up adjacent hashes and hash them together.
          - If odd number, duplicate the last hash.
          - Repeat until only one hash remains (the root).

        Returns:
            str: The Merkle root hash.
        """
        current_level = self.leaves[:]
        self.tree.append(current_level[:])

        while len(current_level) > 1:
            next_level = []

            # If odd number of nodes, duplicate the last one
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

            # Hash pairs together
            for i in range(0, len(current_level), 2):
                parent = sha256_pair(current_level[i], current_level[i + 1])
                next_level.append(parent)

            self.tree.append(next_level[:])
            current_level = next_level

        return current_level[0]

    def get_proof(self, index):
        """
        Generate a Merkle Proof for the leaf at the given index.
        The proof is a list of sibling hashes needed to recompute the root.

        Parameters:
            index (int): Index of the leaf to prove (0-based).

        Returns:
            list: List of (sibling_hash, position) tuples.
                  position = 'left' or 'right' (where sibling sits).

        Raises:
            IndexError: If index is out of range.

        Example:
            proof = tree.get_proof(2)
            # proof = [("abc...", "right"), ("def...", "left"), ...]
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Index {index} out of range (0 to {len(self.leaves)-1}).")

        proof = []
        current_index = index

        for level in self.tree[:-1]:  # skip root level
            # Handle odd level by duplicating last
            level_copy = level[:]
            if len(level_copy) % 2 == 1:
                level_copy.append(level_copy[-1])

            # Find sibling
            if current_index % 2 == 0:
                # current is left child, sibling is to the right
                sibling_index = current_index + 1
                proof.append((level_copy[sibling_index], 'right'))
            else:
                # current is right child, sibling is to the left
                sibling_index = current_index - 1
                proof.append((level_copy[sibling_index], 'left'))

            # Move up to parent index
            current_index = current_index // 2

        return proof

    def verify_proof(self, leaf_data, index, proof):
        """
        Verify a Merkle Proof without needing the full tree.
        Recomputes the root from the leaf + proof and compares to stored root.

        Parameters:
            leaf_data (str): The original data item (will be hashed).
            index     (int): The leaf's position in the tree.
            proof     (list): The proof returned by get_proof().

        Returns:
            bool: True if proof is valid (leaf is in the tree), False otherwise.

        Example:
            tree.verify_proof("block0hash", 0, proof) -> True
        """
        # Hash the leaf
        current_hash = hashlib.sha256(leaf_data.encode('utf-8')).hexdigest()

        for sibling_hash, position in proof:
            if position == 'right':
                # current is left, sibling is right
                current_hash = sha256_pair(current_hash, sibling_hash)
            else:
                # current is right, sibling is left
                current_hash = sha256_pair(sibling_hash, current_hash)

        return current_hash == self.root

    def display(self):
        """
        Print the full Merkle Tree level by level, bottom to top.

        Returns:
            None
        """
        print_separator()
        print("  MERKLE TREE")
        print_separator()

        level_names = ['Leaves (Block Hashes)'] + \
                      [f'Level {i}' for i in range(1, len(self.tree) - 1)] + \
                      ['Root']

        for i, level in enumerate(self.tree):
            name = level_names[i] if i < len(level_names) else f'Level {i}'
            print(f"\n  [{name}]")
            for j, h in enumerate(level):
                print(f"    [{j}] {h[:20]}...")

        print_separator()
        print(f"  Merkle Root: {self.root}")
        print_separator()


# ─────────────────────────────────────────────
#  BUILD FROM BLOCKCHAIN
# ─────────────────────────────────────────────

def build_from_blockchain():
    """
    Build a Merkle Tree from the current SecureVault blockchain.
    Uses each block's block_hash as a leaf.

    Returns:
        MerkleTree: Tree built from blockchain block hashes.

    Raises:
        ValueError: If blockchain has no blocks.
    """
    bc = get_blockchain()

    if not bc.chain:
        raise ValueError("Blockchain is empty.")

    block_hashes = [block.block_hash for block in bc.chain]

    print_separator()
    print(f"  Building Merkle Tree from {len(block_hashes)} blockchain blocks...")
    tree = MerkleTree(block_hashes)
    print(f"  Merkle Root: {tree.root}")
    print_separator()

    return tree


def demo_merkle_proof(tree, index):
    """
    Generate and verify a Merkle Proof for a given block index.

    Parameters:
        tree  (MerkleTree): The Merkle Tree.
        index (int): Block index to prove.

    Returns:
        None
    """
    bc = get_blockchain()
    block_hash = bc.chain[index].block_hash

    print_separator()
    print(f"  MERKLE PROOF for Block #{index}")
    print_separator()
    print(f"  Leaf data (block hash): {block_hash[:30]}...")

    proof = tree.get_proof(index)

    print(f"\n  Proof steps ({len(proof)} hashes):")
    for i, (sibling, position) in enumerate(proof):
        print(f"    Step {i+1}: {position.upper()} sibling = {sibling[:20]}...")

    valid = tree.verify_proof(block_hash, index, proof)
    print(f"\n  Proof valid: {valid}")
    print(f"  [{'+'if valid else '!'}] Block #{index} is {'confirmed in' if valid else 'NOT in'} the tree.")
    print_separator()


# ─────────────────────────────────────────────
#  MENU
# ─────────────────────────────────────────────

def merkle_menu():
    """
    Merkle Tree bonus module menu.

    Returns:
        None
    """
    tree = None

    while True:
        print_separator()
        print("  BONUS — Merkle Tree")
        print_separator()
        print("  1. Build Merkle Tree from Blockchain")
        print("  2. Display Full Tree")
        print("  3. Generate & Verify Proof for a Block")
        print("  0. Back")
        print_separator()

        choice = input("  Select option: ").strip()

        if choice == '1':
            try:
                tree = build_from_blockchain()
                print("  [+] Tree built successfully.")
            except ValueError as e:
                print(f"  [!] {e}")

        elif choice == '2':
            if tree is None:
                print("  [!] Build the tree first (option 1).")
            else:
                tree.display()

        elif choice == '3':
            if tree is None:
                print("  [!] Build the tree first (option 1).")
            else:
                bc = get_blockchain()
                print(f"  Blockchain has {len(bc.chain)} blocks (index 0 to {len(bc.chain)-1})")
                try:
                    idx = int(input("  Enter block index: ").strip())
                    demo_merkle_proof(tree, idx)
                except (ValueError, IndexError) as e:
                    print(f"  [!] {e}")

        elif choice == '0':
            break
        else:
            print("  [!] Invalid option.")