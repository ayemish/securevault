"""
tests/test_module5.py - Unit Tests for Module 5: Blockchain Audit Logger
=========================================================================
5 tests covering Block creation, mining, chain validation, tamper detection.
Run with: python -m unittest tests/test_module5.py
"""

import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from module5_blockchain import Block, Blockchain


class TestBlockCreation(unittest.TestCase):
    """Test 1 — Block creates correctly and computes hash."""

    def test_block_hash_is_string(self):
        b = Block(0, "TEST", {"msg": "hello"}, "0" * 64)
        b.mine(1)
        self.assertIsInstance(b.block_hash, str)
        self.assertEqual(len(b.block_hash), 64)

    def test_block_hash_starts_with_difficulty_zeros(self):
        b = Block(1, "TEST", {}, "0" * 64)
        b.mine(2)
        self.assertTrue(b.block_hash.startswith("00"))

    def test_compute_hash_deterministic(self):
        b = Block(0, "GENESIS", {"msg": "init"}, "0" * 64)
        b.nonce = 42
        h1 = b.compute_hash()
        h2 = b.compute_hash()
        self.assertEqual(h1, h2)

    def test_block_to_dict_has_all_fields(self):
        b = Block(0, "TEST", {"x": 1}, "0" * 64)
        b.mine(1)
        d = b.to_dict()
        for field in ['index', 'timestamp', 'event_type', 'event_data',
                      'previous_hash', 'nonce', 'block_hash']:
            self.assertIn(field, d)

    def test_block_from_dict_reconstructs(self):
        b = Block(1, "HASH", {"algo": "sha256"}, "abc" * 21 + "d")
        b.mine(1)
        d = b.to_dict()
        b2 = Block.from_dict(d)
        self.assertEqual(b.block_hash, b2.block_hash)
        self.assertEqual(b.nonce, b2.nonce)


class TestBlockchainCreation(unittest.TestCase):
    """Test 2 — Blockchain initializes with genesis block."""

    def setUp(self):
        # Use a temp path so tests don't touch real blockchain.json
        self.bc = Blockchain(difficulty=1, filepath='data/test_blockchain.json')

    def tearDown(self):
        if os.path.exists('data/test_blockchain.json'):
            os.remove('data/test_blockchain.json')

    def test_genesis_block_exists(self):
        self.assertEqual(len(self.bc.chain), 1)

    def test_genesis_block_index_zero(self):
        self.assertEqual(self.bc.chain[0].index, 0)

    def test_genesis_previous_hash_is_zeros(self):
        self.assertEqual(self.bc.chain[0].previous_hash, "0" * 64)

    def test_genesis_event_type(self):
        self.assertEqual(self.bc.chain[0].event_type, "GENESIS")

    def test_blockchain_saves_to_file(self):
        self.assertTrue(os.path.exists('data/test_blockchain.json'))


class TestAddBlock(unittest.TestCase):
    """Test 3 — Adding blocks to the chain."""

    def setUp(self):
        self.bc = Blockchain(difficulty=1, filepath='data/test_add.json')

    def tearDown(self):
        if os.path.exists('data/test_add.json'):
            os.remove('data/test_add.json')

    def test_add_block_increases_length(self):
        initial = len(self.bc.chain)
        self.bc.add_block("ENCRYPT", {"algo": "caesar"})
        self.assertEqual(len(self.bc.chain), initial + 1)

    def test_added_block_has_correct_index(self):
        self.bc.add_block("TEST", {})
        self.assertEqual(self.bc.chain[-1].index, 1)

    def test_added_block_links_to_previous(self):
        self.bc.add_block("TEST", {})
        self.assertEqual(
            self.bc.chain[1].previous_hash,
            self.bc.chain[0].block_hash
        )

    def test_added_block_hash_meets_difficulty(self):
        self.bc.add_block("HASH", {"algo": "sha256"})
        last = self.bc.chain[-1]
        self.assertTrue(last.block_hash.startswith("0" * self.bc.difficulty))

    def test_multiple_blocks_correct_chain(self):
        self.bc.add_block("STEP1", {})
        self.bc.add_block("STEP2", {})
        self.assertEqual(len(self.bc.chain), 3)
        self.assertEqual(self.bc.chain[2].previous_hash, self.bc.chain[1].block_hash)


class TestChainValidation(unittest.TestCase):
    """Test 4 — Chain validation detects valid and tampered chains."""

    def setUp(self):
        self.bc = Blockchain(difficulty=1, filepath='data/test_valid.json')
        self.bc.add_block("EVENT1", {"data": "abc"})
        self.bc.add_block("EVENT2", {"data": "def"})

    def tearDown(self):
        if os.path.exists('data/test_valid.json'):
            os.remove('data/test_valid.json')

    def test_valid_chain_passes(self):
        self.assertTrue(self.bc.validate_chain())

    def test_tampered_data_detected(self):
        # Change event_data without recomputing hash
        self.bc.chain[1].event_data = {"data": "TAMPERED"}
        self.assertFalse(self.bc.validate_chain())

    def test_tampered_hash_detected(self):
        # Directly change stored hash
        self.bc.chain[1].block_hash = "0" * 64
        self.assertFalse(self.bc.validate_chain())

    def test_broken_link_detected(self):
        # Break the previous_hash link
        self.bc.chain[2].previous_hash = "0" * 64
        self.assertFalse(self.bc.validate_chain())

    def test_single_block_chain_valid(self):
        bc2 = Blockchain(difficulty=1, filepath='data/test_single.json')
        self.assertTrue(bc2.validate_chain())
        if os.path.exists('data/test_single.json'):
            os.remove('data/test_single.json')


class TestProofOfWork(unittest.TestCase):
    """Test 5 — Proof-of-Work mining correctness."""

    def test_difficulty_1_hash_starts_with_one_zero(self):
        b = Block(0, "TEST", {}, "0" * 64)
        b.mine(1)
        self.assertTrue(b.block_hash.startswith("0"))

    def test_difficulty_2_hash_starts_with_two_zeros(self):
        b = Block(0, "TEST", {}, "0" * 64)
        b.mine(2)
        self.assertTrue(b.block_hash.startswith("00"))

    def test_nonce_is_positive_after_mining(self):
        b = Block(0, "TEST", {}, "0" * 64)
        b.mine(1)
        self.assertGreaterEqual(b.nonce, 0)

    def test_mined_hash_matches_compute_hash(self):
        b = Block(0, "TEST", {"x": 1}, "0" * 64)
        b.mine(1)
        self.assertEqual(b.block_hash, b.compute_hash())

    def test_changing_data_invalidates_hash(self):
        b = Block(0, "TEST", {"x": 1}, "0" * 64)
        b.mine(1)
        original_hash = b.block_hash
        b.event_data = {"x": 2}  # tamper
        # Now compute_hash() should differ from stored block_hash
        self.assertNotEqual(b.compute_hash(), original_hash)


if __name__ == '__main__':
    unittest.main(verbosity=2)