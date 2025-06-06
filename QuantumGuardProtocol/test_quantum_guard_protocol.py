import unittest
import os
import hmac
import hashlib
import sys # Added import for sys
import unittest.mock # Added for patching
import subprocess # Added for running main via subprocess

# Import the protocol to be tested
from quantum_guard_protocol import QuantumGuardProtocol, secure_zero, PROTOCOL_NAME, SESSION_KEY_SIZE, run_protocol_demonstration, hkdf_expand

from nacl.public import PublicKey
from nacl.signing import SigningKey
from nacl.secret import SecretBox
from nacl.exceptions import BadSignatureError

# Removed rich imports
# from rich.console import Console
# from rich.traceback import Traceback

# Removed console instance
# console = Console()

class TestQuantumGuardProtocol(unittest.TestCase):

    def setUp(self):
        # console.print(f"[bold blue]\n--- Running Test: {self._testMethodName} ---[/bold blue]") # Removed rich print
        # Generate long-term keys for Alice and Bob for each test
        self.alice_signing_key = SigningKey.generate()
        self.alice_verify_key = self.alice_signing_key.verify_key

        self.bob_signing_key = SigningKey.generate()
        self.bob_verify_key = self.bob_signing_key.verify_key

        self.alice_protocol = QuantumGuardProtocol("Alice", self.alice_signing_key, self.alice_verify_key)
        self.bob_protocol = QuantumGuardProtocol("Bob", self.bob_signing_key, self.bob_verify_key)

    def tearDown(self):
        # Reverted to original tearDown logic, no rich prints
        pass # Original tearDown had no custom logic

    def test_protocol_initialization(self):
        self.assertIsInstance(self.alice_protocol, QuantumGuardProtocol)
        self.assertIsInstance(self.bob_protocol, QuantumGuardProtocol)
        self.assertEqual(self.alice_protocol.name, "Alice")
        self.assertEqual(self.bob_protocol.name, "Bob")
        self.assertEqual(self.alice_protocol.long_term_signing_key, self.alice_signing_key)
        self.assertEqual(self.alice_protocol.long_term_verify_key, self.alice_verify_key)
        self.assertIsNone(self.alice_protocol.ephemeral_private_key)
        self.assertIsNone(self.alice_protocol.ephemeral_public_key)
        self.assertIsNone(self.alice_protocol.session_key)

    def test_ephemeral_key_generation(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        self.assertIsInstance(alice_eph_pub, bytes)
        self.assertEqual(len(alice_eph_pub), PublicKey.SIZE)
        self.assertIsInstance(bob_eph_pub, bytes)
        self.assertEqual(len(bob_eph_pub), PublicKey.SIZE)
        
        self.assertIsNotNone(self.alice_protocol.ephemeral_private_key)
        self.assertIsNotNone(self.alice_protocol.ephemeral_public_key)
        self.assertEqual(self.alice_protocol.ephemeral_public_key.encode(), alice_eph_pub)

    def test_signature_and_verification_success(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        alice_signature = self.alice_protocol.sign_ephemeral_public_key(alice_eph_pub)

        self.assertTrue(self.bob_protocol.verify_signature(alice_eph_pub, alice_signature, self.alice_verify_key))

    def test_signature_and_verification_failure_bad_signature(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        alice_signature = self.alice_protocol.sign_ephemeral_public_key(alice_eph_pub)
        
        # Tamper with the signature
        tampered_signature = bytearray(alice_signature)
        tampered_signature[0] ^= 0x01 # Flip a bit
        tampered_signature = bytes(tampered_signature)

        self.assertIs(self.bob_protocol.verify_signature(alice_eph_pub, tampered_signature, self.alice_verify_key), False)

    def test_signature_and_verification_failure_tampered_message(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        alice_signature = self.alice_protocol.sign_ephemeral_public_key(alice_eph_pub)
        
        # Tamper with the signed message (ephemeral public key)
        tampered_eph_pub = bytearray(alice_eph_pub)
        tampered_eph_pub[0] ^= 0x01 # Flip a bit
        tampered_eph_pub = bytes(tampered_eph_pub)

        self.assertFalse(self.bob_protocol.verify_signature(tampered_eph_pub, alice_signature, self.alice_verify_key))

    def test_key_exchange_matching_secrets(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)
        
        self.assertTrue(hmac.compare_digest(alice_shared_secret, bob_shared_secret))

    def test_key_derivation_matching_keys(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)

        alice_session_key = self.alice_protocol.derive_key(alice_shared_secret, alice_eph_pub, bob_eph_pub)
        bob_session_key = self.bob_protocol.derive_key(bob_shared_secret, bob_eph_pub, alice_eph_pub)

        self.assertTrue(hmac.compare_digest(alice_session_key, bob_session_key))
        self.assertEqual(len(alice_session_key), SESSION_KEY_SIZE)

    def test_key_derivation_salt_mismatch(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)

        # Alice derives her key using a deliberately incorrect peer_public_key for salt derivation
        # This simulates a mutation where the salt derivation is faulty for one party
        malicious_peer_eph_pub = os.urandom(PublicKey.SIZE) # A completely different key

        alice_session_key = self.alice_protocol.derive_key(alice_shared_secret, alice_eph_pub, malicious_peer_eph_pub)
        bob_session_key = self.bob_protocol.derive_key(bob_shared_secret, bob_eph_pub, alice_eph_pub)

        # The session keys should NOT match due to the salt mismatch
        self.assertFalse(hmac.compare_digest(alice_session_key, bob_session_key))

    def test_key_derivation_info_string_impact(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)

        # Derive a session key with the correct PROTOCOL_NAME
        original_alice_session_key = self.alice_protocol.derive_key(alice_shared_secret, alice_eph_pub, bob_eph_pub)

        # Temporarily modify PROTOCOL_NAME or its effective value for testing
        # NOTE: In a real test, you'd mock/patch the PROTOCOL_NAME directly in the module
        # Here, we simulate by directly calling the internal HKDF-expand logic with a modified info string

        # Re-derive PRK for the simulated scenario (as it depends on shared_secret which is zeroed after use)
        sorted_eph_keys = sorted([alice_eph_pub, bob_eph_pub])
        hkdf_salt = hashlib.sha256(sorted_eph_keys[0] + sorted_eph_keys[1]).digest()
        prk = hmac.new(hkdf_salt, alice_shared_secret, hashlib.sha256).digest()

        # Simulate a mutation: PROTOCOL_NAME is empty or ignored
        mutated_info_encrypt = b"encryption key" + b'' # Simulating PROTOCOL_NAME being empty
        
        # Directly use the internal hkdf_expand function to derive a key with mutated info
        # We need a way to access the internal hkdf_expand function or simulate its behavior.
        # Given the current structure, let's derive it manually for this test for clarity.

        # Manual HKDF-Expand to simulate the `derive_key` function's internal logic
        def simulated_hkdf_expand(prk_val: bytes, info_val: bytes, length: int) -> bytes:
            okm = b''
            t = b''
            counter = 0x01
            while len(okm) < length:
                t = hmac.new(prk_val, t + info_val + bytes([counter]), hashlib.sha256).digest()
                okm += t
                counter += 1
            return okm[:length]

        mutated_alice_session_key = simulated_hkdf_expand(prk, mutated_info_encrypt, SESSION_KEY_SIZE)

        # The session keys should NOT match if PROTOCOL_NAME had an impact
        self.assertFalse(hmac.compare_digest(original_alice_session_key, mutated_alice_session_key))

    def test_hkdf_expand_length_handling(self):
        prk = os.urandom(32) # A dummy PRK
        info = b"test info"

        # Test with a length that is a multiple of SHA256 digest size (32 bytes)
        key1 = hkdf_expand(prk, info, 32)
        self.assertEqual(len(key1), 32)

        # Test with a length that is not a multiple of SHA256 digest size
        key2 = hkdf_expand(prk, info, 20)
        self.assertEqual(len(key2), 20)

        # Test with a length that is larger than SHA256 digest size but requires multiple iterations
        key3 = hkdf_expand(prk, info, 60) # Requires 2 iterations (32 + 28)
        self.assertEqual(len(key3), 60)

        # Ensure that different info strings produce different keys
        key4 = hkdf_expand(prk, b"other info", 32)
        self.assertFalse(hmac.compare_digest(key1, key4))

    def test_encryption_decryption_success(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)

        self.alice_protocol.derive_key(alice_shared_secret, alice_eph_pub, bob_eph_pub)
        self.bob_protocol.derive_key(bob_shared_secret, bob_eph_pub, alice_eph_pub)

        plaintext = b"A very secret test message."
        encrypted_message = self.alice_protocol.encrypt(plaintext)
        decrypted_text = self.bob_protocol.decrypt(encrypted_message)

        self.assertIsNotNone(decrypted_text)
        self.assertEqual(decrypted_text, plaintext)

    def test_decryption_failure_tampered_ciphertext(self):
        alice_eph_pub = self.alice_protocol.generate_ephemeral_keys()
        bob_eph_pub = self.bob_protocol.generate_ephemeral_keys()

        alice_shared_secret = self.alice_protocol.perform_key_exchange(bob_eph_pub)
        bob_shared_secret = self.bob_protocol.perform_key_exchange(alice_eph_pub)

        self.alice_protocol.derive_key(alice_shared_secret, alice_eph_pub, bob_eph_pub)
        self.bob_protocol.derive_key(bob_shared_secret, bob_eph_pub, alice_eph_pub)

        plaintext = b"A very secret test message."
        encrypted_message = self.alice_protocol.encrypt(plaintext)

        # Tamper with the encrypted message
        tampered_encrypted_message = bytearray(encrypted_message)
        tampered_encrypted_message[len(tampered_encrypted_message) // 2] ^= 0x01 # Flip a bit in the middle
        tampered_encrypted_message = bytes(tampered_encrypted_message)

        decrypted_text = self.bob_protocol.decrypt(tampered_encrypted_message)
        self.assertIsNone(decrypted_text) # Decryption should fail and return None

    def test_encrypt_before_key_derivation_raises_error(self):
        plaintext = b"Some message"
        with self.assertRaises(ValueError):
            self.alice_protocol.encrypt(plaintext)

    def test_decrypt_before_key_derivation_raises_error(self):
        # Needs a dummy encrypted message as input, but should fail due to missing session key
        dummy_encrypted_message = b'\x00' * (SecretBox.NONCE_SIZE + 16 + 16) # Arbitrary size
        with self.assertRaises(ValueError):
            self.bob_protocol.decrypt(dummy_encrypted_message)

    def test_secure_zero_function(self):
        data = os.urandom(32)
        original_id = id(data)
        zeroed_data = secure_zero(data)

        # Assert that the content is zeroed
        self.assertEqual(zeroed_data, b'\x00' * 32)
        
        # In CPython, secure_zero returns a new bytes object because bytes are immutable.
        # The original `data` object might still hold its value until garbage collected.
        # This test primarily verifies the function returns a zeroed byte string.
        self.assertNotEqual(id(data), id(zeroed_data))

    # New tests for run_protocol_demonstration error paths
    @unittest.mock.patch('quantum_guard_protocol.QuantumGuardProtocol.verify_signature', side_effect=[False])
    @unittest.mock.patch('quantum_guard_protocol.SigningKey.generate')
    def test_run_protocol_demonstration_alice_signature_failure_for_bob(self, mock_signing_key_generate, mock_verify_signature):
        # Mock SigningKey.generate to provide dummy keys for run_protocol_demonstration\'s internal setup
        # This is necessary because run_protocol_demonstration generates its own SigningKey instances.
        mock_signing_key_generate.side_effect = [
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Alice\'s long-term key
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Bob\'s long-term key
        ]
        
        # The first call to verify_signature (bob.verify_signature) will return False as per side_effect=[False]
        with self.assertRaisesRegex(ValueError, "Protocol aborted: Alice\'s signature verification failed for Bob."):
            run_protocol_demonstration()

    @unittest.mock.patch('quantum_guard_protocol.QuantumGuardProtocol.verify_signature', side_effect=[True, False])
    @unittest.mock.patch('quantum_guard_protocol.SigningKey.generate')
    def test_run_protocol_demonstration_bob_signature_failure_for_alice(self, mock_signing_key_generate, mock_verify_signature):
        # Mock SigningKey.generate to provide dummy keys
        mock_signing_key_generate.side_effect = [
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Alice\'s long-term key
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Bob\'s long-term key
        ]

        # The first call to verify_signature (bob.verify_signature) will return True
        # The second call to verify_signature (alice.verify_signature) will return False
        with self.assertRaisesRegex(ValueError, "Protocol aborted: Bob\'s signature verification failed for Alice."):
            run_protocol_demonstration()

    @unittest.mock.patch('quantum_guard_protocol.hmac.compare_digest', side_effect=[False])
    @unittest.mock.patch('quantum_guard_protocol.SigningKey.generate')
    def test_run_protocol_demonstration_shared_secret_mismatch(self, mock_signing_key_generate, mock_compare_digest):
        # Mock SigningKey.generate to provide dummy keys
        mock_signing_key_generate.side_effect = [
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Alice\'s long-term key
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Bob\'s long-term key
        ]

        # The first call to hmac.compare_digest (for shared secrets) will return False
        with self.assertRaisesRegex(ValueError, "ERROR: Shared secrets do not match!"):
            run_protocol_demonstration()

    @unittest.mock.patch('quantum_guard_protocol.hmac.compare_digest', side_effect=[True, False])
    @unittest.mock.patch('quantum_guard_protocol.SigningKey.generate')
    def test_run_protocol_demonstration_session_key_mismatch(self, mock_signing_key_generate, mock_compare_digest):
        # Mock SigningKey.generate to provide dummy keys
        mock_signing_key_generate.side_effect = [
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Alice\'s long-term key
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Bob\'s long-term key
        ]

        # The first call to hmac.compare_digest (for shared secrets) will return True
        # The second call to hmac.compare_digest (for session keys) will return False
        with self.assertRaisesRegex(ValueError, "ERROR: Derived session keys do not match!"):
            run_protocol_demonstration()

    @unittest.mock.patch('quantum_guard_protocol.QuantumGuardProtocol.decrypt', return_value=None)
    @unittest.mock.patch('quantum_guard_protocol.SigningKey.generate')
    def test_run_protocol_demonstration_decryption_failure(self, mock_signing_key_generate, mock_decrypt):
        mock_signing_key_generate.side_effect = [
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Alice's long-term key
            unittest.mock.Mock(verify_key=unittest.mock.Mock(encode=unittest.mock.Mock(hex=lambda: "dummy_hex_key"))), # Bob's long-term key
        ]
        with self.assertRaisesRegex(ValueError, "Bob: Decryption failed!"):
            run_protocol_demonstration()

if __name__ == '__main__':
    # Use a custom test runner to capture and format output with rich
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=0)) 
