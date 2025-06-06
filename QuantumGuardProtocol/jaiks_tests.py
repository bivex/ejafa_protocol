import unittest
import os
import hmac

# Import the protocol to be tested
from jaiks_protocol import QuantumGuardProtocol, secure_zero, SESSION_KEY_SIZE

from nacl.public import PublicKey
from nacl.signing import SigningKey
from nacl.secret import SecretBox

class TestQuantumGuardProtocol(unittest.TestCase):

    def setUp(self):
        # Generate long-term keys for Alice and Bob for each test
        self.alice_signing_key = SigningKey.generate()
        self.alice_verify_key = self.alice_signing_key.verify_key

        self.bob_signing_key = SigningKey.generate()
        self.bob_verify_key = self.bob_signing_key.verify_key

        self.alice_protocol = QuantumGuardProtocol("Alice", self.alice_signing_key, self.alice_verify_key)
        self.bob_protocol = QuantumGuardProtocol("Bob", self.bob_signing_key, self.bob_verify_key)

    def test_protocol_initialization(self):
        self.assertIsInstance(self.alice_protocol, QuantumGuardProtocol)
        self.assertIsInstance(self.bob_protocol, QuantumGuardProtocol)
        self.assertEqual(self.alice_protocol.name, "Alice")
        self.assertEqual(self.bob_protocol.name, "Bob")
        self.assertEqual(self.alice_protocol.long_term_signing_key, self.alice_signing_key)
        self.assertEqual(self.alice_protocol.long_term_verify_key, self.alice_verify_key)

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

        self.assertFalse(self.bob_protocol.verify_signature(alice_eph_pub, tampered_signature, self.alice_verify_key))

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

if __name__ == '__main__':
    unittest.main() 
