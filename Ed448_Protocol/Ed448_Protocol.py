import os
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class Participant:
    def __init__(self, name):
        self.name = name
        self.static_private_key = None
        self.static_public_key = None
        self.ephemeral_private_key = None
        self.ephemeral_public_key = None
        self.shared_secret = None
        self.master_session_key = None
        self.authentication_key = None

    def generate_static_keys(self):
        """Generates static Ed448 key pair."""
        self.static_private_key = ed448.Ed448PrivateKey.generate()
        self.static_public_key = self.static_private_key.public_key()
        print(f"{self.name}: Generated static Ed448 key pair.")

    def generate_ephemeral_keys(self):
        """Generates ephemeral X448 key pair for a session."""
        self.ephemeral_private_key = x448.X448PrivateKey.generate()
        self.ephemeral_public_key = self.ephemeral_private_key.public_key()
        print(f"{self.name}: Generated ephemeral X448 key pair.")
        return self.ephemeral_public_key

    def derive_shared_secret(self, peer_ephemeral_public_key):
        """Derives the shared secret using X448 Diffie-Hellman."""
        self.shared_secret = self.ephemeral_private_key.exchange(peer_ephemeral_public_key)
        print(f"{self.name}: Derived shared X448 secret.")

    def derive_session_keys(self, combined_salt):
        """Derives master session key and authentication key using HKDF-SHA512.
        Takes a pre-combined salt as input for consistent key derivation.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
            length=64, # 32 bytes for session key, 32 bytes for auth key
            salt=combined_salt, # Use the already combined salt
            info=b'EjafaProtocol Session Keys',
            backend=default_backend()
        )

        derived_key_material = hkdf.derive(self.shared_secret)
        self.master_session_key = derived_key_material[:32] # AES-256 key
        self.authentication_key = derived_key_material[32:] # HMAC-SHA256 key for authentication

        print(f"{self.name}: Derived master session key and authentication key.")
        # No return salt here, as salts are exchanged beforehand and passed directly.

    def encrypt_message(self, plaintext):
        """Encrypts a message using AES-256-GCM."""
        aesgcm = AESGCM(self.master_session_key)
        nonce = os.urandom(12) # 96-bit IV for AES-GCM
        if not isinstance(plaintext, bytes):
            plaintext = plaintext.encode('utf-8')
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        print(f"{self.name}: Encrypted message.")
        return nonce, ciphertext

    def decrypt_message(self, nonce, ciphertext):
        """Decrypts a message using AES-256-GCM."""
        aesgcm = AESGCM(self.master_session_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            print(f"{self.name}: Decrypted message.")
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"{self.name}: ERROR: Decryption failed: {e}")
            return None

def run_protocol_simulation():
    print("--- Ed448_Protocol Simulation Start ---")

    # 1. Setup Participants
    alice = Participant("Alice")
    bob = Participant("Bob")

    # 2. Static Key Generation
    alice.generate_static_keys()
    bob.generate_static_keys()

    # 3. Ephemeral Key Exchange
    alice_eph_pub = alice.generate_ephemeral_keys()
    bob_eph_pub = bob.generate_ephemeral_keys()

    alice.derive_shared_secret(bob_eph_pub)
    bob.derive_shared_secret(alice_eph_pub)

    # 4. Key Derivation (with salts)
    alice_salt = os.urandom(16)
    bob_salt = os.urandom(16)

    # In a real protocol, Alice would send alice_salt to Bob, and Bob would send bob_salt to Alice.
    # Then they would both combine them in a predefined order (e.g., Alice's salt + Bob's salt).
    # For this simulation, we ensure they have both salts and combine them consistently.
    combined_hkdf_salt = alice_salt + bob_salt

    alice.derive_session_keys(combined_hkdf_salt)
    bob.derive_session_keys(combined_hkdf_salt)

    # Verify salts are indeed used in the derivation for the other party, this is implicit in the derive_session_keys call
    # The actual salt sent would be the one generated by the peer

    # 5. Mutual Authentication and Session Key Confirmation (using Ed448 and HMAC)
    # To simplify, we'll use a basic transcript of exchanged public keys
    transcript = alice_eph_pub.public_bytes_raw() + bob_eph_pub.public_bytes_raw()

    # Alice's authentication message
    h_alice = hmac.HMAC(alice.authentication_key, hashes.SHA512(), backend=default_backend())
    alice_auth_nonce = os.urandom(16)
    h_alice.update(transcript + alice_auth_nonce)
    alice_mac = h_alice.finalize()
    alice_signature = alice.static_private_key.sign(alice_mac)
    print("Alice: Authenticated and signed her key confirmation.")

    # Bob verifies Alice and sends his confirmation
    bob_verified_alice = False
    h_bob_verify_alice = hmac.HMAC(bob.authentication_key, hashes.SHA512(), backend=default_backend())
    h_bob_verify_alice.update(transcript + alice_auth_nonce)
    bob_expected_mac_from_alice = h_bob_verify_alice.finalize()
    try:
        alice.static_public_key.verify(alice_signature, bob_expected_mac_from_alice)
        print("Bob: Successfully verified Alice's signature and confirmation.")
        bob_verified_alice = True
    except Exception as e:
        print(f"Bob: ERROR: Failed to verify Alice: {e}")

    if not bob_verified_alice:
        print("Protocol aborted due to failed authentication.")
        return

    # Bob's authentication message
    h_bob = hmac.HMAC(bob.authentication_key, hashes.SHA512(), backend=default_backend())
    bob_auth_nonce = os.urandom(16)
    h_bob.update(transcript + bob_auth_nonce)
    bob_mac = h_bob.finalize()
    bob_signature = bob.static_private_key.sign(bob_mac)
    print("Bob: Authenticated and signed his key confirmation.")

    # Alice verifies Bob
    alice_verified_bob = False
    h_alice_verify_bob = hmac.HMAC(alice.authentication_key, hashes.SHA512(), backend=default_backend())
    h_alice_verify_bob.update(transcript + bob_auth_nonce)
    alice_expected_mac_from_bob = h_alice_verify_bob.finalize()
    try:
        bob.static_public_key.verify(bob_signature, alice_expected_mac_from_bob)
        print("Alice: Successfully verified Bob's signature and confirmation.")
        alice_verified_bob = True
    except Exception as e:
        print(f"Alice: ERROR: Failed to verify Bob: {e}")
    
    if not alice_verified_bob:
        print("Protocol aborted due to failed authentication.")
        return

    print("\n--- Mutual Authentication Successful! ---\n")

    # 6. Secure Message Transmission
    message = "Hello Bob, this is a secret message from Alice!"
    nonce, ciphertext = alice.encrypt_message(message)

    decrypted_message = bob.decrypt_message(nonce, ciphertext)
    if decrypted_message:
        print(f"Bob received: {decrypted_message}")

    message_from_bob = "Hi Alice, I received your message securely!"
    nonce_bob, ciphertext_bob = bob.encrypt_message(message_from_bob)
    decrypted_message_alice = alice.decrypt_message(nonce_bob, ciphertext_bob)
    if decrypted_message_alice:
        print(f"Alice received: {decrypted_message_alice}")

    print("\n--- Ed448_Protocol Simulation End ---")

if __name__ == "__main__":
    run_protocol_simulation() 
