import os
import hashlib
import hmac
from typing import Tuple, Optional

# Required libraries:
# pip install pynacl

import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox

PROTOCOL_NAME = "QuantumGuardProtocol"
HKDF_SALT_SIZE = 32
SESSION_KEY_SIZE = 32 # For SecretBox

class QuantumGuardProtocol:
    def __init__(self, name: str, long_term_signing_key: SigningKey, long_term_verify_key: VerifyKey):
        self.name = name
        self.long_term_signing_key = long_term_signing_key
        self.long_term_verify_key = long_term_verify_key
        print(f"{self.name}: Initialized with long-term keys.")
        self.ephemeral_private_key: Optional[PrivateKey] = None
        self.ephemeral_public_key: Optional[PublicKey] = None
        self.session_key: Optional[bytes] = None

    def generate_ephemeral_keys(self):
        """Generates ephemeral X25519 key pair."""
        self.ephemeral_private_key = PrivateKey.generate()
        self.ephemeral_public_key = self.ephemeral_private_key.public_key
        print(f"{self.name}: Generated ephemeral X25519 key pair.")
        return self.ephemeral_public_key.encode()

    def sign_ephemeral_public_key(self, ephemeral_public_key_bytes: bytes) -> bytes:
        """Signs the ephemeral public key with the long-term signing key."""
        signed = self.long_term_signing_key.sign(ephemeral_public_key_bytes)
        print(f"{self.name}: Signed ephemeral public key.")
        return signed.signature

    def verify_signature(self, peer_ephemeral_public_key_bytes: bytes, peer_signature: bytes, peer_long_term_verify_key: VerifyKey) -> bool:
        """Verifies the peer's signature on their ephemeral public key."""
        try:
            peer_long_term_verify_key.verify(peer_ephemeral_public_key_bytes, peer_signature)
            print(f"{self.name}: Verified peer's ephemeral public key signature.")
            return True
        except nacl.signing.BadSignatureError:
            print(f"{self.name}: ERROR: Peer's ephemeral public key signature verification failed!")
            return False

    def perform_key_exchange(self, peer_ephemeral_public_key_bytes: bytes) -> bytes:
        """Performs X25519 key exchange with the peer's ephemeral public key."""
        peer_ephemeral_public_key = PublicKey(peer_ephemeral_public_key_bytes)
        shared_secret = Box(self.ephemeral_private_key, peer_ephemeral_public_key).shared_key()
        print(f"{self.name}: Performed X25519 key exchange.")
        return shared_secret

    def derive_key(self, shared_secret: bytes, my_ephemeral_public_key_bytes: bytes, peer_ephemeral_public_key_bytes: bytes) -> bytes:
        """Derives a session key using HKDF-SHA256."""
        # Use a consistent salt for HKDF, derived from both ephemeral public keys
        # Sorted to ensure consistent ordering for both parties
        sorted_eph_keys = sorted([my_ephemeral_public_key_bytes, peer_ephemeral_public_key_bytes])
        hkdf_salt = hashlib.sha256(sorted_eph_keys[0] + sorted_eph_keys[1]).digest()

        # HKDF-Expand with different info strings for key separation
        info_encrypt = b"encryption key" + PROTOCOL_NAME.encode()
        
        # HKDF-Expand (RFC 5869)
        # HKDF-Extract is effectively HMAC-SHA256(salt, IKM)
        prk = hmac.new(hkdf_salt, shared_secret, hashlib.sha256).digest()

        # HKDF-Expand(PRK, info, L) -> OKM
        def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
            okm = b''
            t = b''
            counter = 0x01
            while len(okm) < length:
                t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
                okm += t
                counter += 1
            return okm[:length]
        
        self.session_key = hkdf_expand(prk, info_encrypt, SESSION_KEY_SIZE)
        print(f"{self.name}: Derived session key using HKDF-SHA256.")
        return self.session_key

    def encrypt(self, plaintext: bytes):
        """Encrypts plaintext using XChaCha20-Poly1305 with the session key."""
        if not self.session_key:
            raise ValueError("Session key not derived. Perform key exchange first.")
        
        box = SecretBox(self.session_key)
        # The encrypt method returns an EncryptedMessage object which is bytes (nonce || ciphertext || mac)
        encrypted_message = box.encrypt(plaintext)
        print(f"{self.name}: Encrypted message.")
        return encrypted_message

    def decrypt(self, encrypted_message: bytes) -> Optional[bytes]:
        """Decrypts ciphertext using XChaCha20-Poly1305 with the session key."""
        if not self.session_key:
            raise ValueError("Session key not derived. Perform key exchange first.")
        
        box = SecretBox(self.session_key)
        try:
            # The decrypt method expects the combined EncryptedMessage (nonce || ciphertext || mac)
            plaintext = box.decrypt(encrypted_message)
            print(f"{self.name}: Decrypted message successfully.")
            return plaintext
        except nacl.exceptions.BadSignatureError:
            print(f"{self.name}: ERROR: Decryption failed (bad MAC or corrupted ciphertext).")
            return None
        except Exception as e:
            print(f"{self.name}: ERROR: Decryption failed: {e}")
            return None


def main():
    print("--- QuantumGuardProtocol Demonstration ---")

    # 1. Generate long-term Ed25519 keys for Alice and Bob
    alice_long_term_signing_key = SigningKey.generate()
    alice_long_term_verify_key = alice_long_term_signing_key.verify_key

    bob_long_term_signing_key = SigningKey.generate()
    bob_long_term_verify_key = bob_long_term_signing_key.verify_key

    print(f"Alice's Long-Term Verify Key (Hex): {alice_long_term_verify_key.encode().hex()}")
    print(f"Bob's Long-Term Verify Key (Hex): {bob_long_term_verify_key.encode().hex()}")
    print("\n")

    # 2. Initialize protocol instances
    alice = QuantumGuardProtocol("Alice", alice_long_term_signing_key, alice_long_term_verify_key)
    bob = QuantumGuardProtocol("Bob", bob_long_term_signing_key, bob_long_term_verify_key)
    print("\n")

    # 3. Alice initiates key exchange
    alice_ephemeral_pub_bytes = alice.generate_ephemeral_keys()
    alice_signature = alice.sign_ephemeral_public_key(alice_ephemeral_pub_bytes)
    print("\n")

    # 4. Bob receives Alice's ephemeral key and signature, verifies, and responds
    if not bob.verify_signature(alice_ephemeral_pub_bytes, alice_signature, alice_long_term_verify_key):
        print("Protocol aborted: Alice's signature verification failed for Bob.")
        return

    bob_ephemeral_pub_bytes = bob.generate_ephemeral_keys()
    bob_signature = bob.sign_ephemeral_public_key(bob_ephemeral_pub_bytes)
    print("\n")

    # 5. Alice receives Bob's ephemeral key and signature, verifies
    if not alice.verify_signature(bob_ephemeral_pub_bytes, bob_signature, bob_long_term_verify_key):
        print("Protocol aborted: Bob's signature verification failed for Alice.")
        return
    print("\n")

    # 6. Both parties derive shared secrets
    alice_shared_secret = alice.perform_key_exchange(bob_ephemeral_pub_bytes)
    bob_shared_secret = bob.perform_key_exchange(alice_ephemeral_pub_bytes)

    if alice_shared_secret != bob_shared_secret:
        print("ERROR: Shared secrets do not match!")
        return
    print("Shared secrets match. \n")

    # 7. Both parties derive session keys using HKDF
    alice_session_key = alice.derive_key(alice_shared_secret, alice_ephemeral_pub_bytes, bob_ephemeral_pub_bytes)
    bob_session_key = bob.derive_key(bob_shared_secret, bob_ephemeral_pub_bytes, alice_ephemeral_pub_bytes)

    if alice_session_key != bob_session_key:
        print("ERROR: Derived session keys do not match!")
        return
    print("Derived session keys match. \n")

    # 8. Alice encrypts a message
    plaintext = b"This is a super secret message for Bob!"
    encrypted_message = alice.encrypt(plaintext)
    print(f"Alice: Plaintext: {plaintext.decode()}")
    print(f"Alice: Encrypted Message (Hex): {encrypted_message.hex()}")
    print("\n")

    # 9. Bob decrypts the message
    decrypted_text = bob.decrypt(encrypted_message)
    if decrypted_text is None:
        print("Bob: Decryption failed!")
        return

    print(f"Bob: Decrypted text: {decrypted_text.decode()}")
    print("\n--- All QuantumGuardProtocol tests passed ---")

if __name__ == "__main__":
    main() 
