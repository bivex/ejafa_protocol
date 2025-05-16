#!/usr/bin/env python3

import os
import struct
import base64
import hashlib
from typing import Tuple, Optional

# Required libraries:
# pip install pynacl cryptography

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt

PRIVATE_KEY_SIZE = 32
PUBLIC_KEY_SIZE = 32
SHARED_SECRET_SIZE = 32
SESSION_KEY_SIZE = 32
NONCE_SIZE = 24  # XChaCha20-Poly1305 uses 24-byte nonces
ROUNDS = 20
PROTOCOL_NAME = "EjafaProtocol"

class EjafaProtocol:
    def __init__(self, name: str, private_key: bytes, public_key: bytes):
        self.name = name
        self.private_key = private_key
        self.public_key = public_key
        print(f"{self.name}: Constructor - Keys set")
        self.log_keys()

    def perform_key_exchange(self, peer_public_key: bytes) -> bytes:
        """Perform X25519 key exchange with peer's public key"""
        # Convert raw private key to X25519PrivateKey object
        private_key_obj = X25519PrivateKey.from_private_bytes(self.private_key)
        
        # Convert raw peer public key to X25519PublicKey object
        peer_key_obj = X25519PublicKey.from_public_bytes(peer_public_key)
        
        # Perform key exchange
        shared_secret = private_key_obj.exchange(peer_key_obj)
        
        print(f"{self.name}: performKeyExchange - Key exchange performed")
        print(f"{self.name}: Shared Secret (hex): {shared_secret.hex()}")
        
        return shared_secret

    def derive_key(self, shared_secret: bytes) -> bytes:
        """Derive a session key from the shared secret using BLAKE2b"""
        key = bytearray(SESSION_KEY_SIZE)
        
        context = bytearray(8)
        context[0:len(PROTOCOL_NAME)] = PROTOCOL_NAME.encode()
        
        buffer = bytearray(40)
        # subkey_id = 1 (little-endian uint64)
        buffer[0:8] = struct.pack("<Q", 1)
        buffer[8:16] = context
        # Session key size (little-endian uint64)
        buffer[16:24] = struct.pack("<Q", SESSION_KEY_SIZE)
        # buffer[24:] is already zeroed
        
        h = hashlib.blake2b(key=shared_secret, digest_size=32)
        for _ in range(ROUNDS):
            h.update(buffer)
        
        derived_key = h.digest()[:SESSION_KEY_SIZE]
        
        print(f"{self.name}: deriveKey - Key derived from shared secret")
        print(f"{self.name}: Derived Key (hex): {derived_key.hex()}")
        self.log_key(derived_key, "Derived Key")
        
        return derived_key

    def encrypt(self, plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt plaintext using XChaCha20-Poly1305"""
        nonce = self.generate_nonce()
        
        # XChaCha20-Poly1305 encryption (using PyNaCl)
        ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, 
            None,  # No additional data
            nonce, 
            key
        )
        
        print(f"{self.name}: encrypt - Encryption performed")
        self.log_key(nonce, "Nonce")
        
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes) -> Optional[bytes]:
        """Decrypt ciphertext using XChaCha20-Poly1305"""
        try:
            # XChaCha20-Poly1305 decryption (using PyNaCl)
            plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext,
                None,  # No additional data
                nonce,
                key
            )
            print(f"{self.name}: decrypt - Decryption succeeded")
            return plaintext
        except Exception as e:
            print(f"{self.name}: decrypt - Decryption failed")
            return None

    def generate_nonce(self) -> bytes:
        """Generate a random nonce for encryption"""
        nonce = os.urandom(NONCE_SIZE)
        print(f"{self.name}: generateNonce - Nonce generated")
        return nonce

    def log_keys(self) -> None:
        """Log public and private keys in base64 format"""
        print(f"{self.name}: Public Key (Base64): {base64.b64encode(self.public_key).decode()}")
        print(f"{self.name}: Private Key (Base64): {base64.b64encode(self.private_key).decode()}")

    def log_key(self, key: bytes, label: str) -> None:
        """Log a key or other binary data in base64 format"""
        print(f"{self.name}: {label} (Base64): {base64.b64encode(key).decode()}")


def main():
    # Same key values as in the Go implementation
    alice_private_key = bytes([
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    ])
    alice_public_key = bytes([
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
    ])
    bob_private_key = bytes([
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    ])
    bob_public_key = bytes([
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
    ])

    alice = EjafaProtocol("Alice", alice_private_key, alice_public_key)
    bob = EjafaProtocol("Bob", bob_private_key, bob_public_key)

    alice_shared_secret = alice.perform_key_exchange(bob_public_key)
    bob_shared_secret = bob.perform_key_exchange(alice_public_key)

    print(f"aliceSharedSecret (hex): {alice_shared_secret.hex()}")
    print(f"bobSharedSecret (hex): {bob_shared_secret.hex()}")

    if alice_shared_secret != bob_shared_secret:
        print("ERROR: Shared secrets do not match!")
        return

    alice_key = alice.derive_key(alice_shared_secret)
    bob_key = bob.derive_key(bob_shared_secret)

    plaintext = b"This is a secret message."
    ciphertext, nonce = alice.encrypt(plaintext, alice_key)

    decrypted_text = bob.decrypt(ciphertext, bob_key, nonce)
    if decrypted_text is None:
        print("Bob: Decryption failed!")
        return

    print(f"Bob: Decrypted text: {decrypted_text.decode()}")
    print("All tests passed")


if __name__ == "__main__":
    main() 