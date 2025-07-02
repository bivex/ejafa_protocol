# EjafaProtocol Python Implementation
 [![Protocolled 📡](https://a.b-b.top/badge.svg?repo=ejafa_protocol&label=Protocolled%20📡&background_color=795548&background_color2=8d6e63&utm_source=github&utm_medium=readme&utm_campaign=badge)](https://a.b-b.top)
This is a Python implementation of the EjafaProtocol, a secure communication protocol that uses:
- X25519 for key exchange
- BLAKE2b for key derivation
- XChaCha20-Poly1305 for authenticated encryption

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/EjafaProtocol.git
cd EjafaProtocol
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Usage

Run the example implementation:

```
python ejafa.py
```

## Implementation Details

The EjafaProtocol Python implementation provides:

1. **Secure Key Exchange**: Using X25519 for Diffie-Hellman key exchange
2. **Key Derivation**: Using BLAKE2b for deriving session keys
3. **Authenticated Encryption**: Using XChaCha20-Poly1305 for secure message encryption

## API

```python
# Create protocol instances
alice = EjafaProtocol("Alice", alice_private_key, alice_public_key)
bob = EjafaProtocol("Bob", bob_private_key, bob_public_key)

# Perform key exchange
shared_secret = alice.perform_key_exchange(bob_public_key)

# Derive session key
key = alice.derive_key(shared_secret)

# Encrypt message
ciphertext, nonce = alice.encrypt(plaintext, key)

# Decrypt message
plaintext = bob.decrypt(ciphertext, key, nonce)
```

## Security Notes

- This implementation uses cryptographic primitives from the `cryptography` and `PyNaCl` libraries
- The protocol uses 32-byte keys and 24-byte nonces for XChaCha20-Poly1305
- Key derivation uses 20 rounds of BLAKE2b hashing 
