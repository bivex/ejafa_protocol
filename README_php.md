# EjafaProtocol PHP Implementation

This is a PHP implementation of the EjafaProtocol, a secure communication protocol that uses:
- X25519 for key exchange
- BLAKE2b for key derivation
- XChaCha20-Poly1305 for authenticated encryption

## Requirements

- PHP 7.2 or higher
- Sodium extension (included in PHP 7.2+ by default)
- Hash extension (included in PHP by default)

## Installation

1. Ensure you have PHP 7.2+ installed with the sodium extension:
   ```
   php -m | grep sodium
   ```

   If the sodium extension is not listed, you may need to install it:
   ```
   # On Ubuntu/Debian
   sudo apt-get install php-sodium
   
   # On CentOS/RHEL
   sudo yum install php-sodium
   
   # On macOS with Homebrew
   brew install php
   ```

2. Clone this repository:
   ```
   git clone https://github.com/yourusername/EjafaProtocol.git
   cd EjafaProtocol
   ```

## Usage

Run the example implementation:

```
php ejafa.php
```

## Implementation Details

The EjafaProtocol PHP implementation provides:

1. **Secure Key Exchange**: Using X25519 for Diffie-Hellman key exchange via libsodium
2. **Key Derivation**: Using BLAKE2b for deriving session keys via libsodium's generichash
3. **Authenticated Encryption**: Using XChaCha20-Poly1305 for secure message encryption

## API

```php
// Create protocol instances
$alice = new EjafaProtocol("Alice", $alicePrivateKey, $alicePublicKey);
$bob = new EjafaProtocol("Bob", $bobPrivateKey, $bobPublicKey);

// Perform key exchange
$sharedSecret = $alice->performKeyExchange($bob->publicKey);

// Derive session key
$key = $alice->deriveKey($sharedSecret);

// Encrypt message
list($ciphertext, $nonce) = $alice->encrypt($plaintext, $key);

// Decrypt message
$plaintext = $bob->decrypt($ciphertext, $key, $nonce);
```

## Security Notes

- This implementation uses cryptographic primitives from PHP's libsodium extension
- The protocol uses 32-byte keys and 24-byte nonces for XChaCha20-Poly1305
- Key derivation uses 20 rounds of BLAKE2b hashing
- All keys and cryptographic material are handled as raw binary strings for optimal security 