<?php
/**
 * EjafaProtocol PHP Implementation
 * 
 * Requires PHP 7.2+ with:
 * - sodium extension (usually included in PHP)
 * - hash extension (usually included in PHP)
 */

// Constants
const PRIVATE_KEY_SIZE = 32;
const PUBLIC_KEY_SIZE = 32;
const SHARED_SECRET_SIZE = 32;
const SESSION_KEY_SIZE = 32;
const NONCE_SIZE = 24; // XChaCha20-Poly1305 uses 24-byte nonces
const ROUNDS = 20;
const PROTOCOL_NAME = "EjafaProtocol";

class EjafaProtocol {
    private $name;
    private $privateKey;
    private $publicKey;
    
    /**
     * Constructor
     * 
     * @param string $name The name of this party (e.g., "Alice", "Bob")
     * @param string $privateKey Raw binary private key data
     * @param string $publicKey Raw binary public key data
     */
    public function __construct(string $name, string $privateKey, string $publicKey) {
        $this->name = $name;
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        
        $this->printMessage("Constructor - Keys set");
        $this->logKeys();
    }
    
    /**
     * Perform X25519 key exchange with peer's public key
     * 
     * @param string $peerPublicKey Raw binary public key of the peer
     * @return string Shared secret
     */
    public function performKeyExchange(string $peerPublicKey): string {
        // Perform X25519 key exchange using libsodium
        $sharedSecret = sodium_crypto_scalarmult($this->privateKey, $peerPublicKey);
        
        $this->printMessage("performKeyExchange - Key exchange performed");
        $this->printMessage("Shared Secret (hex): " . bin2hex($sharedSecret), false);
        
        return $sharedSecret;
    }
    
    /**
     * Derive a session key from the shared secret using BLAKE2b
     * 
     * @param string $sharedSecret The shared secret from key exchange
     * @return string Derived key
     */
    public function deriveKey(string $sharedSecret): string {
        $key = str_repeat("\0", SESSION_KEY_SIZE);
        
        $context = str_repeat("\0", 8);
        // Copy protocol name to context (up to 8 bytes)
        for ($i = 0; $i < min(strlen(PROTOCOL_NAME), 8); $i++) {
            $context[$i] = PROTOCOL_NAME[$i];
        }
        
        $buffer = str_repeat("\0", 40);
        // subkey_id = 1 (little-endian uint64)
        $buffer[0] = "\x01";
        
        // Copy context
        for ($i = 0; $i < 8; $i++) {
            $buffer[8 + $i] = $context[$i];
        }
        
        // SESSION_KEY_SIZE (little-endian uint64)
        $buffer[16] = chr(SESSION_KEY_SIZE);
        
        // Create BLAKE2b hash state with the shared secret as key
        $hashState = sodium_crypto_generichash_init($sharedSecret, SESSION_KEY_SIZE);
        
        // Perform multiple rounds of hashing
        for ($i = 0; $i < ROUNDS; $i++) {
            sodium_crypto_generichash_update($hashState, $buffer);
        }
        
        $derivedKey = sodium_crypto_generichash_final($hashState, SESSION_KEY_SIZE);
        
        $this->printMessage("deriveKey - Key derived from shared secret");
        $this->printMessage("Derived Key (hex): " . bin2hex($derivedKey), false);
        $this->logKey($derivedKey, "Derived Key");
        
        return $derivedKey;
    }
    
    /**
     * Encrypt plaintext using XChaCha20-Poly1305
     * 
     * @param string $plaintext Text to encrypt
     * @param string $key Encryption key
     * @return array Array containing [ciphertext, nonce]
     */
    public function encrypt(string $plaintext, string $key): array {
        $nonce = $this->generateNonce();
        
        // XChaCha20-Poly1305 encryption
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            '', // No additional data
            $nonce,
            $key
        );
        
        $this->printMessage("encrypt - Encryption performed");
        $this->logKey($nonce, "Nonce");
        
        return [$ciphertext, $nonce];
    }
    
    /**
     * Decrypt ciphertext using XChaCha20-Poly1305
     * 
     * @param string $ciphertext Encrypted data
     * @param string $key Decryption key
     * @param string $nonce Nonce used during encryption
     * @return string|null Decrypted plaintext or null on failure
     */
    public function decrypt(string $ciphertext, string $key, string $nonce): ?string {
        try {
            // XChaCha20-Poly1305 decryption
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                '', // No additional data
                $nonce,
                $key
            );
            
            $this->printMessage("decrypt - Decryption succeeded");
            return $plaintext;
        } catch (Exception $e) {
            $this->printMessage("decrypt - Decryption failed");
            return null;
        }
    }
    
    /**
     * Generate a random nonce for encryption
     * 
     * @return string Random nonce
     */
    public function generateNonce(): string {
        $nonce = random_bytes(NONCE_SIZE);
        $this->printMessage("generateNonce - Nonce generated");
        return $nonce;
    }
    
    /**
     * Log public and private keys in base64 format
     */
    private function logKeys(): void {
        $this->printMessage("Public Key (Base64): " . base64_encode($this->publicKey), false);
        $this->printMessage("Private Key (Base64): " . base64_encode($this->privateKey), false);
    }
    
    /**
     * Log a key or other binary data in base64 format
     * 
     * @param string $key Binary key data
     * @param string $label Label for the key
     */
    private function logKey(string $key, string $label): void {
        $this->printMessage("{$label} (Base64): " . base64_encode($key), false);
    }
    
    /**
     * Print a formatted message with the party's name
     *
     * @param string $message The message to print
     * @param bool $withName Whether to include the name in the output
     */
    private function printMessage(string $message, bool $withName = true): void {
        if ($withName) {
            echo "{$this->name}: " . $message . "\n";
        } else {
            echo "  → " . $message . "\n";
        }
    }
}

/**
 * Main execution function
 */
function main() {
    echo "\n╔══════════════════════════════════════════════╗\n";
    echo "║           EJAFA PROTOCOL PHP TEST             ║\n";
    echo "╚══════════════════════════════════════════════╝\n\n";
    
    // Same key values as in the Go/Python implementations
    $alicePrivateKey = pack('C*',
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    );
    $alicePublicKey = pack('C*',
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    );
    $bobPrivateKey = pack('C*',
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    );
    $bobPublicKey = pack('C*',
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    );

    echo "► Creating Protocol Instances\n";
    echo "───────────────────────────────────────────────\n";
    $alice = new EjafaProtocol("Alice", $alicePrivateKey, $alicePublicKey);
    $bob = new EjafaProtocol("Bob", $bobPrivateKey, $bobPublicKey);
    echo "\n";

    echo "► Performing Key Exchange\n";
    echo "───────────────────────────────────────────────\n";
    $aliceSharedSecret = $alice->performKeyExchange($bobPublicKey);
    $bobSharedSecret = $bob->performKeyExchange($alicePublicKey);
    echo "\n";

    echo "► Verifying Shared Secrets\n";
    echo "───────────────────────────────────────────────\n";
    echo "Alice's shared secret (hex): " . bin2hex($aliceSharedSecret) . "\n";
    echo "Bob's shared secret (hex):   " . bin2hex($bobSharedSecret) . "\n";
    
    if ($aliceSharedSecret !== $bobSharedSecret) {
        echo "✖ ERROR: Shared secrets do not match!\n\n";
        return;
    }
    
    echo "✓ Shared secrets match!\n\n";

    echo "► Deriving Session Keys\n";
    echo "───────────────────────────────────────────────\n";
    $aliceKey = $alice->deriveKey($aliceSharedSecret);
    $bobKey = $bob->deriveKey($bobSharedSecret);
    echo "\n";

    echo "► Testing Encryption and Decryption\n";
    echo "───────────────────────────────────────────────\n";
    $plaintext = "This is a secret message.";
    echo "Original text: \"" . $plaintext . "\"\n\n";
    
    list($ciphertext, $nonce) = $alice->encrypt($plaintext, $aliceKey);
    
    $decryptedText = $bob->decrypt($ciphertext, $bobKey, $nonce);
    if ($decryptedText === null) {
        echo "✖ Bob: Decryption failed!\n\n";
        return;
    }
    
    echo "Decrypted text: \"" . $decryptedText . "\"\n\n";
    
    if ($plaintext === $decryptedText) {
        echo "✓ Messages match - All tests passed!\n\n";
    } else {
        echo "✖ Messages don't match - Test failed!\n\n";
    }
    
    echo "╔══════════════════════════════════════════════╗\n";
    echo "║           TEST RESULTS SUMMARY               ║\n";
    echo "╚══════════════════════════════════════════════╝\n\n";
    
    $results = [
        'Initialization' => true,
        'Key Exchange' => true,
        'Shared Secret Match' => ($aliceSharedSecret === $bobSharedSecret),
        'Key Derivation' => true,
        'Encryption' => true,
        'Decryption' => ($decryptedText !== null),
        'Message Integrity' => ($plaintext === $decryptedText)
    ];
    
    foreach ($results as $test => $passed) {
        $status = $passed ? "✓ PASSED" : "✖ FAILED";
        echo str_pad($test, 25) . " : " . $status . "\n";
    }
    
    echo "\n";
}

// Execute main function
main(); 