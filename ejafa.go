package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"log"
)

const (
	privateKeySize   = 32
	publicKeySize    = 32
	sharedSecretSize = 32
	sessionKeySize   = 32
	nonceSize        = chacha20poly1305.NonceSizeX
	rounds           = 20
	protocolName     = "EjafaProtocol"
)

type EjafaProtocol struct {
	name       string
	privateKey [privateKeySize]byte
	publicKey  [publicKeySize]byte
}

func NewEjafaProtocol(name string, privateKey, publicKey []byte) *EjafaProtocol {
	e := &EjafaProtocol{name: name}
	copy(e.privateKey[:], privateKey)
	copy(e.publicKey[:], publicKey)
	fmt.Printf("%s: Constructor - Keys set\n", e.name)
	e.logKeys()
	return e
}

func (e *EjafaProtocol) performKeyExchange(peerPublicKey []byte) [sharedSecretSize]byte {
	var sharedSecret [sharedSecretSize]byte
	tmp, err := curve25519.X25519(e.privateKey[:], peerPublicKey)
	if err != nil {
		log.Fatalf("%s: performKeyExchange - Key exchange failed: %v", e.name, err)
	}
	copy(sharedSecret[:], tmp)
	fmt.Printf("%s: performKeyExchange - Key exchange performed\n", e.name)
	fmt.Printf("%s: Shared Secret (hex): %x\n", e.name, sharedSecret)
	return sharedSecret
}

func (e *EjafaProtocol) deriveKey(sharedSecret [sharedSecretSize]byte) []byte {
	key := make([]byte, sessionKeySize)

	context := make([]byte, 8)
	copy(context, []byte(protocolName))

	buffer := make([]byte, 40)
	binary.LittleEndian.PutUint64(buffer[0:], 1) // subkey_id = 1
	copy(buffer[8:], context)
	binary.LittleEndian.PutUint64(buffer[16:], uint64(sessionKeySize))
	// buffer[24:] is already zeroed

	h, _ := blake2b.New256(sharedSecret[:])
	for i := 0; i < rounds; i++ {
		h.Write(buffer)
	}
	derivedKey := h.Sum(nil)

	copy(key, derivedKey[:sessionKeySize])

	fmt.Printf("%s: deriveKey - Key derived from shared secret\n", e.name)
	fmt.Printf("%s: Derived Key (hex): %x\n", e.name, key)
	e.logKey(key, "Derived Key")
	return key
}

func (e *EjafaProtocol) encrypt(plaintext, key []byte) ([]byte, []byte) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		log.Fatalf("%s: encrypt - Failed to create AEAD: %v", e.name, err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("%s: encrypt - Failed to generate nonce: %v", e.name, err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	fmt.Printf("%s: encrypt - Encryption performed\n", e.name)
	e.logKey(nonce, "Nonce")
	return ciphertext, nonce
}

func (e *EjafaProtocol) decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("%s: decrypt - Failed to create AEAD: %v", e.name, err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("%s: decrypt - Decryption failed\n", e.name)
		return nil, err
	}
	fmt.Printf("%s: decrypt - Decryption succeeded\n", e.name)
	return plaintext, nil
}

func (e *EjafaProtocol) generateNonce() []byte {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("%s: generateNonce - Failed to generate nonce: %v", e.name, err)
	}
	fmt.Printf("%s: generateNonce - Nonce generated\n", e.name)
	return nonce
}

func (e *EjafaProtocol) logKeys() {
	fmt.Printf("%s: Public Key (Base64): %s\n", e.name, base64.StdEncoding.EncodeToString(e.publicKey[:]))
	fmt.Printf("%s: Private Key (Base64): %s\n", e.name, base64.StdEncoding.EncodeToString(e.privateKey[:]))
}

func (e *EjafaProtocol) logKey(key []byte, label string) {
	fmt.Printf("%s: %s (Base64): %s\n", e.name, label, base64.StdEncoding.EncodeToString(key))
}

func main() {
	alicePrivateKey := []byte{
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
	}
	alicePublicKey := []byte{
		0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
		0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
	}
	bobPrivateKey := []byte{
		0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
		0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
	}
	bobPublicKey := []byte{
		0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
		0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
	}
	alice := NewEjafaProtocol("Alice", alicePrivateKey, alicePublicKey)
	bob := NewEjafaProtocol("Bob", bobPrivateKey, bobPublicKey)

	aliceSharedSecret := alice.performKeyExchange(bob.publicKey[:])
	bobSharedSecret := bob.performKeyExchange(alice.publicKey[:])

	fmt.Printf("aliceSharedSecret (hex): %x\n", aliceSharedSecret)
	fmt.Printf("bobSharedSecret (hex): %x\n", bobSharedSecret)

	if aliceSharedSecret != bobSharedSecret {
		log.Fatal("main: Shared secrets do not match!")
	}

	aliceKey := alice.deriveKey(aliceSharedSecret)
	bobKey := bob.deriveKey(bobSharedSecret)

	plaintext := []byte("This is a secret message.")
	ciphertext, nonce := alice.encrypt(plaintext, aliceKey)

	decryptedText, err := bob.decrypt(ciphertext, bobKey, nonce)
	if err != nil {
		log.Fatal("Bob: Decryption failed:", err)
	}

	fmt.Printf("Bob: Decrypted text: %s\n", string(decryptedText))
	fmt.Println("main: All tests passed")
}
