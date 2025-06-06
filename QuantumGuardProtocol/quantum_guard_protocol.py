import os
import hashlib
import hmac
from typing import Tuple, Optional
import sys

# Required libraries:
# pip install pynacl rich

import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox
from nacl.exceptions import BadSignatureError

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

PROTOCOL_NAME = "QuantumGuardProtocol"
HKDF_SALT_SIZE = 32
SESSION_KEY_SIZE = 32 # For SecretBox

console = Console()

def secure_zero(b: bytes):
    """Attempts to securely zero out a bytes object.
    Note: In CPython, this might not guarantee immediate memory overwrite
    due to garbage collection, but it's a good practice for explicitly
    indicating sensitive data should be cleared.
    """
    # Create a mutable bytearray from the bytes object
    ba = bytearray(b)
    # Overwrite with zeros
    for i in range(len(ba)):
        ba[i] = 0
    # Convert back to bytes (this might create a new object, but original is still referenced)
    return bytes(ba)

# HKDF-Expand(PRK, info, L) -> OKM
def hkdf_expand(prk_val: bytes, info_val: bytes, length: int) -> bytes:
    okm = b''
    t = b''
    counter = 0x01
    while len(okm) < length:
        t = hmac.new(prk_val, t + info_val + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]

class QuantumGuardProtocol:
    def __init__(self, name: str, long_term_signing_key: SigningKey, long_term_verify_key: VerifyKey):
        self.name = name
        self.long_term_signing_key = long_term_signing_key
        self.long_term_verify_key = long_term_verify_key
        console.print(f"[{self.name}]: Initialized with long-term keys.")
        self.ephemeral_private_key: Optional[PrivateKey] = None
        self.ephemeral_public_key: Optional[PublicKey] = None
        self.session_key: Optional[bytes] = None

    def generate_ephemeral_keys(self):
        """Generates ephemeral X25519 key pair."""
        self.ephemeral_private_key = PrivateKey.generate()
        self.ephemeral_public_key = self.ephemeral_private_key.public_key
        console.print(f"[{self.name}]: Generated ephemeral X25519 key pair.")
        return self.ephemeral_public_key.encode()

    def sign_ephemeral_public_key(self, ephemeral_public_key_bytes: bytes) -> bytes:
        """Signs the ephemeral public key with the long-term signing key."""
        signed = self.long_term_signing_key.sign(ephemeral_public_key_bytes)
        console.print(f"[{self.name}]: Signed ephemeral public key.")
        return signed.signature

    def verify_signature(self, peer_ephemeral_public_key_bytes: bytes, peer_signature: bytes, peer_long_term_verify_key: VerifyKey) -> bool:
        """Verifies the peer's signature on their ephemeral public key."""
        try:
            peer_long_term_verify_key.verify(peer_ephemeral_public_key_bytes, peer_signature)
            console.print(f"[{self.name}]: [green]Verified peer's ephemeral public key signature.[/green]")
            return True
        except BadSignatureError:
            console.print(f"[{self.name}]: [bold red]ERROR: Peer's ephemeral public key signature verification failed![/bold red]")
            return False

    def perform_key_exchange(self, peer_ephemeral_public_key_bytes: bytes) -> bytes:
        """Performs X25519 key exchange with the peer's ephemeral public key."""
        peer_ephemeral_public_key = PublicKey(peer_ephemeral_public_key_bytes)
        shared_secret = Box(self.ephemeral_private_key, peer_ephemeral_public_key).shared_key()
        # Securely zero out ephemeral private key after use
        if self.ephemeral_private_key:
            self.ephemeral_private_key = None

        console.print(f"[{self.name}]: Performed X25519 key exchange.")
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

        # Securely zero out shared secret after use for key derivation
        shared_secret = secure_zero(shared_secret)

        # HKDF-Expand(PRK, info, L) -> OKM
        self.session_key = hkdf_expand(prk, info_encrypt, SESSION_KEY_SIZE)
        
        # Securely zero out PRK after session key derivation
        prk = secure_zero(prk)

        console.print(f"[{self.name}]: Derived session key using HKDF-SHA256.")
        return self.session_key

    def encrypt(self, plaintext: bytes):
        """Encrypts plaintext using XChaCha20-Poly1305 with the session key."""
        if not self.session_key:
            raise ValueError("Session key not derived. Perform key exchange first.")
        
        box = SecretBox(self.session_key)
        # The encrypt method returns an EncryptedMessage object which is bytes (nonce || ciphertext || mac)
        encrypted_message = box.encrypt(plaintext)
        console.print(f"[{self.name}]: Encrypted message.")
        return encrypted_message

    def decrypt(self, encrypted_message: bytes) -> Optional[bytes]:
        """Decrypts ciphertext using XChaCha20-Poly1305 with the session key."""
        if not self.session_key:
            raise ValueError("Session key not derived. Perform key exchange first.")
        
        box = SecretBox(self.session_key)
        try:
            # The decrypt method expects the combined EncryptedMessage (nonce || ciphertext || mac)
            plaintext = box.decrypt(encrypted_message)
            console.print(f"[{self.name}]: [green]Decrypted message successfully.[/green]")
            return plaintext
        except BadSignatureError:
            console.print(f"[{self.name}]: [bold red]ERROR: Decryption failed (bad MAC or corrupted ciphertext). This could indicate tampering.[/bold red]")
            return None
        except Exception as e:
            # Catching generic exceptions for unhandled cases, but BadSignatureError is specific
            console.print(f"[{self.name}]: [bold red]ERROR: Decryption failed unexpectedly: {e}[/bold red]")
            return None

def run_protocol_demonstration():
    console.rule("[bold blue]QuantumGuardProtocol Demonstration[/bold blue]")
    # NOTE FOR PRODUCTION: Avoid logging sensitive cryptographic material (keys, nonces, plaintext, ciphertext)
    # in production environments. This detailed logging is for demonstration purposes only.

    # 1. Generate long-term Ed25519 keys for Alice and Bob
    alice_long_term_signing_key = SigningKey.generate()
    alice_long_term_verify_key = alice_long_term_signing_key.verify_key

    bob_long_term_signing_key = SigningKey.generate()
    bob_long_term_verify_key = bob_long_term_signing_key.verify_key

    console.print(Panel(
        f"[bold green]--- Long-Term Key Generation ---[/bold green]\n"
        f"Alice's Long-Term Verify Key (Hex): [yellow]{alice_long_term_verify_key.encode().hex()}[/yellow]\n"
        f"Bob's Long-Term Verify Key (Hex): [yellow]{bob_long_term_verify_key.encode().hex()}[/yellow]",
        title="[bold cyan]Phase 1: Setup[/bold cyan]",
        border_style="dim cyan"
    ))
    
    console.print(Panel(
        f"[bold green]--- Protocol Initialization ---[/bold green]\n"
        f"Alice initialized.\n"
        f"Bob initialized.",
        title="[bold cyan]Phase 2: Protocol Instances[/bold cyan]",
        border_style="dim cyan"
    ))

    # 2. Initialize protocol instances
    alice = QuantumGuardProtocol("Alice", alice_long_term_signing_key, alice_long_term_verify_key)
    bob = QuantumGuardProtocol("Bob", bob_long_term_signing_key, bob_long_term_verify_key)
    
    console.rule("[bold blue]Phase 3: Key Exchange Initiation[/bold blue]")

    # 3. Alice initiates key exchange
    alice_ephemeral_pub_bytes = alice.generate_ephemeral_keys()
    alice_signature = alice.sign_ephemeral_public_key(alice_ephemeral_pub_bytes)
    console.print(Panel(
        f"[bold green]Alice's Ephemeral Public Key (Hex):[/bold green] [yellow]{alice_ephemeral_pub_bytes.hex()}[/yellow]\n"
        f"[bold green]Alice's Signature (Hex):[/bold green] [yellow]{alice_signature.hex()}[/yellow]",
        title="[bold magenta]Alice Sends Ephemeral Key[/bold magenta]",
        border_style="magenta"
    ))

    console.rule("[bold blue]Phase 4: Bob's Verification & Response[/bold blue]")

    # 4. Bob receives Alice's ephemeral key and signature, verifies, and responds
    if not bob.verify_signature(alice_ephemeral_pub_bytes, alice_signature, alice_long_term_verify_key):
        raise ValueError("Protocol aborted: Alice's signature verification failed for Bob.")

    bob_ephemeral_pub_bytes = bob.generate_ephemeral_keys()
    bob_signature = bob.sign_ephemeral_public_key(bob_ephemeral_pub_bytes)
    console.print(Panel(
        f"[bold green]Bob's Ephemeral Public Key (Hex):[/bold green] [yellow]{bob_ephemeral_pub_bytes.hex()}[/yellow]\n"
        f"[bold green]Bob's Signature (Hex):[/bold green] [yellow]{bob_signature.hex()}[/yellow]",
        title="[bold magenta]Bob Sends Ephemeral Key[/bold magenta]",
        border_style="magenta"
    ))

    console.rule("[bold blue]Phase 5: Alice's Verification[/bold blue]")

    # 5. Alice receives Bob's ephemeral key and signature, verifies
    if not alice.verify_signature(bob_ephemeral_pub_bytes, bob_signature, bob_long_term_verify_key):
        raise ValueError("Protocol aborted: Bob's signature verification failed for Alice.")
    console.print("[green]Both parties successfully authenticated ephemeral keys![/green]")

    console.rule("[bold blue]Phase 6: Shared Secret Derivation[/bold blue]")

    # 6. Both parties derive shared secrets
    alice_shared_secret = alice.perform_key_exchange(bob_ephemeral_pub_bytes)
    bob_shared_secret = bob.perform_key_exchange(alice_ephemeral_pub_bytes)

    # Use hmac.compare_digest for constant-time comparison of secrets
    if not hmac.compare_digest(alice_shared_secret, bob_shared_secret):
        raise ValueError("ERROR: Shared secrets do not match!")
    console.print("[bold green]Shared secrets match.[/bold green]")

    # Securely zero out shared secrets after comparison, as they are no longer needed directly
    alice_shared_secret = secure_zero(alice_shared_secret)
    bob_shared_secret = secure_zero(bob_shared_secret)

    console.rule("[bold blue]Phase 7: Session Key Derivation (HKDF)[/bold blue]")

    # 7. Both parties derive session keys using HKDF
    alice_session_key = alice.derive_key(alice_shared_secret, alice_ephemeral_pub_bytes, bob_ephemeral_pub_bytes)
    bob_session_key = bob.derive_key(bob_shared_secret, bob_ephemeral_pub_bytes, alice_ephemeral_pub_bytes)

    # Use hmac.compare_digest for constant-time comparison of secrets
    if not hmac.compare_digest(alice_session_key, bob_session_key):
        raise ValueError("ERROR: Derived session keys do not match!")
    console.print("[bold green]Derived session keys match.[/bold green]")
    console.print(Panel(
        f"[bold green]Alice's Session Key (Hex):[/bold green] [yellow]{alice_session_key.hex()}[/yellow]\n"
        f"[bold green]Bob's Session Key (Hex):[/bold green] [yellow]{bob_session_key.hex()}[/yellow]",
        title="[bold cyan]Derived Session Keys[/bold cyan]",
        border_style="dim cyan"
    ))

    console.rule("[bold blue]Phase 8: Encrypted Communication[/bold blue]")

    # 8. Alice encrypts a message
    plaintext = b"This is a super secret message for Bob!"
    encrypted_message = alice.encrypt(plaintext)
    console.print(f"[{alice.name}]: Plaintext: [cyan]{plaintext.decode()}[/cyan]")
    console.print(Panel(
        f"[bold green]Encrypted Message (Hex):[/bold green] [yellow]{encrypted_message.hex()}[/yellow]\n"
        f"[bold magenta]Note: Nonce is embedded in the encrypted message.[/bold magenta]",
        title="[bold cyan]Alice Encrypts Message[/bold cyan]",
        border_style="dim cyan"
    ))

    console.rule("[bold blue]Phase 9: Decryption[/bold blue]")

    # 9. Bob decrypts the message
    decrypted_text = bob.decrypt(encrypted_message)
    if decrypted_text is None:
        raise ValueError("Bob: Decryption failed!")

    console.print(Panel(
        f"[bold green]Decrypted text:[/bold green] [cyan]{decrypted_text.decode()}[/cyan]",
        title="[bold cyan]Bob Decrypts Message[/bold cyan]",
        border_style="dim cyan"
    ))
    
    console.rule("[bold green]All QuantumGuardProtocol tests passed ---[/bold green]")


def main():
    try:
        run_protocol_demonstration()
        console.rule("[bold green]All QuantumGuardProtocol tests passed ---[/bold green]")
    except ValueError as e:
        console.print(f"[bold red]Protocol Error:[/bold red] {e}")
        sys.exit(1) # Uncommented to ensure non-zero exit on error
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred:[/bold red] {e}")
        sys.exit(1) # Uncommented to ensure non-zero exit on unexpected errors

if __name__ == "__main__":
    main() 
