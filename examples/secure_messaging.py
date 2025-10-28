#!/usr/bin/env python3
"""
Secure Messaging System
Demonstrate end-to-end encryption for secure communications
Uses RSA for key exchange and AES for message encryption
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
from datetime import datetime


class SecureMessaging:
    """Handle secure message encryption and decryption"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None

    def generate_keypair(self):
        """Generate RSA key pair"""
        print("[*] Generating RSA key pair...")

        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

        print("✓ Key pair generated successfully")
        return self.public_key

    def export_public_key(self, filename="public_key.pem"):
        """Export public key to file"""
        if not self.public_key:
            print("✗ No public key to export")
            return False

        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(filename, 'wb') as f:
            f.write(pem)

        print(f"✓ Public key exported to {filename}")
        return True

    def import_public_key(self, filename):
        """Import peer's public key"""
        try:
            with open(filename, 'rb') as f:
                pem_data = f.read()

            self.peer_public_key = serialization.load_pem_public_key(
                pem_data,
                backend=default_backend()
            )

            print(f"✓ Peer public key loaded from {filename}")
            return True

        except Exception as e:
            print(f"✗ Error loading public key: {e}")
            return False

    def encrypt_message(self, message):
        """
        Encrypt message using hybrid encryption
        - Generate random AES key
        - Encrypt message with AES
        - Encrypt AES key with RSA
        """
        if not self.peer_public_key:
            print("✗ No peer public key loaded")
            return None

        try:
            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key
            iv = os.urandom(16)  # Initialization vector

            # Encrypt message with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )

            encryptor = cipher.encryptor()

            # Pad message to AES block size
            message_bytes = message.encode('utf-8')
            padding_length = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + bytes([padding_length] * padding_length)

            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

            # Encrypt AES key with RSA
            encrypted_key = self.peer_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Package everything together
            encrypted_package = {
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_message': base64.b64encode(encrypted_message).decode('utf-8'),
                'timestamp': datetime.now().isoformat()
            }

            return json.dumps(encrypted_package)

        except Exception as e:
            print(f"✗ Encryption error: {e}")
            return None

    def decrypt_message(self, encrypted_package_json):
        """Decrypt message using hybrid decryption"""
        if not self.private_key:
            print("✗ No private key available")
            return None

        try:
            # Parse encrypted package
            package = json.loads(encrypted_package_json)

            encrypted_key = base64.b64decode(package['encrypted_key'])
            iv = base64.b64decode(package['iv'])
            encrypted_message = base64.b64decode(package['encrypted_message'])

            # Decrypt AES key with RSA
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Decrypt message with AES
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )

            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

            # Remove padding
            padding_length = padded_message[-1]
            message = padded_message[:-padding_length]

            return message.decode('utf-8')

        except Exception as e:
            print(f"✗ Decryption error: {e}")
            return None

    def sign_message(self, message):
        """Create digital signature for message"""
        if not self.private_key:
            print("✗ No private key available")
            return None

        try:
            signature = self.private_key.sign(
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return base64.b64encode(signature).decode('utf-8')

        except Exception as e:
            print(f"✗ Signing error: {e}")
            return None

    def verify_signature(self, message, signature_b64):
        """Verify digital signature"""
        if not self.peer_public_key:
            print("✗ No peer public key loaded")
            return False

        try:
            signature = base64.b64decode(signature_b64)

            self.peer_public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except Exception as e:
            print(f"✗ Signature verification failed: {e}")
            return False


def demo_secure_messaging():
    """Demonstrate secure messaging"""
    print("\n" + "="*70)
    print("SECURE MESSAGING SYSTEM DEMO")
    print("="*70)

    # Create two users
    print("\n[Phase 1: Key Generation]")
    print("\nAlice generates her key pair...")
    alice = SecureMessaging()
    alice.generate_keypair()
    alice.export_public_key("alice_public.pem")

    print("\nBob generates his key pair...")
    bob = SecureMessaging()
    bob.generate_keypair()
    bob.export_public_key("bob_public.pem")

    # Exchange public keys
    print("\n[Phase 2: Key Exchange]")
    print("\nAlice imports Bob's public key...")
    alice.import_public_key("bob_public.pem")

    print("Bob imports Alice's public key...")
    bob.import_public_key("alice_public.pem")

    # Alice sends encrypted message to Bob
    print("\n[Phase 3: Secure Communication]")
    message_from_alice = "Hi Bob! This is a secret message. Meet me at the secure location."

    print(f"\nAlice's original message: '{message_from_alice}'")

    print("\nAlice encrypts the message...")
    encrypted = alice.encrypt_message(message_from_alice)

    print(f"Encrypted message (first 100 chars): {encrypted[:100]}...")

    print("\nAlice signs the message for authenticity...")
    signature = alice.sign_message(message_from_alice)
    print(f"Signature (first 50 chars): {signature[:50]}...")

    # Bob receives and decrypts
    print("\n[Phase 4: Message Reception]")
    print("\nBob receives the encrypted message...")
    print("Bob decrypts the message...")

    decrypted = bob.decrypt_message(encrypted)
    print(f"Decrypted message: '{decrypted}'")

    print("\nBob verifies the signature...")
    if bob.verify_signature(decrypted, signature):
        print("✓ Signature verified! Message is authentic and from Alice.")
    else:
        print("✗ Signature verification failed! Message may be tampered.")

    # Bob replies
    print("\n[Phase 5: Reply]")
    message_from_bob = "Hi Alice! Message received. I'll be there."

    print(f"\nBob's reply: '{message_from_bob}'")
    print("Bob encrypts his reply...")

    encrypted_reply = bob.encrypt_message(message_from_bob)

    print("\nAlice receives and decrypts Bob's reply...")
    decrypted_reply = alice.decrypt_message(encrypted_reply)
    print(f"Decrypted reply: '{decrypted_reply}'")

    # Cleanup
    print("\n[Cleanup]")
    os.remove("alice_public.pem")
    os.remove("bob_public.pem")
    print("✓ Temporary files removed")

    print("\n" + "="*70)
    print("DEMO COMPLETE")
    print("="*70)

    print("\nKey Concepts Demonstrated:")
    print("  1. Asymmetric encryption (RSA) for key exchange")
    print("  2. Symmetric encryption (AES) for message encryption")
    print("  3. Hybrid encryption for efficiency")
    print("  4. Digital signatures for authentication")
    print("  5. End-to-end encryption workflow")


def interactive_mode():
    """Interactive secure messaging"""
    print("\n" + "="*70)
    print("SECURE MESSAGING SYSTEM - INTERACTIVE MODE")
    print("="*70)

    messaging = SecureMessaging()

    while True:
        print("\nOptions:")
        print("  1. Generate my key pair")
        print("  2. Export my public key")
        print("  3. Import peer's public key")
        print("  4. Encrypt message")
        print("  5. Decrypt message")
        print("  6. Sign message")
        print("  7. Verify signature")
        print("  8. Run demo")
        print("  9. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == '1':
            messaging.generate_keypair()

        elif choice == '2':
            filename = input("Export to file (default: public_key.pem): ").strip()
            if not filename:
                filename = "public_key.pem"
            messaging.export_public_key(filename)

        elif choice == '3':
            filename = input("Import from file: ").strip()
            if filename:
                messaging.import_public_key(filename)

        elif choice == '4':
            message = input("Enter message to encrypt: ").strip()
            if message:
                encrypted = messaging.encrypt_message(message)
                if encrypted:
                    print(f"\nEncrypted message:\n{encrypted}")
                    save = input("\nSave to file? (y/n): ").strip().lower()
                    if save == 'y':
                        filename = input("Filename: ").strip()
                        with open(filename, 'w') as f:
                            f.write(encrypted)
                        print(f"✓ Saved to {filename}")

        elif choice == '5':
            filename = input("Load encrypted message from file: ").strip()
            if filename:
                try:
                    with open(filename, 'r') as f:
                        encrypted = f.read()
                    decrypted = messaging.decrypt_message(encrypted)
                    if decrypted:
                        print(f"\nDecrypted message:\n{decrypted}")
                except Exception as e:
                    print(f"Error: {e}")

        elif choice == '6':
            message = input("Enter message to sign: ").strip()
            if message:
                signature = messaging.sign_message(message)
                if signature:
                    print(f"\nSignature:\n{signature}")

        elif choice == '7':
            message = input("Enter original message: ").strip()
            signature = input("Enter signature: ").strip()
            if message and signature:
                if messaging.verify_signature(message, signature):
                    print("✓ Signature is valid!")
                else:
                    print("✗ Signature is invalid!")

        elif choice == '8':
            demo_secure_messaging()

        elif choice == '9':
            print("\nGoodbye!")
            break

        else:
            print("Invalid option")


def main():
    """Main function"""
    print("="*70)
    print("SECURE MESSAGING SYSTEM")
    print("="*70)
    print("\nThis tool demonstrates end-to-end encryption:")
    print("  • RSA asymmetric encryption for key exchange")
    print("  • AES symmetric encryption for messages")
    print("  • Digital signatures for authentication")

    print("\nMode:")
    print("  1. Interactive mode")
    print("  2. Run demo")
    print("  3. Exit")

    choice = input("\nSelect mode: ").strip()

    if choice == '1':
        interactive_mode()
    elif choice == '2':
        demo_secure_messaging()
    elif choice == '3':
        print("\nGoodbye!")
    else:
        print("Invalid option")


if __name__ == "__main__":
    main()
