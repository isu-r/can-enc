import random
import hashlib
import itertools

# Diffie–Hellman parameters (small values for demonstration)
p = 7919    # a prime (for demo only)
g = 2       # primitive root modulo p

def generate_key_pair():
    """Generate a new Diffie–Hellman key pair."""
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    return private_key, public_key

def derive_key(shared_int):
    """
    Derive a 32-byte key from the shared secret using SHA-256.
    This key is then used for our simple XOR encryption.
    """
    shared_bytes = str(shared_int).encode('utf-8')
    return hashlib.sha256(shared_bytes).digest()

def encrypt_message(plaintext, key):
    """
    Encrypt the plaintext using a simple XOR cipher.
    Returns the ciphertext as a hex string.
    """
    plaintext_bytes = plaintext.encode('utf-8')
    cipher_bytes = bytes([b ^ k for b, k in zip(plaintext_bytes, itertools.cycle(key))])
    return cipher_bytes.hex()

def decrypt_message(ciphertext_hex, key):
    """
    Decrypt the hex-encoded ciphertext using the XOR cipher.
    Returns the decrypted plaintext string.
    """
    cipher_bytes = bytes.fromhex(ciphertext_hex)
    plain_bytes = bytes([b ^ k for b, k in zip(cipher_bytes, itertools.cycle(key))])
    return plain_bytes.decode('utf-8')

def main():
    print("=== Ephemeral Diffie–Hellman Ratchet Demo ===")
    device = input("Enter your device name (A, B, or C): ").strip().upper()
    if device not in ['A', 'B', 'C']:
        print("Invalid device name!")
        return

    # Determine peer devices.
    peers = [d for d in ['A', 'B', 'C'] if d != device]

    # Generate our initial ephemeral key pair.
    my_private, my_public = generate_key_pair()
    print(f"\nYour initial ephemeral public key is: {my_public}")

    # For each peer, input their initial ephemeral public key.
    peer_keys = {}
    for peer in peers:
        try:
            pk = int(input(f"Enter initial public key for device {peer}: ").strip())
            peer_keys[peer] = pk
        except ValueError:
            print("Invalid input for public key.")
            return

    print("\n--- Configuration complete ---")
    print("At any prompt, enter Q to quit.\n")

    # Continuous loop for sending and receiving messages.
    while True:
        choice = input("Send (S) or Receive (R) or Quit (Q): ").strip().upper()
        if choice == 'Q':
            break

        elif choice == 'S':
            target = input(f"Enter target device ({'/'.join(peers)}): ").strip().upper()
            if target not in peer_keys:
                print("Target device not configured!")
                continue
            message = input("Enter message to send: ")
            if message.upper() == 'Q':
                break
            # Compute shared secret using our current ephemeral private key and the target's stored ephemeral public key.
            shared_secret = pow(peer_keys[target], my_private, p)
            key = derive_key(shared_secret)
            # Generate a new ephemeral key pair for ourselves (this will be our new identity for future messages).
            new_private, new_public = generate_key_pair()
            # Prepare plaintext by appending the new public key using a unique delimiter.
            plaintext = f"{message}||PUBLIC_KEY||{new_public}"
            ciphertext = encrypt_message(plaintext, key)
            print("\n--- Encrypted Message ---")
            print(ciphertext)
            # Update our own ephemeral key pair.
            my_private, my_public = new_private, new_public

        elif choice == 'R':
            source = input(f"Enter source device ({'/'.join(peers)}): ").strip().upper()
            if source not in peer_keys:
                print("Source device not configured!")
                continue
            ciphertext = input("Paste the encrypted message: ").strip()
            if ciphertext.upper() == 'Q':
                break
            # Use our current ephemeral private key and the stored sender's ephemeral public key to compute shared secret.
            shared_secret = pow(peer_keys[source], my_private, p)
            key = derive_key(shared_secret)
            try:
                plaintext = decrypt_message(ciphertext, key)
            except Exception as e:
                print("Decryption error:", e)
                continue
            # Expect the plaintext to contain the delimiter "||PUBLIC_KEY||".
            if "||PUBLIC_KEY||" not in plaintext:
                print("Message format error: missing PUBLIC_KEY marker.")
                continue
            try:
                # Extract the custom message and the new public key.
                message_part, new_peer_key_str = plaintext.rsplit("||PUBLIC_KEY||", 1)
                message_part = message_part.strip()
                new_peer_key = int(new_peer_key_str.strip())
            except Exception as e:
                print("Error parsing the new public key:", e)
                continue
            print("\n--- Decrypted Message ---")
            print(message_part)
            # Update the stored ephemeral public key for the sender.
            peer_keys[source] = new_peer_key

        else:
            print("Invalid option. Please choose S, R, or Q.")

if __name__ == "__main__":
    main()
