import random
import hashlib
import itertools

# Diffie–Hellman parameters (small prime for demonstration)
# In production, use a sufficiently large prime and generator.
p = 7919      # a prime number (for demo purposes)
g = 2         # a primitive root modulo p

def derive_key(shared_int):
    """
    Derive a 32-byte key from the shared secret using SHA-256.
    """
    shared_bytes = str(shared_int).encode('utf-8')
    return hashlib.sha256(shared_bytes).digest()

def encrypt_message(message, key):
    """
    Encrypt the message using a simple XOR cipher.
    The key is cycled over the message bytes.
    Returns the ciphertext as a hex string.
    """
    message_bytes = message.encode('utf-8')
    encrypted = bytes([b ^ k for b, k in zip(message_bytes, itertools.cycle(key))])
    return encrypted.hex()

def decrypt_message(ciphertext_hex, key):
    """
    Decrypt the hex-encoded ciphertext using the same XOR cipher.
    Returns the decrypted message string.
    """
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    decrypted = bytes([b ^ k for b, k in zip(ciphertext_bytes, itertools.cycle(key))])
    return decrypted.decode('utf-8')

def main():
    # Identify which device this is.
    device_name = input("Enter your device name (A, B, or C): ").strip().upper()
    if device_name not in ['A', 'B', 'C']:
        print("Invalid device name! Please choose A, B, or C.")
        return

    # Determine the names of the other devices.
    other_devices = [d for d in ['A', 'B', 'C'] if d != device_name]

    # Generate your Diffie–Hellman private key and public key.
    private_key = random.randint(2, p - 2)
    public_key = pow(g, private_key, p)
    print(f"\nYour public key is: {public_key}\n")

    # For each of the other two devices, ask for their public key
    # and compute the shared secret (and then derive a key from it).
    shared_keys = {}
    for d in other_devices:
        try:
            other_pub = int(input(f"Enter public key for device {d}: "))
        except ValueError:
            print("Invalid input! Please enter a valid integer key.")
            return
        shared_secret = pow(other_pub, private_key, p)
        shared_keys[d] = derive_key(shared_secret)

    print("\nConfiguration complete!")
    mode = input("Do you want to send or receive? (S/R): ").strip().upper()
    if mode == 'S':
        # Sending mode: ask for the target device and the message.
        target = input(f"Enter target device ({'/'.join(other_devices)}): ").strip().upper()
        if target not in shared_keys:
            print("Target device not configured!")
            return
        message = input("Enter the message to send: ")
        ciphertext = encrypt_message(message, shared_keys[target])
        print("\nEncrypted message (copy and send this to the target device):")
        print(ciphertext)
    elif mode == 'R':
        # Receiving mode: ask for the source device and the ciphertext.
        source = input(f"Enter source device ({'/'.join(other_devices)}): ").strip().upper()
        if source not in shared_keys:
            print("Source device not configured!")
            return
        ciphertext = input("Paste the encrypted message: ").strip()
        try:
            message = decrypt_message(ciphertext, shared_keys[source])
            print("\nDecrypted message:")
            print(message)
        except Exception as e:
            print("Error during decryption:", e)
    else:
        print("Invalid mode selected!")

if __name__ == "__main__":
    main()
