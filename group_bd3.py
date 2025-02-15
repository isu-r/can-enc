import sys
import secrets
import random
import hashlib
import base64
import uuid
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- BD Protocol Parameters (demo values) ---
# In a real system, use a large prime and a proper generator.
p = 2357  # Demo prime
g = 2     # Generator

# --- Predefined acceptable MAC addresses and corresponding identities ---
ACCEPTED_MACS = {
    "00:0C:29:BD:61:6B": "A",
    "AA:BB:CC:DD:EE:02": "B",
    "AA:BB:CC:DD:EE:03": "C"
}

def get_mac_address():
    """Retrieve and format the device's MAC address."""
    mac_int = uuid.getnode()
    mac_str = ':'.join(("%012X" % mac_int)[i:i+2] for i in range(0, 12, 2))
    return mac_str

def main():
    # Identify device based on its MAC address.
    mac = get_mac_address()
    print("Detected MAC address:", mac)
    if mac not in ACCEPTED_MACS:
        print("This MAC address is not recognized. Exiting.")
        sys.exit(1)
    device_id = ACCEPTED_MACS[mac]
    print("Device identity determined as:", device_id)
    
    # --- BD Protocol: Key Exchange (manual process) ---
    # Each device generates a BD secret and computes its BD public value.
    bd_secret = secrets.randbelow(p - 2) + 2  # random number in [2, p-1]
    bd_public = pow(g, bd_secret, p)
    print("\nYour BD public value:", bd_public)
    
    # Manually exchange BD public values with the other devices.
    if device_id == "A":
        bd_public_B = int(input("Enter BD public value for device B: "))
        bd_public_C = int(input("Enter BD public value for device C: "))
    elif device_id == "B":
        bd_public_A = int(input("Enter BD public value for device A: "))
        bd_public_C = int(input("Enter BD public value for device C: "))
    elif device_id == "C":
        bd_public_A = int(input("Enter BD public value for device A: "))
        bd_public_B = int(input("Enter BD public value for device B: "))
    
    # --- BD Protocol Round 2: Compute T value ---
    # Using a predetermined cyclic order:
    #  • Device A uses device C’s BD public value.
    #  • Device B uses device A’s BD public value.
    #  • Device C uses device B’s BD public value.
    if device_id == "A":
        T = pow(bd_public_C, bd_secret, p)
    elif device_id == "B":
        T = pow(bd_public_A, bd_secret, p)
    elif device_id == "C":
        T = pow(bd_public_B, bd_secret, p)
    print("\nYour T value:", T)
    
    # Manually exchange T values with the other devices.
    T1 = int(input("Enter T value from first other device: "))
    T2 = int(input("Enter T value from second other device: "))
    
    # Compute the shared key as the product of the T values modulo p.
    shared_key = (T * T1 * T2) % p
    print("\nShared key (BD protocol):", shared_key)
    
    # --- Deterministic RSA Key Generation ---
    # Derive a seed from the shared key and override the randomness for RSA generation.
    seed = int(hashlib.sha256(str(shared_key).encode()).hexdigest(), 16)
    rng = random.Random(seed)
    
    import Crypto.Random
    Crypto.Random.get_random_bytes = lambda n: bytes([rng.getrandbits(8) for _ in range(n)])
    
    # Generate a 1024-bit RSA key pair.
    rsa_key = RSA.generate(1024)
    rsa_public_pem = rsa_key.publickey().export_key().decode()
    print("\nYour RSA public key (derived from shared BD key):")
    print(rsa_public_pem)
    
    # --- Messaging with RSA Encryption ---
    # Initialize the nonce (starting at 0).
    nonce = 0
    
    # Create cipher objects:
    # Use the public key for encryption and the private key for decryption.
    cipher_encrypt = PKCS1_OAEP.new(rsa_key.publickey())
    cipher_decrypt = PKCS1_OAEP.new(rsa_key)
    
    mode = input("\nEnter mode (send/receive): ").strip().lower()
    
    if mode.startswith("s"):
        # Send mode: ask for message content, format it with a nonce, then encrypt.
        content = input("Enter the message content: ")
        message_str = f"message type: general, content: {content}, nonce: {nonce}"
        encrypted = cipher_encrypt.encrypt(message_str.encode())
        encrypted_b64 = base64.b64encode(encrypted).decode()
        print("\nEncrypted message (copy and paste this to the recipient):")
        print(encrypted_b64)
        nonce += 1  # Increment nonce after sending
    elif mode.startswith("r"):
        # Receive mode: paste the encrypted message and decrypt it.
        encrypted_b64 = input("Paste the encrypted message: ")
        try:
            encrypted = base64.b64decode(encrypted_b64)
            decrypted = cipher_decrypt.decrypt(encrypted)
            print("\nDecrypted message:")
            print(decrypted.decode())
        except Exception as e:
            print("Decryption failed:", e)
    else:
        print("Invalid mode. Please enter 'send' or 'receive'.")

if __name__ == "__main__":
    main()



