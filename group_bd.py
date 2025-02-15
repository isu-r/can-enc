import sys
import secrets
import random
import hashlib
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# --- BD Protocol Parameters (demo values) ---
# In a real system, p should be a large safe prime and g a generator.
p = 2357  # demo prime
g = 2     # generator

def main():
    # Identify the device (A, B, or C)
    device_id = input("Enter your device identity (A, B, or C): ").strip().upper()
    if device_id not in ['A', 'B', 'C']:
        print("Invalid device identity. Must be A, B, or C.")
        sys.exit(1)
    
    # --- BD Protocol Round 1 ---
    # Generate BD secret and public value.
    bd_secret = secrets.randbelow(p - 2) + 2  # random number in [2, p-1]
    bd_public = pow(g, bd_secret, p)
    print("\nYour BD public value:", bd_public)
    
    # Manually exchange BD public values with the other two devices.
    if device_id == "A":
        bd_public_B = int(input("Enter BD public value for device B: "))
        bd_public_C = int(input("Enter BD public value for device C: "))
    elif device_id == "B":
        bd_public_A = int(input("Enter BD public value for device A: "))
        bd_public_C = int(input("Enter BD public value for device C: "))
    elif device_id == "C":
        bd_public_A = int(input("Enter BD public value for device A: "))
        bd_public_B = int(input("Enter BD public value for device B: "))
    
    # --- BD Protocol Round 2 ---
    # Following a predetermined cyclic order (A, B, C), each device computes a T value:
    #   - Device A uses device C’s BD public value.
    #   - Device B uses device A’s BD public value.
    #   - Device C uses device B’s BD public value.
    if device_id == "A":
        T = pow(bd_public_C, bd_secret, p)
    elif device_id == "B":
        T = pow(bd_public_A, bd_secret, p)
    elif device_id == "C":
        T = pow(bd_public_B, bd_secret, p)
    print("\nYour T value:", T)
    
    # Now manually exchange the T values.
    T1 = int(input("Enter T value from first other device: "))
    T2 = int(input("Enter T value from second other device: "))
    # The shared key is the product of all T values modulo p.
    shared_key = (T * T1 * T2) % p
    print("\nShared key (BD protocol):", shared_key)
    
    # --- Deterministic RSA Key Generation ---
    # Derive a seed from the shared key.
    seed = int(hashlib.sha256(str(shared_key).encode()).hexdigest(), 16)
    rng = random.Random(seed)
    
    # Monkey-patch the randomness source so that RSA.generate() is deterministic.
    import Crypto.Random
    Crypto.Random.get_random_bytes = lambda n: bytes([rng.getrandbits(8) for _ in range(n)])
    
    # Generate a 1024-bit RSA key pair.
    rsa_key = RSA.generate(1024)
    
    # Export and display the RSA public key in PEM format.
    rsa_public_pem = rsa_key.publickey().export_key().decode()
    print("\nYour RSA public key (derived from shared BD key):")
    print(rsa_public_pem)
    
    # --- Communication: Send or Receive ---
    mode = input("\nEnter mode (send/receive): ").strip().lower()
    cipher = PKCS1_OAEP.new(rsa_key)
    
    if mode.startswith("s"):
        # In send mode, enter the message, encrypt it, and show the ciphertext.
        message = input("Enter the message to send: ")
        encrypted = cipher.encrypt(message.encode())
        encrypted_b64 = base64.b64encode(encrypted).decode()
        print("\nEncrypted message (copy and paste this to the recipient):")
        print(encrypted_b64)
    elif mode.startswith("r"):
        # In receive mode, paste the ciphertext and decrypt it.
        encrypted_b64 = input("Paste the encrypted message: ")
        try:
            encrypted = base64.b64decode(encrypted_b64)
            decrypted = cipher.decrypt(encrypted)
            print("\nDecrypted message:")
            print(decrypted.decode())
        except Exception as e:
            print("Decryption failed:", e)
    else:
        print("Invalid mode. Please enter 'send' or 'receive'.")

if __name__ == "__main__":
    main()
