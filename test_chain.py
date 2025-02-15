import time
import json
import hashlib
import ecdsa

def sha256(data):
    """Return the SHA-256 hash of the given data string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

class Authority:
    """Represents an authority node that can sign blocks."""
    def __init__(self):
        # Generate a new ECDSA key pair (using the SECP256k1 curve)
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def sign(self, data):
        """Sign the given data string and return the signature as a hex string."""
        return self.private_key.sign(data.encode('utf-8')).hex()

    def get_public_key_hex(self):
        """Return the public key as a hex string."""
        return self.public_key.to_string().hex()

class Block:
    """Represents a single block in the blockchain."""
    def __init__(self, index, previous_hash, data, timestamp=None, signature=None, signer=None):
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.timestamp = timestamp or time.time()
        self.signature = signature  # Signature of the block data by an authority
        self.signer = signer        # The public key (in hex) of the signing authority

    def compute_hash(self):
        """Compute the SHA-256 hash of the block’s content."""
        block_content = json.dumps({
            'index': self.index,
            'previous_hash': self.previous_hash,
            'data': self.data,
            'timestamp': self.timestamp,
            'signer': self.signer
        }, sort_keys=True)
        return sha256(block_content)

class Blockchain:
    """Simple blockchain that only accepts blocks signed by authorized authorities."""
    def __init__(self, authorized_keys):
        self.chain = []
        self.authorized_keys = authorized_keys  # List of authorized public keys (hex strings)
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the genesis block with no signature."""
        genesis_block = Block(0, "0", "Genesis Block", time.time())
        # For the genesis block, we do not require a signature
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    def add_block(self, block):
        """Add a block to the chain after verification."""
        if self.verify_block(block):
            block.hash = block.compute_hash()
            self.chain.append(block)
            return True
        else:
            return False

    def verify_block(self, block):
        """Verify the block’s previous hash, authorized signer, and signature."""
        # Check if the previous hash matches the hash of the last block
        last_block = self.chain[-1]
        if block.previous_hash != last_block.compute_hash():
            print("Invalid previous hash")
            return False

        # Ensure the signer is in the list of authorized keys
        if block.signer not in self.authorized_keys:
            print("Signer not authorized")
            return False

        # Recreate the block data to verify the signature
        block_data = json.dumps({
            'index': block.index,
            'previous_hash': block.previous_hash,
            'data': block.data,
            'timestamp': block.timestamp,
            'signer': block.signer
        }, sort_keys=True)

        try:
            # Create a verifying key from the signer's public key
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(block.signer), curve=ecdsa.SECP256k1)
            signature_bytes = bytes.fromhex(block.signature)
            if vk.verify(signature_bytes, block_data.encode('utf-8')):
                return True
            else:
                print("Signature verification failed")
                return False
        except Exception as e:
            print("Error during signature verification:", e)
            return False

if __name__ == '__main__':
    # Create an authority and get its public key
    authority = Authority()
    authorized_keys = [authority.get_public_key_hex()]

    # Initialize the blockchain with the authorized keys
    blockchain = Blockchain(authorized_keys)

    # Create a new block
    previous_hash = blockchain.chain[-1].compute_hash()
    new_block = Block(index=1, previous_hash=previous_hash, data="Block 1 Data")
    
    # Prepare block data to sign
    block_data = json.dumps({
        'index': new_block.index,
        'previous_hash': new_block.previous_hash,
        'data': new_block.data,
        'timestamp': new_block.timestamp,
        'signer': authority.get_public_key_hex()
    }, sort_keys=True)
    
    # Authority signs the block data
    new_block.signature = authority.sign(block_data)
    new_block.signer = authority.get_public_key_hex()

    # Add the new block to the blockchain
    if blockchain.add_block(new_block):
        print("Block added successfully!")
    else:
        print("Failed to add block.")

    # Display the blockchain
    for block in blockchain.chain:
        print(vars(block))
