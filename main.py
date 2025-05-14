import os
import secrets
import logging

KEY_DIR = 'keys/'
os.makedirs(KEY_DIR, exist_ok=True)

logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Key Configuration
SEGMENTS = 4                   # Number of key segments
BLOCKS_PER_SEGMENT = 64        # Blocks per segment (256 total bytes / 4 segments)
KEY_BLOCK_SIZE = 128           # Size of each key block in bytes
KEY_SIZE = SEGMENTS * BLOCKS_PER_SEGMENT  # Total key blocks (256)

def generate_keys():
    try:
        logging.info("Generating keys...")
        # Generate private key (256 blocks of 128 bytes each)
        private_key = [secrets.token_bytes(KEY_BLOCK_SIZE) for _ in range(KEY_SIZE)]
        # Public key is the same as private key for this implementation
        public_key = list(private_key)

        # Save keys
        private_key_path = os.path.join(KEY_DIR, "private_key.bin")
        public_key_path = os.path.join(KEY_DIR, "public_key.bin")

        with open(private_key_path, 'wb') as f:
            for block in private_key:
                f.write(block)
        with open(public_key_path, 'wb') as f:
            for block in public_key:
                f.write(block)

        logging.info(f"Keys generated: {private_key_path}, {public_key_path}")
        return private_key_path, public_key_path

    except Exception as e:
        logging.error(f"Key generation failed: {e}")
        raise

def obfuscate_file(file_path):
    try:
        # Load public key (same as private key)
        public_key = []
        with open(os.path.join(KEY_DIR, 'public_key.bin'), 'rb') as f:
            while True:
                block = f.read(KEY_BLOCK_SIZE)
                if not block:
                    break
                public_key.append(block)
        if len(public_key) != KEY_SIZE:
            raise ValueError("Public key size mismatch")

        # Read input file
        with open(file_path, 'rb') as f:
            data = f.read()
        original_len = len(data)

        # Prepend original length (4 bytes, big-endian)
        obf_data = original_len.to_bytes(4, 'big')

        # Obfuscate each byte
        for byte in data:
            # Determine segment and index
            segment = (byte >> 6) & 0x03  # Top 2 bits (0-3)
            index = byte & 0x3F           # Bottom 6 bits (0-63)
            block_idx = segment * BLOCKS_PER_SEGMENT + index
            obf_data += public_key[block_idx]

        # Write obfuscated file
        output_path = file_path + '.obf'
        with open(output_path, 'wb') as f:
            f.write(obf_data)

        logging.info(f"Obfuscated {original_len} bytes -> {len(obf_data)} bytes")
        return output_path

    except Exception as e:
        logging.error(f"Obfuscation failed: {e}")
        raise

def recover_file(file_path):
    try:
        # Load private key (same as public key)
        private_key = []
        with open(os.path.join(KEY_DIR, 'private_key.bin'), 'rb') as f:
            while True:
                block = f.read(KEY_BLOCK_SIZE)
                if not block:
                    break
                private_key.append(block)
        if len(private_key) != KEY_SIZE:
            raise ValueError("Private key size mismatch")

        # Read obfuscated file
        with open(file_path, 'rb') as f:
            raw_data = f.read()

        # Extract original length
        original_len = int.from_bytes(raw_data[:4], 'big')
        cipher_blocks = raw_data[4:]

        # Process blocks
        recovered_data = bytearray()
        for i in range(0, len(cipher_blocks), KEY_BLOCK_SIZE):
            chunk = cipher_blocks[i:i+KEY_BLOCK_SIZE]
            try:
                block_idx = private_key.index(chunk)
            except ValueError:
                continue  
            #Skip unrecognized blocks

            # Reverse segment/index calculation
            segment = block_idx // BLOCKS_PER_SEGMENT
            index = block_idx % BLOCKS_PER_SEGMENT
            original_byte = (segment << 6) | index
            recovered_data.append(original_byte)

            # Stop when original length is reached
            if len(recovered_data) >= original_len:
                break

        # Truncate to exact original length
        recovered_data = recovered_data[:original_len]

        # Write recovered file
        output_path = file_path.replace('.obf', '.rec')
        with open(output_path, 'wb') as f:
            f.write(recovered_data)

        logging.info(f"Recovered {len(recovered_data)} bytes")
        return output_path

    except Exception as e:
        logging.error(f"Recovery failed: {e}")
        raise
