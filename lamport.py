import os
import hashlib
import secrets
import logging

KEY_DIR = 'keys/'
os.makedirs(KEY_DIR, exist_ok=True)

logging.basicConfig(filename='logs/app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def generate_keys():
    try:
        logging.info("Key generation initiated.")

        # Generate 256 pairs of random 256-bit private keys
        private_key = [[secrets.token_bytes(32) for _ in range(256)] for _ in range(2)]

        # Generate public key by hashing each private key
        public_key = [[hashlib.sha256(private_key[i][j]).digest() for j in range(256)] for i in range(2)]

        private_key_path = os.path.join(KEY_DIR, "private_key.bin")
        public_key_path = os.path.join(KEY_DIR, "public_key.bin")

        # Save the private key
        with open(private_key_path, 'wb') as pk_file:
            for part in private_key:
                for byte_data in part:
                    pk_file.write(byte_data)

        # Save the public key
        with open(public_key_path, 'wb') as pub_file:
            for part in public_key:
                for hash_data in part:
                    pub_file.write(hash_data)

        logging.info("Keys generated successfully. Private key saved at %s, Public key saved at %s", private_key_path, public_key_path)

        return private_key_path, public_key_path

    except Exception as e:
        logging.error("Error generating keys: %s", str(e))
        raise


def sign_file(file_path):
    try:
        with open('keys/private_key.bin', 'rb') as pk_file:
            private_key = [pk_file.read(32) for _ in range(512)]

        with open(file_path, 'rb') as f:
            file_data = f.read()
            hashed_data = hashlib.sha256(file_data).digest()

        signature = []
        for i in range(256):
            bit = (hashed_data[i // 8] >> (7 - (i % 8))) & 1
            signature.append(private_key[bit * 256 + i])

        signature_path = os.path.join('keys', 'signature.bin')
        with open(signature_path, 'wb') as sig_file:
            for chunk in signature:
                sig_file.write(chunk)

        logging.info(f"File signed successfully. Signature saved at {signature_path}")
        return signature_path

    except Exception as e:
        logging.error(f"Error signing file: {str(e)}")
        raise e
    

def verify_signature(file_path, signature_path):
    try:
        # Load the public key
        with open('keys/public_key.bin', 'rb') as pub_file:
            public_key = [pub_file.read(32) for _ in range(512)]

        # Read and hash the file data
        with open(file_path, 'rb') as f:
            file_data = f.read()
            hashed_data = hashlib.sha256(file_data).digest()

        # Read the signature
        with open(signature_path, 'rb') as sig_file:
            signature = [sig_file.read(32) for _ in range(256)]

        # Verification process
        for i in range(256):
            bit = (hashed_data[i // 8] >> (7 - (i % 8))) & 1
            public_hash = hashlib.sha256(signature[i]).digest()

            # Debugging: Print the bit, hash, and the corresponding public key entry
            logging.info(f"Bit: {bit}, Public Hash: {public_hash.hex()}, Expected Public Key: {public_key[bit * 256 + i].hex()}")

            if public_hash != public_key[bit * 256 + i]:
                logging.warning(f"Signature verification failed at index {i}.")
                return False

        logging.info("Signature verification successful.")
        return True

    except Exception as e:
        logging.error(f"Error verifying signature: {str(e)}")
        raise e
