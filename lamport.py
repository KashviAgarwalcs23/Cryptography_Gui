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
        logging.info("File signing initiated for %s", file_path)
        private_key_path = os.path.join(KEY_DIR, "private_key.bin")

        if not os.path.exists(private_key_path):
            raise FileNotFoundError("Private key not found. Generate keys first.")

        # Read the private key
        with open(private_key_path, 'rb') as pk_file:
            private_key = [pk_file.read(32 * 256), pk_file.read(32 * 256)]

        # Hash the file content
        with open(file_path, 'rb') as file:
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()

        # Sign the file
        signature = b""
        for i, char in enumerate(file_hash):
            index = int(char, 16)
            signature += private_key[index // 16][index % 16]

        # Save the signature
        signature_path = os.path.join(KEY_DIR, "signature.bin")
        with open(signature_path, 'wb') as sig_file:
            sig_file.write(signature)

        logging.info("File signed successfully. Signature saved at %s", signature_path)
        return signature_path

    except Exception as e:
        logging.error("Error signing file: %s", str(e))
        raise

