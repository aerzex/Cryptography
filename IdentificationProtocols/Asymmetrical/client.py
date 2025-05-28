import socket
import secrets
import os
import sys
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.RSA import encrypt, load_public_key_from_pem, decrypt, load_private_key_from_pfx, generate_keys
from HashFunctions.SHA2 import sha256_function

HOST = 'localhost'
PORT = 55560

def main():
    # generate_keys(1024, "pass", "IdentificationProtocols/Asymetrical/rsa_keys/client/")
    pub_key = load_public_key_from_pem("IdentificationProtocols/Asymetrical/rsa_keys/server/pub_key.pem")
    scrt_key = load_private_key_from_pfx("IdentificationProtocols/Asymetrical/rsa_keys/client/scrt_key.pfx", "pass")
    identifier_a = "UserA"
    identifier_b = "UserB"
    z = secrets.randbelow(999999) + 100000
    encrypted_value = encrypt(identifier_a + str(z), pub_key)

    message = {
        "Hash_value": sha256_function(z).hex(),
        "Identifier_A": identifier_a,
        "EncryptedHex": encrypted_value.hex()
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(json.dumps(message).encode())
            print(f"Sent to server: {message}")

            data = s.recv(4096)
            if not data:
                print("No response from server")
                return

            response = json.loads(data.decode())
            print(f"Received from server: {response}")

            hash_value = response["Hash_value"]
            encrypted_hex = response["EncryptedHex"]
            encrypted = bytes.fromhex(encrypted_hex)
            decrypted = decrypt(encrypted, scrt_key).decode()

            z_b = decrypted[len(identifier_a + str(z) + identifier_b):]
            expected_hash = sha256_function(str(z) + z_b).hex()
            if expected_hash != hash_value:
                print("Identification failed!")
                s.sendall("Identification failed!".encode())
                return

            print("Identification successful!")
            s.sendall("Identification successful!".encode())

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
