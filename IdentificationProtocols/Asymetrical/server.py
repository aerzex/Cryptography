import socket
import os
import sys
import secrets
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.RSA import encrypt, decrypt, load_private_key_from_pfx, load_public_key_from_pem
from HashFunctions.SHA2 import sha256_function

PORT = 55560

def main():
    # generate_keys(1024, "P@ssw0rd", "IdentificationProtocols/Asymetrical/rsa_keys/server/")
    scrt_key = load_private_key_from_pfx("IdentificationProtocols/Asymetrical/rsa_keys/server/scrt_key.pfx", "P@ssw0rd")
    identifier_a = "UserA"
    pub_key = load_public_key_from_pem("IdentificationProtocols/Asymetrical/rsa_keys/client/pub_key.pem")
    identifier_b = "UserB"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', PORT))
    server.listen(1)
    print("Server (User B) listening on port", PORT)

    while True:
        conn, addr = server.accept()
        with conn:
            print(f"Connected by {addr}")

            try:
                data = conn.recv(4096)
                if not data:
                    print("No data received")
                    continue

                message = json.loads(data.decode())
                hash_value = message["Hash_value"]
                ID_a = message["Identifier_A"]
                encrypted_hex = message["EncryptedHex"]
                encrypted = bytes.fromhex(encrypted_hex)
                decrypted = decrypt(encrypted, scrt_key).decode()
                z = decrypted[len(ID_a):]
                expected_hash = sha256_function(int(z)).hex()

                if ID_a != identifier_a or hash_value != expected_hash:
                    print("Identification failed!")
                    conn.sendall(json.dumps({"status": "Identification failed!"}).encode())
                    continue

                print("Identification successful!")
                z_b = str(secrets.randbelow(999999) + 100000)
                combined_hash = sha256_function(str(z) + z_b)
                encrypted_value = encrypt(ID_a + str(z) + identifier_b + z_b, pub_key)
                response = {
                    "status": "Identification successful!",
                    "Hash_value": combined_hash.hex(),
                    "EncryptedHex": encrypted_value.hex()
                }
                conn.sendall(json.dumps(response).encode())

            except Exception as e:
                error_msg = f"Identification failed: {e}"
                print(error_msg)
                conn.sendall(json.dumps({"status": error_msg}).encode())

if __name__ == "__main__":
    main()
