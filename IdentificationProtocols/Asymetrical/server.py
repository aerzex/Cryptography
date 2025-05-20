import socket
import os
import sys
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.RSA import encrypt, decrypt, generate_keys, load_private_key_from_pfx, load_public_key_from_pem
from HashFunctions.Streebog import streebog_256

PORT = 55560

def main():
    generate_keys(1024, "P@ssw0rd", "IdentificationProtocols/Asymetrical/rsa_keys/")
    scrt_key = load_private_key_from_pfx("IdentificationProtocols/Asymetrical/rsa_keys/scrt_key.pfx", "P@ssw0rd")
    identifier_a = "UserA"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', PORT))
    server.listen(1)
    print("Server (User B) listening on port", PORT)

    while True:
        conn, addr = server.accept()
        with conn:
            print(f"Connected by {addr}")
            
            try:
                data = conn.recv(1024)
                if not data:
                    print("No data received")
                    continue

                hash_value = data["Hash_value"]
                ID_a = data["Identifier_A"]
                encrypted_hex = data["EncryptedHex"]
                encrypted = bytes(encrypted_hex).fromhex()
                decrypted = decrypt(encrypted, scrt_key)
                z = decrypted[ID_a:]
                expected_hash = streebog_256(int(z)).hex
                if ID_a != identifier_a or hash_value != expected_hash:
                    print("Identification failed!")
                    response = "Identification failed!"
                    conn.sendall(response)

                print("Identification successful!")
                response = "Identification successful!"
                conn.sendall(response)


            except Exception as e:
                print(f"Identification failed: {e}")
                conn.sendall(f"Identification failed: {e}")

if __name__ == "__main__":
    main()
    
