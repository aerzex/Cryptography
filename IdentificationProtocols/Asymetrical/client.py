import socket
import secrets
import os
import sys
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.RSA import encrypt, load_public_key_from_pem
from HashFunctions.Streebog import streebog_256

HOST = 'localhost'
PORT = 55560

def main():
    pub_key = load_public_key_from_pem("IdentificationProtocols/Asymetrical/rsa_keys/pub_key.pem")
    
    identifier_a = "UserA"
    z = secrets.randbelow(999999) + 100000
    encrypted_value = encrypt(identifier_a + str(z))
    
    message = {
        "Hash_value": streebog_256(z).hex(),
        "Identifier_A": identifier_a,
        "EncryptedHex": encrypted_value.hex()
    }

    try:    
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(message)
            print(f"Sent to server: {message}")

            response = s.recv(1024)
            if not response:
                print("No response from server")
                return
            print(f"server response: {response}")


    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()