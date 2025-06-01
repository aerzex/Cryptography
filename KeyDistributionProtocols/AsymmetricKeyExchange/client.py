import socket
import os
import sys
import time
import json
import struct

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from DigitalSignatures.RSA import sign_data_client, serialize_signature, verify_center_signature
from CipherSystems.RSA import load_private_key_from_pfx, load_public_key_from_pem, encrypt
from HashFunctions.SHA2 import sha256_function, sha512_function

HOST = '127.0.0.1'
PORT = 55562

def client():
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "secret": "password",
        "identifierB": "UserB",
    }
    data_dump = json.dumps(data)
    
    password = "P@ssw0rd"
    try:
        server_pub_key = load_public_key_from_pem("DigitalSignatures/RSA/rsa_keys/server/pub_key.pem")
        scrt_key = load_private_key_from_pfx("DigitalSignatures/RSA/rsa_keys/client/scrt_key.pfx", password)
        signature = sign_data_client(data_dump, scrt_key, sha512_function)

        message_serialized = serialize_signature(signature)

        encrypted_message = encrypt(message_serialized, server_pub_key)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(struct.pack('!I', len(encrypted_message)) + encrypted_message)


            response_len = struct.unpack('!I', s.recv(4))[0]
            response = s.recv(response_len)
            print("Response from server:", json.loads(response.decode('utf-8')))
    
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    client()