import socket
import struct
import json

from elgamal_signature import sign_data_client, serialize_signature, load_private_key, sha256_function, verify_center_signature

HOST = '127.0.0.1'
PORT = 55555

def client():
    data = "Random data"
    filename = "DigitalSignatures/RSA/rsa_keys/client/scrt_key.pfx"
    password = "P@ssw0rd"
    try:
        scrt_key = load_private_key(filename, password)
        signature = sign_data_client(data, scrt_key, sha256_function)
        message = serialize_signature(signature)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(struct.pack('!I', len(message)) + message)

            length = struct.unpack('!I', s.recv(4))[0]
            response = s.recv(length)
            response_data = json.loads(response.decode('utf-8'))
            print("Response from server:", response_data)
            
            verify_center_signature(response_data)
    
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    client()