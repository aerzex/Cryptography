import socket
import struct
import json

from rsa_signature import sign_data, serialize_signature, load_private_key_from_pfx, sha256_function

HOST = '127.0.0.1'
PORT = 12345

def client():
    data = "Random data"
    filename = "DigitalSignatures/RSA/rsa_keys/scrt_key.pfx"
    password = "P@ssw0rd"
    try:
        scrt_key = load_private_key_from_pfx(filename, password)
        signature = sign_data(data, scrt_key, sha256_function)
        message = serialize_signature(signature)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(struct.pack('!I', len(message)) + message)

            length = struct.unpack('!I', s.recv(4))[0]
            response = s.recv(length)
            response_data = json.loads(response.decode('utf-8'))
            print("Response from server:", response_data)
    
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    client()