import json
import socket
import os
import sys
import secrets
import struct

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow
from HashFunctions.SHA2 import sha512_function, sha256_function

HOST = 'localhost'
PORT = 55563

def compute_generator(password, p, hash_function=sha512_function):
    password_bytes = password.encode('utf-8')
    hash_value = hash_function(password_bytes) 
    g = int.from_bytes(hash_value, 'big') % p
    return g

def main():
    password = "P@ssw0rd"  
    hash_function = sha512_function  
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            try:
                length_bytes = conn.recv(4)
                if len(length_bytes) != 4:
                    raise ValueError(f"Received {len(length_bytes)} bytes for length, expected 4")
                length = struct.unpack('!I', length_bytes)[0]
                message_bytes = conn.recv(length)
                client_data = json.loads(message_bytes.decode('utf-8'))
                print(f"Request from client: {client_data}")

                p = int(client_data["p"])
                alpha = int(client_data["value"])


                g = compute_generator(password, p, hash_function)
                print(f"Computed g={g} for p={p}")

                y = secrets.randbelow(p - 4) + 2
                beta = algorithm_fast_pow(g, y, p)
                print(f"Generated y={y}, beta={beta}")


                with open("KeyDistributionProtocols/SPEKE/speke_keys/client2_keys.txt", "w", encoding="utf-8") as f:
                    f.write(f"private_y={y}\npublic_beta={beta}\n")

                response = {
                    "status": "success",
                    "value": str(beta)
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                print(f"Sent response: {response}")

                k = algorithm_fast_pow(alpha, y, p)
                with open("KeyDistributionProtocols/SPEKE/speke_keys/secret_client2.txt", "w") as file:
                    file.write(str(k))  
                print(f"Session key: {k}")

            except Exception as e:
                print(f"Error handling connection: {e}")
                response = {
                    "status": "error",
                    "message": f"Server error: {str(e)}"
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)

if __name__ == "__main__":
    main()