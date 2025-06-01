import json
import socket
import os
import sys
import secrets
import struct

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from DigitalSignatures.RSA import verify_client_signature, sign_data_client, serialize_signature
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow
from CipherSystems.RSA import load_private_key_from_pfx, load_public_key_from_pem
from HashFunctions.SHA2 import sha512_function

HOST = 'localhost'
PORT = 55563

def main():
    try:
        client1_pub_key = load_public_key_from_pem("DigitalSignatures/RSA/rsa_keys/client/pub_key.pem")
        client2_scrt_key = load_private_key_from_pfx("DigitalSignatures/RSA/rsa_keys/server/scrt_key.pfx", "P@ssw0rd")
        print("RSA keys loaded successfully")
    except Exception as e:
        print(f"Error loading RSA keys: {e}")
        return

    filename = "KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/users_keys.json"

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

                alpha_str = client_data["value"]
                signature_client1 = client_data["signature"]

                is_valid, message = verify_client_signature(signature_client1, client1_pub_key)
                if not is_valid:
                    response = {
                        "status": "error",
                        "message": f"Invalid signature: {message}"
                    }
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                    print(f"Sent response: {response}")
                    return

                with open(filename, "r", encoding="utf-8") as json_file:
                    users_keys = json.load(json_file)

                p, g = users_keys["prime"], users_keys["g"]
                y = secrets.randbelow(p - 4) + 2
                beta = algorithm_fast_pow(g, y, p)
                print(f"Generated y={y}, beta={beta}")

                with open("KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/client2_keys.txt", "w", encoding="utf-8") as f:
                    f.write(f"private_y={y}\npublic_beta={beta}\n")

                beta_str = str(beta)
                signature = sign_data_client(beta_str, client2_scrt_key, sha512_function)
                response = {
                    "status": "success",
                    "value": beta_str,
                    "signature": signature
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                print(f"Sent response: {response}")

                alpha = int(alpha_str)
                k = algorithm_fast_pow(alpha, y, p)
                with open("KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/secret_client2.txt", "w") as file:
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