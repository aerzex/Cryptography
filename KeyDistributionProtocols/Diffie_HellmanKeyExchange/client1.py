import socket
import json
import struct
import secrets
import sys
import os
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_generate_prime, algorithm_all_divisors, algorithm_Miller_Rabin_test, algorithm_fast_pow
from HashFunctions.SHA2 import sha512_function
from DigitalSignatures.RSA import serialize_signature, sign_data_client, verify_client_signature
from CipherSystems.RSA import load_private_key_from_pfx, load_public_key_from_pem

HOST = 'localhost'
PORT = 55563

def generate_users_keys(size, filename="KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/"):
    p = algorithm_generate_prime(size)
    divisors = algorithm_all_divisors(p - 1)
    prime_divisors = []
    for divisor in divisors:
        if algorithm_Miller_Rabin_test(divisor):
            prime_divisors.append(divisor)
    while True:
        g = secrets.randbelow(p - 4) + 2
        check = 1  
        for prime_divisor in prime_divisors:
            if algorithm_fast_pow(g, (p - 1) // prime_divisor, p) == 1:
                check = 0
                break
        if check:
            break

    users_keys = {
        "prime": p,
        "g": g
    }

    with open(filename + "users_keys.json", "w", encoding="utf-8") as json_file:
        json.dump(users_keys, json_file, ensure_ascii=False, indent=4)

    


def main():
    # generate_users_keys(1024)

    filename = "KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/users_keys.json"
    password = "P@ssw0rd"


    try:
        client2_pub_key = load_public_key_from_pem("DigitalSignatures/RSA/rsa_keys/server/pub_key.pem")
        client1_scrt_key = load_private_key_from_pfx("DigitalSignatures/RSA/rsa_keys/client/scrt_key.pfx", password)
        
        with open(filename, "r", encoding="utf-8") as json_file:
            users_keys = json.load(json_file)

        p, g = users_keys["prime"], users_keys["g"]
        x = secrets.randbelow(p - 4) + 2
        alpha = algorithm_fast_pow(g, x, p)

        with open("KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/client1_keys.txt", "w", encoding="utf-8") as f:
            f.write(f"private_x={x}\npublic_alpha={alpha}\n")

        alpha_str = str(alpha)
        signature = sign_data_client(alpha_str, client1_scrt_key, sha512_function)
        message = {
            "type": "public_key",
            "value": alpha_str,
            "signature": signature
        }
        message_bytes = json.dumps(message, ensure_ascii=False).encode('utf-8')
        print(f"Sending message: {message}")


        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(struct.pack('!I', len(message_bytes)) + message_bytes)

            length_bytes = s.recv(4)
            if len(length_bytes) != 4:
                raise ValueError(f"Received {len(length_bytes)} bytes for length, expected 4")
            length = struct.unpack('!I', length_bytes)[0]
            message_bytes = s.recv(length)
            response = json.loads(message_bytes.decode('utf-8'))
            print(f"Response from client2: {response}")

            if response["status"] == "error":
                print(f"Server error: {response['message']}")
                return

            beta_str = response["value"]
            signature_client2 = response["signature"]

            is_valid, message = verify_client_signature(signature_client2, client2_pub_key)
            if not is_valid:
                print(f"Invalid signature: {message}")
                return

            beta = int(beta_str)
            k = algorithm_fast_pow(beta, x, p)
            with open("KeyDistributionProtocols/Diffie_HellmanKeyExchange/diffie_hellman_keys/secret_client1.txt", "w") as file:
                file.write(str(k))
            print(f"Session key: {k}")

            response = {
                "status": "success",
                "message": "Session key generated"
            }
            print(response)

    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    main()