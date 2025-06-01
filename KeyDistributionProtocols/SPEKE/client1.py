import socket
import json
import struct
import secrets
import sys
import os

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_generate_prime, algorithm_all_divisors, algorithm_Miller_Rabin_test, algorithm_fast_pow
from HashFunctions.SHA2 import sha512_function, sha256_function

HOST = 'localhost'
PORT = 55563

def generate_users_keys(size, password, hash_function=sha512_function, filename="KeyDistributionProtocols/SPEKE/speke_keys/"):
    p = algorithm_generate_prime(size)
    password_bytes = password.encode('utf-8')
    hash_value = hash_function(password_bytes) 
    g = int.from_bytes(hash_value, 'big') % p
    users_keys = {
        "prime": p,
        "g": g
    }
    with open(filename + "users_keys.json", "w", encoding="utf-8") as json_file:
        json.dump(users_keys, json_file, ensure_ascii=False, indent=4)
    return p, g

def main():
    
    password = "P@ssw0rd"  
    hash_function = sha512_function
    filename = "KeyDistributionProtocols/SPEKE/speke_keys/"
  
    # generate_users_keys(1024, password, hash_function)
    
    try:

        with open(filename + "users_keys.json", "r", encoding="utf-8") as json_file:
            users_keys = json.load(json_file)
        p, g = users_keys["prime"], users_keys["g"]
        print(f"Loaded parameters: p={p}, g={g}")

        x = secrets.randbelow(p - 4) + 2
        alpha = algorithm_fast_pow(g, x, p)
        print(f"Generated x={x}, alpha={alpha}")

        with open("KeyDistributionProtocols/SPEKE/speke_keys/client1_keys.txt", "w", encoding="utf-8") as f:
            f.write(f"private_x={x}\npublic_alpha={alpha}\n")

        message = {
            "type": "public_key",
            "p": str(p), 
            "value": str(alpha)
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

            beta = int(response["value"])

            k = algorithm_fast_pow(beta, x, p)
            with open("KeyDistributionProtocols/SPEKE/speke_keys/secret_client1.txt", "w") as file:
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