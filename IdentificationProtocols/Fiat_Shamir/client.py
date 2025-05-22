import socket
import json
import secrets
import os
import sys
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow

HOST = 'localhost'
PORT = 55561

with open("IdentificationProtocols/Fiat_Shamir/fiat_shamir_keys/scrt_key.json") as f:
    scrt_key = json.load(f)

x = scrt_key["x"]
N = scrt_key["N"]

identifier = "Prover"

ITERATIONS = 10

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for i in range(ITERATIONS):
            k = secrets.randbelow(N - 2) + 1
            r = algorithm_fast_pow(k, 2, N)
            message = {"r": r}
            s.sendall(json.dumps(message).encode())
            print(f"[{i+1}] Sent r")

            data = s.recv(1024)
            a = json.loads(data.decode())["a"]
            print(f"[{i+1}] Received a: {a}")

            S = k * algorithm_fast_pow(x, a, N) % N

            s.sendall(json.dumps({"s": S}).encode())
            print(f"[{i+1}] Sent s")

        result = s.recv(1024).decode()
        print("Result:", result)

if __name__ == "__main__":
    main()
