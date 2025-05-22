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

with open("IdentificationProtocols/Fiat_Shamir/fiat_shamir_keys/pub_key.json") as f:
    pub_key = json.load(f)

N = pub_key["N"]
y = pub_key["y"]
identifier = "Verifier"

ITERATIONS = 10

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    with conn:
        print(f"[Server] Connected by {addr}")
        success = True

        for i in range(ITERATIONS):
            data = conn.recv(2048)
            r = json.loads(data.decode())["r"]
            print(f"[{i+1}] Received r")

            a = secrets.randbits(1) 
            conn.sendall(json.dumps({"a": a}).encode())
            print(f"[{i+1}] Sent a: {a}")

            data = conn.recv(2048)
            s = json.loads(data.decode())["s"]
            print(f"[{i+1}] Received y")

            left = algorithm_fast_pow(s, 2, N) * algorithm_fast_pow(y, a, N) % N
            right = r
            print(f"[{i+1}] Check: {left} == {right}")

            if left != right:
                success = False

        result = "Identification successful!" if success else "Identification failed!"
        conn.sendall(result.encode())
        print("Final Result:", result)

if __name__ == "__main__":
    main()
