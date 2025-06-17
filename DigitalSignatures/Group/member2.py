import socket
import struct
import json
import secrets
import select
from group_signature import sign_data_client, algorithm_fast_pow, generate_member_keys, load_key, sha256_function

HOST = '127.0.0.1'
PORT = 55556

def client():
    leader_pub_key = load_key("DigitalSignatures/Group/group_keys/leader_public_key.json")
    p, alpha, N = leader_pub_key["Prime"], leader_pub_key["Alpha"], leader_pub_key["N"]

    try:
        pub_key = load_key("DigitalSignatures/Group/group_keys/member_1_public_key.json")
        scrt_key = load_key("DigitalSignatures/Group/group_keys/member_1_secret_key.json")
        t = secrets.randbelow(N)
        r = algorithm_fast_pow(alpha, t, p)

        data = {
            "MemberPublicKey": pub_key,
            "R": r,
            "T": t,
            "Message": "random data"
        }
        message = json.dumps(data, ensure_ascii=False).encode('utf-8')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            sock.sendall(struct.pack('!I', len(message)) + message)

            timeout = 10  
            ready = select.select([sock], [], [], timeout)
            if ready[0]:
                length_bytes = sock.recv(4)
                if not length_bytes:
                    print("Server closed connection unexpectedly")
                    return
                length = struct.unpack('!I', length_bytes)[0]
                response_bytes = sock.recv(length)
                if not response_bytes:
                    print("Server sent empty response")
                    return
                response = json.loads(response_bytes.decode('utf-8'))
                print(f"Response from leader: {response}")

                if response["status"] == "success":
                    lamda = response["lamda"]
                    R = response["R"]
                    E = response["E"]
                    s = (t + scrt_key["x"] * lamda * E) % N
                    data = {"s": s}
                    message = json.dumps(data, ensure_ascii=False).encode('utf-8')
                    sock.sendall(struct.pack('!I', len(message)) + message)

                    length = struct.unpack('!I', sock.recv(4))[0]
                    response_bytes = sock.recv(length)
                    response = json.loads(response_bytes.decode('utf-8'))
                    print(f"Final response from leader: {response}")
            else:
                print("No response from server within 10 seconds")

    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    client()