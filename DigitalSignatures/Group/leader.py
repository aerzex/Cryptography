import socket
import struct
import json
import secrets
from group_signature import load_key, generate_leader_keys, sign_data_client, verify_sign, encrypt_3_part_signature, algorithm_fast_pow, algorithm_comprasion, compute_lambda_exponent, encrypt_1_part_signature, encrypt_2_part_signature, sha256_function, sha512_function, streebog_256, streebog_512

HOST = '127.0.0.1'
PORT = 55556

def server():
    # generate_leader_keys(256)
    pub_key = load_key("DigitalSignatures/Group/group_keys/leader_public_key.json")
    scrt_key = load_key("DigitalSignatures/Group/group_keys/leader_secret_key.json")
    hash_function = sha512_function
    p, alpha, N = pub_key["Prime"], pub_key["Alpha"], pub_key["N"]
    z, d = scrt_key["X"], scrt_key["PrivateExponent"]

    members_pub_keys = []
    lamda = []
    R = []
    T = []
    M = ""
    S = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen()
        print(f"Server listening on {HOST}:{PORT}")

        clients = []
        for i in range(2):
            conn, addr = sock.accept()
            print(f"Connected by {addr}")
            try:
                length = struct.unpack('!I', conn.recv(4))[0]
                message_bytes = conn.recv(length)
                data = json.loads(message_bytes.decode('utf-8'))
                print(f"Request from client: {data}")

                if data["Message"]:
                    M = data["Message"]
                    members_pub_keys.append(data["MemberPublicKey"]["y"])
                    R.append(data["R"])
                    T.append(data["T"])
                    hash_value = hash_function(M)
                    lamda_i = compute_lambda_exponent(hash_value, data["MemberPublicKey"]["y"], d, hash_function)
                    lamda.append(lamda_i)
                    clients.append((conn, data["MemberPublicKey"]["id"]))
                else:
                    response = {
                        "status": "error",
                        "message": "Server error: Needs message from member 1. Please try again later"
                    }
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                    conn.close()
            except Exception as e:
                print(f"Error handling connection: {e}")
                response = {
                    "status": "error",
                    "message": f"Server error: {str(e)}"
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                conn.close()

        try:
            U = encrypt_1_part_signature(members_pub_keys, lamda, p)
            t = secrets.randbelow(N)
            r = algorithm_fast_pow(alpha, t, p)
            T.append(t)
            R.append(r)
            E, R_sum = encrypt_2_part_signature(hash_value, R, p, U, hash_function)
            print(R_sum)

            for conn, id in clients:
                response = {
                    "status": "success",
                    "lamda": lamda[id],
                    "R": R_sum,
                    "E": E
                }
                response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)

            for conn, id in clients:
                length = struct.unpack('!I', conn.recv(4))[0]
                message_bytes = conn.recv(length)
                data = json.loads(message_bytes.decode('utf-8'))
                print(f"Request from client {id}: {data}")
                s = data["s"]
                y_i = members_pub_keys[id]
                lambda_i = lamda[id]
                y_lambda_E = algorithm_fast_pow(y_i, lambda_i * E, p)
                y_lambda_E_inv = algorithm_comprasion(y_lambda_E, 1, p)[0]  # Обратный элемент
                expected_R = (y_lambda_E_inv * algorithm_fast_pow(alpha, s, p)) % p
                if R[id] != expected_R:
                    response = {
                        "status": "error",
                        "message": "Server error: Invalid sign part S"
                    }
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                    raise TypeError(f"Invalid sign part \"S\" from member {id}")
                else:
                    S.append(s)

            s = (t + z * E) % N
            S.append(s)
            S = encrypt_3_part_signature(S, N, d)

            signature = sign_data_client(M, U, E, S, hash_function)
            is_valid, message = verify_sign(signature, pub_key)

            if is_valid:
                response = {
                    "status": "success",
                    "message": "Signature is valid",
                    "signature": signature
                }
            else:
                response = {
                    "status": "error",
                    "message": f"Invalid signature: {message}"
                }
            response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
            for conn, _ in clients:
                conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)


        except Exception as e:
            print(f"Server error: {str(e)}")
        finally:
            for conn, _ in clients:
                conn.close()

if __name__ == "__main__":
    server()