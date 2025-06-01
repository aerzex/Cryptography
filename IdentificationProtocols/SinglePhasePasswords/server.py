import socket
import os
import sys

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from HashFunctions.SHA2 import sha256_function, sha512_function

HOST = 'localhost'
PORT = 55561

users = {}

def handle_registration(a, hash_type, p_0_hex):
    try:
        if hash_type not in ["sha256_function", "sha512_function"]:
            return "Invalid hash type"
        
        p_0_bytes = bytes.fromhex(p_0_hex)
        users[a] = {'i': 0, 'p_prev': p_0_bytes, 'hash_type': hash_type}
        return "REGISTERED"
    except ValueError:
        return "Invalid p_0_hex formatorch"
    except Exception as e:
        return f"Registration error: {e}"

def handle_authentication(a, i_str, p_i_hex):
    if a not in users:
        return "AUTH_FAIL: User not found"
    
    user = users[a]
    try:
        i = int(i_str)
        if i != user['i'] + 1:
            return "AUTH_FAIL: Incorrect attempt number"
        
        p_i_bytes = bytes.fromhex(p_i_hex)
        hash_function = sha256_function if user["hash_type"] == "sha256_function" else sha512_function
        h_p_i = hash_function(p_i_bytes)
        
        if h_p_i == user['p_prev']:
            user['i'] = i
            user['p_prev'] = p_i_bytes
            return "AUTH_SUCCESS"
        else:
            return "AUTH_FAIL: Hash mismatch"
    except ValueError:
        return "AUTH_FAIL: Invalid data format"
    except Exception as e:
        return f"AUTH_FAIL: {e}"

def main():

    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = server.accept()
            with conn:
                print(f"Connected by {addr}")
                data = conn.recv(1024).decode('ascii')
                if not data:
                    continue
                
                parts = data.split('|')
                if parts[0] == "REGISTER" and len(parts) == 4:
                    _, a, hash_type, p_0_hex = parts
                    response = handle_registration(a, hash_type, p_0_hex)
                elif parts[0] == "AUTH" and len(parts) == 4:
                    _, i_str, p_i_hex, a = parts
                    response = handle_authentication(a, i_str, p_i_hex)
                else:
                    response = "Invalid command"
                
                conn.sendall(response.encode('ascii'))
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main()