import socket
import os
import sys

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from HashFunctions.SHA2 import sha256_function, sha512_function

HOST = 'localhost'
PORT = 55561

def compute_hash_chain(s, k, hash_function):
    try:
        result = s.encode('ascii')
        for _ in range(k):
            result = hash_function(result)
        return result
    except Exception as e:
        raise ValueError(f"Error in hash chain computation: {e}")

def register(a, s, n, hash_function, host, port):
    try:
        p_0_bytes = compute_hash_chain(s, n, hash_function)
        p_0_hex = p_0_bytes.hex()
        message = f"REGISTER|{a}|{hash_function.__name__}|{p_0_hex}"
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(message.encode('ascii'))
            response = s.recv(1024).decode('ascii')
            print(f"Registration response: {response}")
            return response == "REGISTERED"
    except Exception as e:
        print(f"Registration error: {e}")
        return False

def authenticate(a, s, n, i, hash_function, host, port):
    if i > n:
        print("Exceeded maximum authentications")
        return False
    
    try:
        p_i_bytes = compute_hash_chain(s, n - i, hash_function)
        p_i_hex = p_i_bytes.hex()
        message = f"AUTH|{i}|{p_i_hex}|{a}"
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(message.encode('ascii'))
            response = s.recv(1024).decode('ascii')
            print(f"Authentication response: {response}")
            return response == "AUTH_SUCCESS"
    except Exception as e:
        print(f"Authentication error: {e}")
        return False

def main():

    
    try:
        a = input("Enter your identifier: ")
        s = input("Enter secret password: ")
        
        n = int(input("Enter number of authentications (n): "))
        if n <= 0:
            raise ValueError("n must be a positive integer")
        
        hash_type = input("Choose hash type (sha256/sha512): ").lower()
        if hash_type == "sha256":
            hash_function = sha256_function
        elif hash_type == "sha512":
            hash_function = sha512_function
        else:
            raise ValueError("Invalid hash type. Use 'sha256' or 'sha512'.")
        
        if register(a, s, n, hash_function, HOST, PORT):
            i = 1
            while i <= n:
                input(f"Press Enter to attempt authentication {i}/{n}...")
                if authenticate(a, s, n, i, hash_function, HOST, PORT):
                    i += 1
                else:
                    print("Authentication failed, try again.")
    except ValueError as e:
        print(f"Input error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()