import socket
import os
import time
import random
from two_pass_identification import encrypt_message, decrypt_message

KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
HOST = 'localhost'
PORT = 55558

def main():
    identifier_a = "UserA"
    identifier_b = "UserB"
    auth_choice = input("Choose authentication method (timestamp/random): ").lower()
    M1 = input("Enter message: ")
    
    if auth_choice == "timestamp":
        auth_value = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        auth_type = "timestamp"
    else:
        auth_value = str(random.randint(100000, 999999))
        auth_type = "random"

    plaintext = f"{identifier_a}|{identifier_b}|{auth_type}|{auth_value}|{M1}"

    try:
        M2 = encrypt_message(plaintext, KEY)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(M2)

            response = s.recv(1024)
            if not response:
                print("No response from server")
                return

            decrypted_response = decrypt_message(response, KEY)
            print(f"Server response: {decrypted_response}")

            if "Authenticated" in decrypted_response:
                print("Identification successful!")
            else:
                print("Identification failed!")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()