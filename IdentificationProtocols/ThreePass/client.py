import socket
import os
import random
from three_pass_identification import encrypt_message, decrypt_message

KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
HOST = 'localhost'
PORT = 55559

def main():
    identifier_a = "UserA"
    identifier_b = "UserB"
    message = input("Enter message: ")
    random_a = str(random.randint(100000, 999999))

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            plaintext = f"{identifier_a}|{identifier_b}|{random_a}|{message}"
            encrypted = encrypt_message(plaintext, KEY)
            s.sendall(encrypted)
            print(f"Sent to server: {plaintext}")

            response = s.recv(1024)
            if not response:
                print("No response from server")
                return
            decrypted_response = decrypt_message(response, KEY)
            print(f"Server response: {decrypted_response}")

            parts = decrypted_response.split('|')
            if len(parts) != 5 or parts[0] != identifier_b or parts[1] != identifier_a or parts[3] != random_a:
                print("Identification failed: Invalid server response")
                return

            random_b = parts[2]
            response_message = parts[4]
            print(f"Received server's random number: {random_b}, message: {response_message}")

            final_message = f"{identifier_a}|{identifier_b}|{random_b}"
            encrypted_final = encrypt_message(final_message, KEY)
            s.sendall(encrypted_final)
            print(f"Sent final message: {final_message}")

            print("Identification successful!")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()