import socket
import random
from three_pass_identification import encrypt_message, decrypt_message

KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
PORT = 55559

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', PORT))
    server.listen(1)
    print("Server (User B) listening on port", PORT)

    while True:
        conn, addr = server.accept()
        with conn:
            print(f"Connected by {addr}")
            
            try:
                data = conn.recv(1024)
                if not data:
                    print("No data received")
                    continue
                
                decrypted = decrypt_message(data, KEY)
                parts = decrypted.split('|')
                if len(parts) != 4:
                    raise ValueError("Invalid message format")
                
                identifier_a, identifier_b, random_a, message = parts
                if identifier_b != "UserB":
                    print("Identification failed: Incorrect recipient identifier")
                    conn.sendall(encrypt_message("Identification failed: Incorrect recipient", KEY))
                    continue
                
                print(f"Received from {identifier_a}: random number = {random_a}, message = {message}")

                random_b = str(random.randint(100000, 999999))
                response_message = "OK"
                response = f"{identifier_b}|{identifier_a}|{random_b}|{random_a}|{response_message}"
                encrypted_response = encrypt_message(response, KEY)
                conn.sendall(encrypted_response)
                print(f"Sent to client: {response}")

                final_data = conn.recv(1024)
                if not final_data:
                    print("No final message received")
                    continue
                
                final_decrypted = decrypt_message(final_data, KEY)
                final_parts = final_decrypted.split('|')
                if len(final_parts) != 3 or final_parts[0] != identifier_a or final_parts[1] != identifier_b or final_parts[2] != random_b:
                    print("Identification failed: Invalid final message")
                    conn.sendall(encrypt_message("Identification failed: Invalid final message", KEY))
                    continue
                
                print("Identification successful!")

            except Exception as e:
                print(f"Identification failed: {e}")
                conn.sendall(encrypt_message(f"Identification failed: {e}", KEY))

if __name__ == "__main__":
    main()