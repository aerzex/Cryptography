import socket
import os
from datetime import datetime
from two_pass_identification import encrypt_message, decrypt_message

KEY = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'
PORT = 55558

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
                if len(parts) != 5: 
                    raise ValueError("Invalid message format")
                
                identifier_a, identifier_b, auth_type, auth_value, message = parts
                
                if identifier_b != "UserB":
                    print("Identification failed: Incorrect recipient identifier")
                    conn.sendall(encrypt_message("Identification failed: Incorrect recipient", KEY))
                    continue
                
                if auth_type == "timestamp":
                    received_time = datetime.fromisoformat(auth_value.replace('Z', ''))
                    current_time = datetime.utcnow()
                    time_diff = (current_time - received_time).total_seconds()
                    if abs(time_diff) > 60:
                        print("Identification failed: Timestamp expired")
                        conn.sendall(encrypt_message("Identification failed: Timestamp expired", KEY))
                        continue
                    print(f"Received timestamp: {auth_value}")
                else:
                    print(f"Received random number: {auth_value}")
                
                print(f"Message from {identifier_a}: {message}")
                print("Identification successful!")
                M3 = "Server message"
                response = f"UserB|UserA|Authenticated|{auth_value}|{M3}"
                M4 = encrypt_message(response, KEY)
                conn.sendall(M4)
                
            except Exception as e:
                print(f"Identification failed: {e}")
                conn.sendall(encrypt_message(f"Identification failed: {e}", KEY))

if __name__ == "__main__":
    main()