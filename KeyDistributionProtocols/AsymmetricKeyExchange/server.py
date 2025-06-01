import socket
import struct
import json
import os
import sys
from datetime import datetime
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from DigitalSignatures.RSA import verify_client_signature
from CipherSystems.RSA import load_private_key_from_pfx, load_public_key_from_pem, decrypt
from HashFunctions.SHA2 import sha512_function, sha256_function

HOST = '127.0.0.1'
PORT = 55562

def server():
    client_public_key = load_public_key_from_pem("DigitalSignatures/RSA/rsa_keys/client/pub_key.pem")
    server_scrt_key = load_private_key_from_pfx("DigitalSignatures/RSA/rsa_keys/server/scrt_key.pfx", "P@ssw0rd")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                try:
                    msg_len = struct.unpack('!I', conn.recv(4))[0]
                    encrypted_message = conn.recv(msg_len)
                    decrypted = decrypt(encrypted_message, server_scrt_key)
                    signature = json.loads(decrypted.decode('utf-8'))
                    
                    is_valid, message = verify_client_signature(signature, client_public_key)
                    
                    data_bytes = bytes.fromhex(signature["EncapsulatedContentInfo"]["OCTET STRING"])
                    data = json.loads(data_bytes.decode('utf-8'))
                    
                    timestamp = data["timestamp"]
                    received_time = datetime.fromisoformat(timestamp.replace('Z', ''))
                    current_time = datetime.utcnow()
                    time_diff = (current_time - received_time).total_seconds()
                    
                    if is_valid and abs(time_diff) < 60:
                        with open("KeyDistributionProtocols/AsymmetricKeyExchange/secret.txt", "w", encoding="utf-8") as file:
                            file.write(data["secret"])

                        response = {
                            "status": "success",
                            "message": "Signature verified, secret key saved"
                        }
                        print("Signature verified, secret key saved")
                    else:
                        response = {
                            "status": "error",
                            "message": f"Invalid signature/timestamp: {message}"
                        }
                        print(f"Invalid signature/timestamp: {message}")
                    
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)
                
                except Exception as e:
                    print(f"Error handling connection: {e}")
                    response = {
                        "status": "error",
                        "message": f"Server error: {str(e)}"
                    }
                    response_bytes = json.dumps(response, ensure_ascii=False).encode('utf-8')
                    conn.sendall(struct.pack('!I', len(response_bytes)) + response_bytes)

if __name__ == "__main__":
    server()