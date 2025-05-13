import socket
import struct
import json
import time

from elgamal_signature import load_public_key, verify_client_signature, generate_keys, load_private_key, signature_encrypt, sha256_function, sha512_function, streebog_256, streebog_512

HOST = '127.0.0.1'
PORT = 55555


def server():
    generate_keys(1024, "DigitalSignatures/ElGamal/elgamal_keys/server/")
    client_public_key = load_public_key("DigitalSignatures/ElGamal/elgamal_keys/client/pub_key.json")

    server_pub_key = load_public_key("DigitalSignatures/ElGamal/elgamal_keys/server/pub_key.json")
    server_scrt_key = load_private_key("DigitalSignatures/ElGamal/elgamal_keys/server/scrt_key.json", "P@ssw0rd")
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
                    length = struct.unpack('!I', conn.recv(4))[0]
                    message_bytes = conn.recv(length)
                    signature = json.loads(message_bytes.decode('utf-8'))

                    print(f"Request from client: {signature}")
                    
                    is_valid, message = verify_client_signature(signature, client_public_key)
                    
                    signer_info = signature["SignerInfos"]
                    hash_function = globals()[signer_info["DigestAlgorithmIdentifier"]]

                    data_hex = signature["EncapsulatedContentInfo"]["OCTET STRING"]
                    data = bytes.fromhex(data_hex)

                    hex_hash_encrypted = signer_info["SignatureValue"]
                    hash_encrypted = bytes.fromhex(hex_hash_encrypted)
                    
                    if is_valid:
                        timestamp = time.strftime("%y%m%d%H%M%SZ", time.gmtime())
                        signer_info["UnsignedAttributes"]["SET OF AttributeValue"]["timestamp"]["UTCTime"] = timestamp
                        
                        timestamp_sign = signature_encrypt(hash_function(hash_function(data + hash_encrypted).hex() + timestamp), server_scrt_key).hex()
                        signer_info["UnsignedAttributes"]["SET OF AttributeValue"]["signature"] = timestamp_sign
                        signer_info["UnsignedAttributes"]["SET OF AttributeValue"]["certificate"] = server_pub_key

                        response = {
                            "status": "success",
                            "signature": signature
                        }
                    else:
                        response = {
                            "status": "error",
                            "message": f"Invalid signature: {message}"
                        }
                    

                    
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