import socket
import struct
import json
import time

from rsa_signature import load_public_key_from_pem, signature_decrypt, sha256_function, convert_to_bytes

HOST = '127.0.0.1'
PORT = 12345

def verify_signature(signature: dict, public_key):
    try:
        signer_info = signature["SignerInfos"]
        signed_attributes = signer_info["SignedAttributes"]
        signature_value = signer_info["SignatureValue"]
        digest_algorithm = signer_info["DigestAlgorithmIdentifier"]
        hash_function = globals()[signer_info["DigestAlgorithmIdentifier"]]

        data_hex = signature["EncapsulatedContentInfo"]["OCTET STRING"]
        data = bytes.fromhex(data_hex)
        
        message_digest = hash_function(data).hex()
        
        if signed_attributes["message_digest"] != message_digest:
            return False, "Message digest mismatch"
        
        decrypted_hash = signature_decrypt(bytes.fromhex(signature_value), public_key).hex()
        
        if decrypted_hash != message_digest:
            return False, "Signature verification failed"
        
        return True, "Signature is valid"
    except Exception as e:
        return False, f"Verification error: {str(e)}"

def server():
    public_key = load_public_key_from_pem("DigitalSignatures/RSA/rsa_keys/pub_key.pem")
    
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
                    
                    is_valid, message = verify_signature(signature, public_key)
                    
                    if is_valid:
                        signature["SignerInfos"]["UnsignedAttributes"]["SET OF AttributeValue"]["timestamp"]["UTCTime"] = time.strftime(
                            "%Y%m%d%H%M%SZ", time.gmtime()
                        )
                        response = {
                            "status": "valid",
                            "message": message,
                            "signature": signature
                        }
                    else:
                        response = {
                            "status": "invalid",
                            "message": message
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