import os
import sys
import json

import time
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from CipherSystems.RSA import load_public_key_from_pem, load_private_key_from_pfx, generate_keys, oaep_padding_decode, oaep_padding_encode, pkcs1_v1_5_padding_decode, pkcs1_v1_5_padding_encode
from HashFunctions.SHA2 import sha256_function, sha512_function, convert_to_bytes
from HashFunctions.Streebog import streebog_256, streebog_512
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow


# generate_keys(1024, "DigitalSignatures/RSA/rsa_keys/client/")

HOST = '127.0.0.1'
PORT = 12345

def sign_data_client(data, scrt_key, hash_function):
    data = convert_to_bytes(data)
    hash_value = hash_function(data)
    hex_hash_value = hash_value.hex()
    hash_encrypted = signature_encrypt(hash_value, scrt_key)
    hex_hash_encrypted = hash_encrypted.hex()
    signature = {
        "CMSVersion": 1,
        "DigestAlgorithmIdentifiers": hash_function.__name__, 
        "EncapsulatedContentInfo": {
            "ContentType": "data",
            "OCTET STRING": data.hex() 
        },
        "CertificateSet": "",
        "RevocationInfoChoises": "",
        "SignerInfos": {
            "CMSVersion": 1,
            "SignerIdentifier": "voyager", 
            "DigestAlgorithmIdentifier": hash_function.__name__,
            "SignedAttributes": {
                "message_digest": hex_hash_value
            },
            "SignatureAlgorithmIdentifier": "RSAdsi",
            "SignatureValue": hex_hash_encrypted, 
            "UnsignedAttributes": { 
                "OBJECT IDENTIFIER": "signature-time-stamp",
                "SET OF AttributeValue": {
                    "hash": hash_function(data + hash_encrypted).hex(),  
                    "timestamp": {
                        "UTCTime": "",  
                        "GeneralizedTime": ""  
                    },
                    "signature": "",
                    "certificate": ""
                }
            }
        }
    }
    return signature

def signature_encrypt(message, scrt_key, padding_type="oaep"):
    N = scrt_key["prime1"] * scrt_key["prime2"]

    data_bytes = convert_to_bytes(message)
    int_block = int.from_bytes(data_bytes, 'big')
    enc_block = algorithm_fast_pow(int_block, scrt_key["privateExponent"], N)
    encrypted_bytes = convert_to_bytes(enc_block)

    return encrypted_bytes

def signature_decrypt(enc_message: bytes, pub_key, padding_type="oaep"):
    N = pub_key["SubjectPublicKeyInfo"]["N"]

    dec_m = algorithm_fast_pow(int.from_bytes(enc_message, 'big'), pub_key["SubjectPublicKeyInfo"]["publicExponent"], N)
    bytes_m = convert_to_bytes(dec_m)

    return bytes_m

def serialize_signature(signature):
    message = json.dumps(signature, ensure_ascii=False)
    return message.encode('utf-8')

def verify_client_signature(signature: dict, public_key):
    try:
        signer_info = signature["SignerInfos"]
        signed_attributes = signer_info["SignedAttributes"]
        signature_value = signer_info["SignatureValue"]
        hash_function = globals()[signer_info["DigestAlgorithmIdentifier"]]

        data_hex = signature["EncapsulatedContentInfo"]["OCTET STRING"]
        data = bytes.fromhex(data_hex)
        
        message_digest = hash_function(data)
        
        
        if signed_attributes["message_digest"] != message_digest.hex():
            return False, "Message digest mismatch"
        
        decrypted_hash = signature_decrypt(bytes.fromhex(signature_value), public_key)
        
        if decrypted_hash != message_digest:
            return False, "Signature verification failed"
        
        return True, "Signature is valid"
    except Exception as e:
        return False, f"Verification error: {str(e)}"


def verify_center_signature(response_data):
    try:
        if response_data.get("status") != "success":
            print(f"Server error: {response_data.get('message', 'No message')}")
            return False
        
        signature = response_data["signature"]
        signer_info = signature["SignerInfos"]
        unsigned_attrs = signer_info["UnsignedAttributes"]["SET OF AttributeValue"]
        hash_function = globals()[signer_info["DigestAlgorithmIdentifier"]]

        timestamp = unsigned_attrs["timestamp"]["UTCTime"]
        center_signature = unsigned_attrs["signature"]
        certificate = unsigned_attrs["certificate"]
        hash_algorithm = signer_info["DigestAlgorithmIdentifier"]
        
        data_hex = signature["EncapsulatedContentInfo"]["OCTET STRING"]
        data = bytes.fromhex(data_hex)

        client_signature = bytes.fromhex(signer_info["SignatureValue"])
        expected_hash = hash_function(hash_function(data + client_signature).hex() + timestamp)

        center_signature = bytes.fromhex(center_signature)
        decrypted_hash = signature_decrypt(center_signature, certificate)

        
        is_valid = decrypted_hash == expected_hash
        
        print("Timestamp Authority Signature Verification Result")
        print(f"Hash Algorithm Used for Signature: {hash_algorithm}")
        print(f"Signature Algorithm: RSAdsi")
        print(f"Signature Author: Timestamp Authority")
        print(f"Signature Creation Time: {timestamp}")
        print(f"Signature is {'valid' if is_valid else 'invalid'}")
        
        return is_valid
    
    except Exception as e:
        print(f"Timestamp Authority Signature Verification Error: {e}")
        print("Timestamp Authority Signature Verification Result")
        print(f"Hash Algorithm Used for Signature: {hash_algorithm or 'unknown'}")
        print(f"Signature Algorithm: RSAdsi")
        print(f"Signature Author: Timestamp Authority")
        print(f"Signature Creation Time: {timestamp or 'unknown'}")
        print("Signature is invalid")
        return False