import os
import sys
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.ElGamal import load_public_key, load_private_key, generate_keys
from HashFunctions.SHA2 import sha256_function, sha512_function, convert_to_bytes
from HashFunctions.Streebog import streebog_256, streebog_512
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow, algorithm_comprasion, algorithm_euclid_extended
import secrets

def sign_data_client(data, scrt_key, pub_key, hash_function):
    data = convert_to_bytes(data)
    hash_value = hash_function(data)
    hex_hash_value = hash_value.hex()
    hash_encrypted = signature_encrypt(hash_value, scrt_key, pub_key)
    bytes_hash_encrypted = convert_to_bytes(hash_encrypted[0]) + convert_to_bytes(hash_encrypted[1])

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
            "SignatureValue": hash_encrypted, 
            "UnsignedAttributes": { 
                "OBJECT IDENTIFIER": "signature-time-stamp",
                "SET OF AttributeValue": {
                    "hash": hash_function(data + bytes_hash_encrypted).hex(),  
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

def signature_encrypt(hash_value: bytes, scrt_key, pub_key):
    a, p = scrt_key["a"], scrt_key["prime"]
    alpha = pub_key["alpha"]
    sigma = 0
    gamma = 0
    while not sigma:
        while True:
            r = secrets.randbelow(p - 2) + 1
            if algorithm_euclid_extended(r, p - 1)[0] == 1:
                break
        gamma = algorithm_fast_pow(alpha, r, p)
    
        int_hash_value = int.from_bytes(hash_value, 'big')
        r_rev = algorithm_comprasion(r, 1, p - 1)[0]
        sigma = ((int_hash_value - (a * gamma))* r_rev) % (p - 1)

    return [gamma, sigma]

def verify_sign(hash_value, sign_value, pub_key):
    alpha, beta, p = pub_key["alpha"], pub_key["beta"], pub_key["prime"]
    gamma, sigma = sign_value[0], sign_value[1]
    int_hash_value = int.from_bytes(hash_value, 'big')
    left = algorithm_fast_pow(beta, gamma, p) * algorithm_fast_pow(gamma, sigma, p) % p
    right = algorithm_fast_pow(alpha, int_hash_value, p)

    if left == right:
        return True
    else:
        return False
 

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
        
        verify = verify_sign(message_digest, signature_value, public_key)

        if not verify:
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

        client_signature = convert_to_bytes(signer_info["SignatureValue"][0]) + convert_to_bytes(signer_info["SignatureValue"][1])
        expected_hash = hash_function(hash_function(data + client_signature).hex() + timestamp)

        
        is_valid = verify_sign(expected_hash, center_signature, certificate)
        
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