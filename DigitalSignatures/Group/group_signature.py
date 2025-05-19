import os
import sys
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from HashFunctions.SHA2 import sha256_function, sha512_function, convert_to_bytes
from HashFunctions.Streebog import streebog_256, streebog_512
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow, algorithm_comprasion, algorithm_euclid_extended, algorithm_generate_prime
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


def generate_keys(size, dir_path):
    p = algorithm_generate_prime(size)
    q = algorithm_generate_prime(size // 2)
    while((p - 1) % q == 0):
        q = algorithm_generate_prime(256)

    alpha = 0
    while True:
        h = secrets.randbelow(p - 4) + 2
        alpha = algorithm_fast_pow(h, (p - 1) // q, p)
        if alpha != 1:
            if algorithm_fast_pow(alpha, q, p) == 1:
                break
            
    x0 = secrets.randbelow(q - 2) + 1
    y0 = algorithm_fast_pow(alpha, x0, p)
    
    leader_key = [x0, y0]

    n = 2
    members_keys = []
    for i in range(n):
        xi = secrets.randbelow(q - 2) + 1
        yi = algorithm_fast_pow(alpha, xi, p)
        members_keys.append((xi, yi))

    save_keys(leader_key, members_keys, dir_path)

    
def save_keys(leader_key, members_keys, dir_path):
    os.makedirs(dir_path, exist_ok=True)

    leader_secret = {"x0": str(leader_key[0])}
    leader_public = {"y0": str(leader_key[1])}
    
    leader_secret_path = os.path.join(dir_path, "leader_secret_key.json")
    leader_public_path = os.path.join(dir_path, "leader_public_key.json")
    
    with open(leader_secret_path, 'w', encoding='utf-8') as f:
        json.dump(leader_secret, f, indent=4, ensure_ascii=False)
    with open(leader_public_path, 'w', encoding='utf-8') as f:
        json.dump(leader_public, f, indent=4, ensure_ascii=False)

    for i, (xi, yi) in enumerate(members_keys, 1):
        member_secret = {"xi": str(xi)}
        member_public = {"yi": str(yi)}
        
        member_secret_path = os.path.join(dir_path, f"member_{i}_secret_key.json")
        member_public_path = os.path.join(dir_path, f"member_{i}_public_key.json")
        
        with open(member_secret_path, 'w', encoding='utf-8') as f:
            json.dump(member_secret, f, indent=4, ensure_ascii=False)
        with open(member_public_path, 'w', encoding='utf-8') as f:
            json.dump(member_public, f, indent=4, ensure_ascii=False)
    




    

def signature_encrypt(hash_value: bytes, scrt_key, pub_key):

    pass