import os
import sys
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from HashFunctions.SHA2 import sha256_function, sha512_function, convert_to_bytes
from HashFunctions.Streebog import streebog_256, streebog_512
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow, algorithm_comprasion, algorithm_euclid_extended, algorithm_generate_prime, algorithm_Miller_Rabin_test
import secrets

def sign_data_client(data, U, E, S, hash_function):
    data = convert_to_bytes(data)
    hash_value = hash_function(data)
    hex_hash_value = hash_value.hex()
    signature_value = (U, E, S)
    hash_signature_value = hash_function(convert_to_bytes(U) + convert_to_bytes(E) + convert_to_bytes(S))

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
            "SignatureValue": signature_value, 
            "UnsignedAttributes": { 
                "OBJECT IDENTIFIER": "signature-time-stamp",
                "SET OF AttributeValue": {
                    "hash": hash_function(data + hash_signature_value).hex(),  
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

def generate_member_keys(member_id, p, alpha, dir_path="DigitalSignatures/Group/group_keys"):
    x = secrets.randbits(256)    
    y = algorithm_fast_pow(alpha, x, p)

    member_keys = (x, y)
    save_member_keys(member_id, member_keys, dir_path)




def generate_leader_keys(size, dir_path="DigitalSignatures/Group/group_keys"):

    while True:
        p = algorithm_generate_prime(size)
        q = algorithm_generate_prime(size)
        N = p * q
        if algorithm_Miller_Rabin_test(2 * N + 1):
            p = 2 * N + 1
            break

    

    alpha = 0
    while True:
        h = secrets.randbelow(p - 4) + 2
        alpha = algorithm_fast_pow(h, (p - 1) // q, p)
        if alpha != 1:
            if algorithm_fast_pow(alpha, q, p) == 1:
                break

    X = secrets.randbits(256)
    L = algorithm_fast_pow(alpha, X, p)
    
    leader_key = (X, L)

    e = secrets.randbits(32)
    phi_N = (p - 1) * (q - 1)
    d = algorithm_comprasion(e, 1, phi_N)[0]
    save_leader_key(leader_key, p, e, d, alpha, N, dir_path)


def save_leader_key(leader_key, p, e, d, alpha, N, dir_path):
    leader_secret = {"X": leader_key[0], "PrivateExponent": d}
    leader_public = {"Prime": p, "Alpha": alpha, "L": leader_key[1], "Exponent": e, "N": N}
    
    leader_secret_path = os.path.join(dir_path, "leader_secret_key.json")
    leader_public_path = os.path.join(dir_path, "leader_public_key.json")
    
    with open(leader_secret_path, 'w', encoding='utf-8') as f:
        json.dump(leader_secret, f, indent=4, ensure_ascii=False)
    with open(leader_public_path, 'w', encoding='utf-8') as f:
        json.dump(leader_public, f, indent=4, ensure_ascii=False)


    
def save_member_keys(member_id: int, member_keys: dict, dir_path: str):
    os.makedirs(dir_path, exist_ok=True)

    member_secret = {"id": member_id, "x": member_keys[0]}
    member_public = {"id": member_id, "y": member_keys[1]}
    
    member_secret_path = os.path.join(dir_path, f"member_{member_id}_secret_key.json")
    member_public_path = os.path.join(dir_path, f"member_{member_id}_public_key.json")
    
    with open(member_secret_path, 'w', encoding='utf-8') as f:
        json.dump(member_secret, f, indent=4, ensure_ascii=False)
    with open(member_public_path, 'w', encoding='utf-8') as f:
        json.dump(member_public, f, indent=4, ensure_ascii=False)


def compute_lambda_exponent(hash_value: bytes, y: int, d: int, hash_function):    
    y_bytes = convert_to_bytes(y)
    hash_digest = hash_function(hash_value + y_bytes + hash_function(hash_value + y_bytes + convert_to_bytes(d)))
    lymbda = int.from_bytes(hash_digest)

    return lymbda

def encrypt_1_part_signature(y, lamda, p):
    U = 1
    for i in range(len(lamda)):
        U = U * algorithm_fast_pow(y[i], lamda[i], p) % p 

    return U

def encrypt_2_part_signature(hash_value: bytes, R: list, p: int, U: int, hash_function):
    R_sum = 1
    for i in range(len(R)):
        R_sum = R_sum * R[i] % p

    E = hash_function(hash_value + convert_to_bytes(R_sum) + convert_to_bytes(U))
    
    return int.from_bytes(E), R_sum

def encrypt_3_part_signature(S, N, d):
    S_sum = 0
    for i in range(len(S)):
        S_sum = (S_sum + S[i]) % N
    S = algorithm_fast_pow(S_sum, d, N)
    return S
        

def load_key(filename):
    with open(filename, "r", encoding="utf-8") as json_file:
        pub_key = json.load(json_file)
    return pub_key


    

def verify_sign(signature, pub_key):
    try:
        p, alpha, e, L  = pub_key["Prime"], pub_key["Alpha"], pub_key["Exponent"], pub_key["L"]

        signer_info = signature["SignerInfos"]
        signed_attributes = signer_info["SignedAttributes"]
        signature_value = signer_info["SignatureValue"]
        hash_function = globals()[signer_info["DigestAlgorithmIdentifier"]]

        data_hex = signature["EncapsulatedContentInfo"]["OCTET STRING"]
        data = bytes.fromhex(data_hex)
        
        message_digest = hash_function(data)
        U, E, S = signature_value[0], signature_value[1], signature_value[2]
        UL_inv = algorithm_comprasion(U * L, 1, p)[0]
        R = (algorithm_fast_pow(UL_inv, E, p) * algorithm_fast_pow(alpha, algorithm_fast_pow(S, e, (p - 1) // 2), p)) % p
        E_expected = int.from_bytes(hash_function(message_digest + convert_to_bytes(R) + convert_to_bytes(U)))

        if E != E_expected:
            return False, "Signature verification failed"
    
        return True, "Signature is valid"
    except Exception as e:
        return False, f"Verification error: {str(e)}"