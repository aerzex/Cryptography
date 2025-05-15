import os
import sys
import json
import secrets
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from CipherSystems.ElGamal import save_keys, load_private_key, load_public_key
from HashFunctions.SHA2 import sha256_function, sha512_function, convert_to_bytes
from HashFunctions.Streebog import streebog_256, streebog_512
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow, algorithm_comprasion, algorithm_euclid_extended, algorithm_generate_prime, algorithm_second_degree_comparison

def sign_data_client(data, scrt_key, pub_key, hash_function):
    data = convert_to_bytes(data)
    hash_value = hash_function(data)
    hex_hash_value = hash_value.hex()
    hash_encrypted = signature_encrypt(hash_value, scrt_key, hash_function)
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

def generate_keys(length, hash_algorithm, dir_path):
    p, q = algorithm_generate_prime(length // 2, 50), algorithm_generate_prime(length // 2, 50)
    N = p * q

    if hash_algorithm == sha512_function:
        m_len = 512
    elif hash_algorithm == (sha256_function or streebog_256 or streebog_512):
        m_len = 256

    a = [0] * m_len
    b = []
    for i in range(m_len):
        while (algorithm_euclid_extended(a[i], N)[0] != 1):
            a[i] = secrets.randbelow(N - 1) + 1
        a_inv = algorithm_comprasion(a[i], 1, N)[0]
        b.append(algorithm_fast_pow(a_inv, 2, N))
    
    pub_key = {
        "N": N,
        "b": b
    }

    scrt_key = {
        "a": a,
        "prime1": p,
        "prime2": q
    }

    save_keys(scrt_key, pub_key, dir_path)

def signature_encrypt(hash_value: bytes, scrt_key, hash_function):
    a, p, q = scrt_key["a"], scrt_key["prime1"], scrt_key["prime2"]
    N = p * q

    r = secrets.randbelow(N - 2) + 1
    u = algorithm_fast_pow(r, 2, N)
    
    u_bytes = convert_to_bytes(u)
    data_bytes = hash_function(hash_value + u_bytes)
    s = ''.join(bin(byte)[2:].zfill(8) for byte in data_bytes)

    result = 1
    for i in range(len(s)):
        result *= (a[i]**int(s[i]))
        result %= N

    t = r * result % N

    return s, t

def bits_to_bytes(bit_string):
    byte_chunks = [bit_string[i:i+8] for i in range(0, len(bit_string), 8)]
    bytes_data = bytes([int(chunk, 2) for chunk in byte_chunks])
    return bytes_data

def signature_decrypt(sign_value, pub_key):
    N, b = pub_key["N"], pub_key["b"]
    s, t = sign_value[0], sign_value[1]

    result = 1
    for i in range(len(s)):
        result *= (b[i]**int(s[i]))
        result %= N

    w = algorithm_fast_pow(t, 2, N) * result % N

    return w

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
        
        expected = bits_to_bytes(signature_value[0])

        w = signature_decrypt(signature_value, public_key)
        decrypted_hash = hash_function(message_digest + convert_to_bytes(w))
        
        if decrypted_hash != expected:
            return False, "Signature verification failed"
        
        return True, "Signature is valid"
    except Exception as e:
        return False, f"Verification error: {str(e)}"

def serialize_signature(signature):
    message = json.dumps(signature, ensure_ascii=False)
    return message.encode('utf-8')

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
        timestamp = signer_info["UnsignedAttributes"]["SET OF AttributeValue"]["timestamp"]["UTCTime"]
        client_signature = signer_info["SignatureValue"]
        expected = bits_to_bytes(center_signature[0])

        w = signature_decrypt(center_signature, certificate)
        decrypted_hash = hash_function(hash_function(hash_function(data + convert_to_bytes(client_signature[0]) + convert_to_bytes(client_signature[1])).hex() + timestamp) + convert_to_bytes(w))
        
        is_valid = decrypted_hash == expected
        
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








