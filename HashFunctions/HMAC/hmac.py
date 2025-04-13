import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from SHA2 import sha256_function, convert_to_bytes, sha512_function
from Streebog import streebog_256, streebog_512

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def hmac_function(key, data, algorithm):
    if algorithm == sha512_function:
        B = 128
    elif algorithm == (sha256_function or streebog_256 or streebog_512):
        B = 64

    key = convert_to_bytes(key)
    data = convert_to_bytes(data)

    if len(key) > B:  
        key = sha256_function(key)
    elif len(key) < B:
        key += b'\x00' * (B - len(key))

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    inner_hash = algorithm(xor_bytes(key, ipad) + data)
    outer_hash = algorithm(xor_bytes(key, opad) + inner_hash)

    return outer_hash   

print(hmac_function("key", "hehe", sha256_function).hex())
print(hmac_function("key", "hehe", sha512_function).hex())