import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from SHA2 import sha256_function, convert_to_bytes, sha512_function
from Streebog import streebog_256, streebog_512

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def hmac_function(key, data, algorithm):
    pass

def hmac_sha256(key, data):
    B = 64
    key = convert_to_bytes(key)
    data = convert_to_bytes(data)
    
    if len(key) > B:  
        key = sha256_function(key)
    elif len(key) < B:
        key += b'\x00' * (B - len(key))

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    inner_hash = sha256_function(xor_bytes(key, ipad) + data)
    outer_hash = sha256_function(xor_bytes(key, opad) + inner_hash)

    return outer_hash

def hmac_sha512(key, data):
    B = 128
    key = convert_to_bytes(key)
    data = convert_to_bytes(data)

    if len(key) > B:  
        key = sha512_function(key)
    elif len(key) < B:
        key += b'\x00' * (B - len(key))

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    inner_hash = sha512_function(xor_bytes(key, ipad) + data)
    outer_hash = sha512_function(xor_bytes(key, opad) + inner_hash)

    return outer_hash

def hmac_streebog256(key, data):
    B = 64

    key = convert_to_bytes(key)
    data = convert_to_bytes(data)

    if len(key) > B:  
        key = streebog_256(key)
    elif len(key) < B:
        key += b'\x00' * (B - len(key))

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    inner_hash = streebog_256(xor_bytes(key, ipad) + data)
    outer_hash = streebog_256(xor_bytes(key, opad) + inner_hash)

    return outer_hash

def hmac_streebog512(key, data):
    B = 64

    key = convert_to_bytes(key)
    data = convert_to_bytes(data)

    if len(key) > B:  
        key = streebog_512(key)
    elif len(key) < B:
        key += b'\x00' * (B - len(key))

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    inner_hash = streebog_512(xor_bytes(key, ipad) + data)
    outer_hash = streebog_512(xor_bytes(key, opad) + inner_hash)

    return outer_hash


print(hmac_sha256("key", "hehe").hex())
print(hmac_sha512("key", "hehe").hex())
