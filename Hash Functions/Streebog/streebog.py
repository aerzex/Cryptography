import struct
from constants import PI, TAU, A, C

def convert_to_bytes(data):
    if isinstance(data, str):
        return data.encode('utf-8')
    elif isinstance(data, int):
        return data.to_bytes((data.bit_length() + 7) // 8 or 1, 'big')
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in data):
        return bytes(data)
    else:
        raise TypeError("Unsupported data type. Use str, int, bytes, or list of bytes.")

def add_512(a, b):
    a_int = int.from_bytes(a, byteorder='big')
    b_int = int.from_bytes(b, byteorder='big')
    result = (a_int + b_int) & ((1 << 512) - 1)
    return result.to_bytes(64, byteorder='big')

def transform_x(a: bytes, b: bytes, result:bytearray):
    for i in range(64):
        result[i] = a[i] ^ b[i]


def transform_s(data: bytearray):
    for i in range(64):
        data[i] = PI[data[i]]

def transform_p(data: bytearray):
    temp = data[:]
    for i, var in enumerate(TAU):
        data[i] = temp[var]

def transform_l(data: bytearray):
    w64 = [int.from_bytes(data[i*8:(i+1)*8], 'big') for i in range(8)]
    buffer = [0] * 8
    
    for i in range(8):
        for j in range(64):
            if w64[i] & (1 << (63 - j)):
                buffer[i] ^= A[j]
    
    for i in range(8):
        data[i*8:(i+1)*8] = buffer[i].to_bytes(8, 'big')

def key_schedule(keys: bytearray, index: int):
    transform_x(keys, C[index], keys)
    transform_s(keys)
    transform_p(keys)
    transform_l(keys)

def transform_e(keys: bytearray, block: bytearray, state: bytearray):
    transform_x(block, keys, state)
    for i in range(12):
        transform_s(state)
        transform_p(state)
        transform_l(state)
        key_schedule(keys, i)
        transform_x(state, keys, state)


def transform_g(n: bytes, hash: bytearray, message: bytearray):
    keys = bytearray(64)
    temp = bytearray(64)
    transform_x(n, hash, keys)
    transform_s(keys)
    transform_p(keys)
    transform_l(keys)
    transform_e(keys, message, temp)
    transform_x(temp, hash, temp)
    transform_x(temp, message, hash)

def streebog_function(message: bytes, hash: bytearray):
    bin_mes = list(message)
    n = bytearray(64)
    sigma = bytearray(64)
    
    for i in range(0, len(bin_mes), 64):
        part = bin_mes[i:i + 64]
        block = bytearray(64)
        block[:len(part)] = part
        if len(part) < 64:
            block[len(part)] = 0x01
        block.reverse()

        transform_g(n, hash, block)
        n = add_512(n, struct.pack('>Q', len(part) * 8).rjust(64, b'\x00'))
        sigma = add_512(sigma, block)
    
    if len(bin_mes) % 64 == 0:
        extra_block = bytearray(64)
        extra_block[0] = 0x01
        extra_block.reverse()

        transform_g(n, hash, extra_block)
        n = add_512(n, bytes(64))
        sigma = add_512(sigma, extra_block)
    
    transform_g(bytes(64), hash, n)
    transform_g(bytes(64), hash, sigma)
    hash.reverse()