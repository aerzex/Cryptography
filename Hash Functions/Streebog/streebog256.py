from streebog import streebog_function

def streebog_256(message: bytes, output='hex') -> bytes:
    hash = bytearray([0x01] * 64)
    streebog_function(message, hash)
    result = bytes(hash[32:])
    return result.hex() if output == 'hex' else result


text = "привет мир"
message = text.encode('utf-8')

hash_256 = streebog_256(message)

print(f"Streebog-256: {hash_256}")