from streebog import streebog_function

def streebog_512(message: bytes, output='hex') -> bytes:
    hash = bytearray(64)
    streebog_function(message, hash)
    result = bytes(hash)
    return result.hex() if output == 'hex' else result


text = "привет мир"
message = text.encode('utf-8')

hash_512 = streebog_512(message)

print(f"Streebog-512: {hash_512}")