from .streebog import streebog_function

def streebog_512(message: bytes, output='hex') -> bytes:
    hash = bytearray(64)
    streebog_function(message, hash)
    result = bytes(hash)
    return result.hex() if output == 'hex' else result


