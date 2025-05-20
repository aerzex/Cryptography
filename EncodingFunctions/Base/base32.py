BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE32_REVERSE = {char: index for index, char in enumerate(BASE32_ALPHABET)}

def base32_encode(data):
    data_bytes = data.encode('utf-8')
    bits = ''.join(bin(byte)[2:].zfill(8) for byte in data_bytes)

    remainder = len(bits) % 5
    if remainder:
        bits += '0' * (5 - remainder)

    encoded = []
    for i in range(0, len(bits), 5):
        block = bits[i:i+5]
        encoded.append(BASE32_ALPHABET[int(block, 2)])

    padding = 8 - (len(encoded) % 8)
    if padding:
        encoded += '=' * padding

    return ''.join(encoded)
    

def base32_decode(data):
    encoded = data.rstrip('=')

    bits = ''
    for symbol in encoded:
        if symbol in BASE32_REVERSE:
            bits += f"{BASE32_REVERSE[symbol]:05b}"
        else:
            raise ValueError(f"Invalid base32 character: {symbol}")
        
    data_bytes = []

    for i in range(0, len(bits), 8):
        part = bits[i:i+8]
        if part:    
            data_bytes.append(int(part, 2))
    
    

    return bytes(data_bytes).decode('utf-8')
    
def main():
    input_string_ru = "Если мне что-то не нравится, значит, не нравится, и все тут; так с какой стати, спрашивается, я стану делать вид, будто мне это нравится, только потому, что большинству моих соплеменников это нравится или они воображают, что нравится. Не могу я что-то любить или не любить по велению моды."
    encoded_string = base32_encode("A")
    decoded_string = base32_decode(encoded_string)
    print(f"Encoded: {encoded_string}")
    print(f"Decoded: {decoded_string}")

main()