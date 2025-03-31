BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BASE64_REVERSE = {char: index for index, char in enumerate(BASE64_ALPHABET)}

def base64_encode(data):
    data_bytes = data.encode('utf-8')
    bits = ''.join(bin(byte)[2:].zfill(8) for byte in data_bytes)

    remainder = len(bits) % 6
    if remainder:
        bits += '0' * (6 - remainder)

    encoded = []
    for i in range(0, len(bits), 6):
        block = bits[i:i+6]
        encoded.append(BASE64_ALPHABET[int(block, 2)])

    padding = (3 - (len(data_bytes) % 3))
    encoded += '=' * padding

    return ''.join(encoded)
    

def base64_decode(data):
    encoded = data.rstrip('=')

    bits = ''
    for symbol in encoded:
        if symbol in BASE64_REVERSE:
            bits += f"{BASE64_REVERSE[symbol]:06b}"
        else:
            raise ValueError(f"Invalid base64 character: {symbol}")
        
    data_bytes = []

    for i in range(0, len(bits), 8):
        part = bits[i:i+8]
        if part:    
            data_bytes.append(int(part, 2))
    
    return bytes(data_bytes).decode('utf-8')
    
def main():
    input_string = "Если мне что-то не нравится, значит, не нравится, и все тут; так с какой стати, спрашивается, я стану делать вид, будто мне это нравится, только потому, что большинству моих соплеменников это нравится или они воображают, что нравится. Не могу я что-то любить или не любить по велению моды."
    encoded_string = base64_encode("A")
    decoded_string = base64_decode(encoded_string)  
    print(f"Encoded: {encoded_string}")
    print(f"Decoded: {decoded_string}")

main()