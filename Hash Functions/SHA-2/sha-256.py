def sha256_function(data):
    data_bytes = data.encode('utf-8')
    bit_len = len(data_bytes) * 8
    padding = b'\x80' + b'\x00' * (56 - (len(data_bytes) + 1) % 64)
    data_bytes = data_bytes + padding + bit_len.to_bytes(8, 'big')
    

    h_dict = {
        'h0': 0x6a09e667, 'h1': 0xbb67ae85, 'h2': 0x3c6ef372, 'h3': 0xa54ff53a,
        'h4': 0x510e527f, 'h5': 0x9b05688c, 'h6': 0x1f83d9ab, 'h7': 0x5be0cd19
        }
    
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    for part in [data_bytes[i:i+64] for i in range(0, len(data_bytes), 64)]:
        w32 = [0] * 64
        for i in range(16):
            w32[i] = int.from_bytes(part[i*4:i*4+4], 'big')

        for i in range(16, 64):
            s0 = (rightrotate(w32[i-15], 7) ^ rightrotate(w32[i-15], 18) ^ rightshift(w32[i-15], 3))
            s1 = (rightrotate(w32[i-2], 17) ^ rightrotate(w32[i-2], 19) ^ rightshift(w32[i-2], 10))
            w32[i] = (w32[i-16] + s0 + w32[i-7] + s1) & 0xFFFFFFFF 

        a, b, c, d, e, f, g, h = h_dict.values()

        for i in range(0, len(w32)):
            S1 = (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)) & 0xFFFFFFFF
            ch = ((e & f) ^ ((~e) & g)) & 0xFFFFFFFF
            temp1 = (h + S1 + ch + k[i] + w32[i]) & 0xFFFFFFFF
            S0 = (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)) & 0xFFFFFFFF
            maj = ((a & b) ^ (a & c) ^ (b & c)) & 0xFFFFFFFF
            temp2 = (S0 + maj) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF


    
        h_dict['h0'] = (h_dict['h0'] + a) & 0xFFFFFFFF
        h_dict['h1'] = (h_dict['h1'] + b) & 0xFFFFFFFF
        h_dict['h2'] = (h_dict['h2'] + c) & 0xFFFFFFFF
        h_dict['h3'] = (h_dict['h3'] + d) & 0xFFFFFFFF
        h_dict['h4'] = (h_dict['h4'] + e) & 0xFFFFFFFF
        h_dict['h5'] = (h_dict['h5'] + f) & 0xFFFFFFFF
        h_dict['h6'] = (h_dict['h6'] + g) & 0xFFFFFFFF
        h_dict['h7'] = (h_dict['h7'] + h) & 0xFFFFFFFF

    
    h0, h1, h2, h3, h4, h5, h6, h7 = h_dict.values()
    
    digest_hex = (
        f"{h0:08x}" + f"{h1:08x}" + f"{h2:08x}" + f"{h3:08x}" +
        f"{h4:08x}" + f"{h5:08x}" + f"{h6:08x}" + f"{h7:08x}"
    )
    return digest_hex

def rightrotate(x, n, bits=32):
    return (x >> n) | (x << (bits - n)) & 0xFFFFFFFF

def rightshift(x, n):
    return x >> n

def main():
    input_string = "Привет, мир"
    print(sha256_function(input_string))

main()