import sys 
import os
import secrets
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../Math Algorithms', 'algorithms'))
sys.path.append(lib_path)
from algorithms import algorithm_fast_pow, algorithm_generate_prime, algorithm_comprasion, algorithm_all_divisors, algorithm_Miller_Rabin_test

def generate_padding(length):
    while True:
        padding = secrets.token_bytes(length)
        if all(byte != 0 for byte in padding):
            return b'\x00\x02' + padding + b'\x00'
        
def save_keys(scrt_key, pub_key):
    with open("Cipher Systems/ElGamal/elgamal_keys/pub_key.json", "w", encoding="utf-8") as json_file:
        json.dump(pub_key, json_file, ensure_ascii=False, indent=4)
    with open("Cipher Systems/ElGamal/elgamal_keys/scrt_key.json", "w", encoding="utf-8") as json_file:
        json.dump(scrt_key, json_file, ensure_ascii=False, indent=4)

def generate_keys(size):
    p = algorithm_generate_prime(size)
    divisors = algorithm_all_divisors(p - 1)
    prime_divisors = []
    for divisor in divisors:
        if algorithm_Miller_Rabin_test(divisor):
            prime_divisors.append(divisor)
    while True:
        alpha = secrets.randbelow(p - 4) + 2
        check = 1  
        for prime_divisor in prime_divisors:
            if algorithm_fast_pow(alpha, (p - 1) // prime_divisor, p) == 1:
                check = 0
                break
        if check:
            break

    a = secrets.randbelow(p - 3) + 2
    beta = algorithm_fast_pow(alpha, a, p)

    pub_key = {
        "prime": p,
        "alpha": alpha,
        "beta": beta
    }

    scrt_key = {
        "a": a,
        "prime": p
    }

    save_keys(scrt_key, pub_key)


def encrypt(message):
    with open("Cipher Systems/ElGamal/elgamal_keys/pub_key.json", "r", encoding="utf-8") as json_file:
        pub_key = json.load(json_file)

    p, alpha, beta  = pub_key["prime"], pub_key["alpha"], pub_key["beta"]
    block_size = (p.bit_length() + 7) // 8
    max_msg_len = block_size - 3 - 8

    encoded = message.encode('utf-8')
    blocks = [encoded[i:i + max_msg_len] for i in range(0, len(encoded), max_msg_len)]
    enc_blocks = []
    for block in blocks:
        pad_length = block_size - 3 - len(block)
        if pad_length < 0:
            raise ValueError("Message too long for El Gamal block")
            
        padding = generate_padding(pad_length)
        padded_block = padding + block
        int_block = int.from_bytes(padded_block, 'big')

        r = secrets.randbelow(p - 2)
        C1 = algorithm_fast_pow(alpha, r, p)
        C2 = (int_block * algorithm_fast_pow(beta, r, p)) % p
        C = [C1, C2]
        enc_blocks.append(C)

    return enc_blocks

def decrypt(enc_message):
    with open("Cipher Systems/ElGamal/elgamal_keys/scrt_key.json", "r", encoding="utf-8") as json_file:
        scrt_key = json.load(json_file)
    a, p = scrt_key["a"], scrt_key["prime"]
    block_size = (p.bit_length() + 7) // 8
    dec_blocks = []
    for block in enc_message:
        dec_m = (block[1] * algorithm_comprasion(algorithm_fast_pow(block[0], a, p), 1, p)[0]) % p

        dec_block = dec_m.to_bytes(block_size, byteorder='big')
        index = dec_block.find(b'\x00', 2)
        if index == -1:
            raise ValueError("Invalid padding")
        dec_blocks.append(dec_block[index+1:])
    
    return b''.join(dec_blocks).decode('utf-8')

def main():
    size = int(input("Enter size of N: "))
    message_en = "If I don’t like a thing, I don’t like it, that’s all; and there is no reason under the sun why I should ape a liking for it just because the majority of my fellow-creatures like it, or make believe they like it. I can’t follow the fashions in the things I like or dislike."
    message_ru = "Если мне что-то не нравится, значит, не нравится, и все тут; так с какой стати, спрашивается, я стану делать вид, будто мне это нравится, только потому, что большинству моих соплеменников это нравится или они воображают, что нравится. Не могу я что-то любить или не любить по велению моды."
    generate_keys(size)
    enc_message = encrypt(message_ru)
    dec_message = decrypt(enc_message)
    print(enc_message)
    print(dec_message)


    
main()