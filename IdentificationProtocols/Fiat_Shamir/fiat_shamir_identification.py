import json
import os
import sys
import secrets
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_generate_prime, algorithm_fast_pow, algorithm_euclid_extended, algorithm_comprasion

def generate_keys(size, dir_path):
    p = algorithm_generate_prime(size // 2)
    q = algorithm_generate_prime(size // 2)
    N = p * q

    while True:
        x = secrets.randbelow(N - 2) + 1
        if algorithm_euclid_extended(x , N)[0] == 1:
            break

    x2 = algorithm_fast_pow(x, 2, N)  
    y = algorithm_comprasion(x2, 1, N)[0]
    scrt_key = {
        "N": N,
        "x": x
    }

    pub_key = {
        "N": N,
        "y": y
    }

    with open(dir_path + "scrt_key.json", "w") as f:
        json.dump(scrt_key, f)
    with open(dir_path + "pub_key.json", "w") as f:
        json.dump(pub_key, f)


generate_keys(1024, "IdentificationProtocols/Fiat_Shamir/fiat_shamir_keys/")
