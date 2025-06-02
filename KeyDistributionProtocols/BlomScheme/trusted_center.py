import json
import os
import sys
import secrets

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)

from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_generate_prime, algorithm_fast_pow

def generate_parameters(n, m, size):
    p = algorithm_generate_prime(size)

    u_list = []
    for _ in range(n):
        u = secrets.randbelow(p)
        while u in u_list:
            u = secrets.randbelow(p)
        u_list.append(u)

    a = [[0] * (m + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        for j in range(i, m + 1):
            a[i][j] = secrets.randbelow(p)
            a[j][i] = a[i][j]
    
    return p, u_list, a

def compute_user_polynomial(u, a, m, p):
    coeffs = [0] * (m + 1)
    for i in range(m + 1):
        sum_j = 0
        for j in range(m + 1):
            sum_j = (sum_j + a[i][j] * algorithm_fast_pow(u, j, p)) % p
        coeffs[i] = sum_j
    return coeffs

def generate_keys(size, n, m):
    try:
        p, u_list, a = generate_parameters(n, m, size)

        user_keys = []
        for i in range(n):
            coeffs = compute_user_polynomial(u_list[i], a, m, p)
            user_keys.append({"u": u_list[i], "coeffs": coeffs})

        public_params = {
            "p": p,
            "u_list": u_list
        }
        os.makedirs("KeyDistributionProtocols/BlomScheme/blom_scheme_keys/", exist_ok=True)
        with open("KeyDistributionProtocols/BlomScheme/blom_scheme_keys/public_params.json", "w", encoding="utf-8") as f:
            json.dump(public_params, f, ensure_ascii=False, indent=4)

        for i in range(n):
            with open(f"KeyDistributionProtocols/BlomScheme/blom_scheme_keys/user_{i+1}_keys.json", "w", encoding="utf-8") as f:
                json.dump(user_keys[i], f, ensure_ascii=False, indent=4)

        print(f"Parameters and keys saved for {n} users")

    except Exception as e:
        print(f"Trusted Center error: {e}")

def main():
    generate_keys(1024, 5, 2)

if __name__ == "__main__":
    main()