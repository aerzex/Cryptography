import json
import os
import sys
import secrets
import argparse

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_generate_prime, algorithm_fast_pow

def generate_shares(n, t, size=1024):
    p = algorithm_generate_prime(size)
    while p <= n:
        p = algorithm_generate_prime(size)
    
    user_list = []
    for i in range(1, n + 1):
        user_list.append(i)
    
    r = [secrets.randbelow(p)]
    r.extend(secrets.randbelow(p) for _ in range(t - 1))
    
    shares = []
    for r_i in user_list:
        s_i = 0
        for j, coefficient in enumerate(r):
            s_i = (s_i + coefficient * algorithm_fast_pow(r_i, j, p)) % p
        shares.append((r_i, s_i))
    
    return p, shares, r[0] 

def main():
    n = 3
    t = 2
    
    if t < 1 or t > n:
        print(f"Error: Threshold t must be between 1 and {n}")
        return
    
    try:
        p, shares, s = generate_shares(n, t)
        print(f"Generated shares with p={p}, secret={s}")
        
        public_params = {
            "p": p,
            "n": n,
            "t": t,
            "x_list": [x for x, _ in shares]
        }
        with open("KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/public_params.json", "w", encoding="utf-8") as f:
            json.dump(public_params, f, indent=4)
        
        for i, (x_i, y_i) in enumerate(shares, 1):
            share = {
                "x": x_i,
                "y": y_i
            }
            with open(f"KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/user_{i}_share.json", "w", encoding="utf-8") as f:
                json.dump(share, f, indent=2)
        
        with open("KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/secret.txt", "w", encoding="utf-8") as f:
            f.write(str(s))
        
        print(f"Generated and saved {n} shares for t={t}, secret={s}")

    except Exception as e:
        print(f"Generator error: {e}")

if __name__ == "__main__":
    main()