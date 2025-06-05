import json
import os
import sys
import argparse

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_comprasion

def lagrange_interpolation(shares, p):
    if not shares:
        raise ValueError("No shares provided")
    
    t = len(shares)
    result = 0
    
    for i in range(t):
        x_i, y_i = shares[i]
        for j in range(t):
            if j != i:
                x_j = shares[j][0]
                denominator = (x_i - x_j) % p
                if denominator == 0:
                    raise ValueError("Duplicate x_i values")
                denominator_inv = algorithm_comprasion(denominator, 1, p)[0]
                temp = (y_i * (-x_j % p) * denominator_inv) % p
        result = (result + temp) % p
    
    return result

def main():
    user_ids = (1, 2)

    try:
        with open("KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/public_params.json", "r", encoding="utf-8") as f:
            public_params = json.load(f)
        p = public_params["p"]
        n = public_params["n"]
        t = public_params["t"]
        
        if len(user_ids) < t:
            raise ValueError(f"At least {t} shares are required for recovery")
        if any(uid < 1 or uid > n for uid in user_ids):
            raise ValueError(f"User IDs must be between 1 and {n}")
        
        shares = []
        for uid in user_ids:
            with open(f"KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/user_{uid}_share.json", "r", encoding="utf-8") as f:
                share = json.load(f)
                shares.append((share["x"], share["y"]))
        
        secret = lagrange_interpolation(shares, p)
        print(f"Recovered secret: {secret}")
        
        with open("KeyDistributionProtocols/ShamirScheme/shamir_scheme_keys/recovered_secret.txt", "w", encoding="utf-8") as f:
            f.write(str(secret))

    except Exception as e:
        print(f"Recovery error: {e}")

if __name__ == "__main__":
    main()