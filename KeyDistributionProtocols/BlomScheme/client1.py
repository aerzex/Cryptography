import json
import os
import sys

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.append(lib_path)
from MathAlgorithms.NumberTheoreticAlgorithms import algorithm_fast_pow

def compute_session_key(coefficients, u_other, p):
    k = 0
    for j, coefficient in enumerate(coefficients):
        k = (k + coefficient * algorithm_fast_pow(u_other, j, p)) % p
    return k

def main():
    user_id = 1
    partner_id = 2

    try:
        with open("KeyDistributionProtocols/BlomScheme/blom_scheme_keys/public_params.json", "r", encoding="utf-8") as f:
            public_params = json.load(f)
        p = public_params["p"]
        u_list = public_params["u_list"]

        if user_id < 1 or user_id > len(u_list) or partner_id < 1 or partner_id > len(u_list):
            raise ValueError(f"User ID or Partner ID out of range (1 to {len(u_list)})")

        with open(f"KeyDistributionProtocols/BlomScheme/blom_scheme_keys/user_{user_id}_keys.json", "r", encoding="utf-8") as f:
            user_keys = json.load(f)
        coeffs = user_keys["coeffs"]

        u_partner = u_list[partner_id - 1]

        k = compute_session_key(coeffs, u_partner, p)
        print(f"User {user_id} session key with User {partner_id}: {k}")

        with open(f"KeyDistributionProtocols/BlomScheme/blom_scheme_keys/secret_user_{user_id}_{partner_id}.txt", "w") as f:
            f.write(str(k)) 

    except Exception as e:
        print(f"User {user_id} error: {e}")

if __name__ == "__main__":
    main()