import random
import sys 
import os
import math
import json

lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.', 'algorithms'))
sys.path.append(lib_path)
from algorithms import algorithm_fast_pow, algorithm_euclid_extended, algorithm_Miller_Rabin_test

def algorithm_pollard_p_minus_1(N):
    if algorithm_Miller_Rabin_test(N):
        return [N]
    if N == 1:
        return None

    small_factors = {
        4: [2, 2],
        6: [2, 3],
        10: [2, 5],
    }
    if N in small_factors:
        return small_factors[N]

    with open("Numbers_Factorization/src/prime_numbers.json", "r") as json_file:
        primes = json.load(json_file)["primes"]

    a = random.randint(2, N - 2)
    divisors = []
    lnN = math.log(N)

    for prime in primes[:1000]:
        l = int(lnN // math.log(prime))
        a = algorithm_fast_pow(a, algorithm_fast_pow(prime, l), N)
        d = algorithm_euclid_extended(abs(a - 1), N)[0]

        if 1 < d < N:
            if algorithm_Miller_Rabin_test(d):
                divisors.append(d)
            else:
                divisors += algorithm_pollard_p_minus_1(d)
            N //= d
        elif N == 4:
            divisors += [2, 2]
            N //= 4
        elif N == 2 or N == 3:
            divisors.append(N)
            N == 1
            break
        else:
            a = random.randint(2, N - 2)

    if N > 1:
        divisors.append(N)

    return divisors


def main():
    N = int(input("Enter number: "))
    print(algorithm_pollard_p_minus_1(N))

if __name__ == "__main__":
    main()