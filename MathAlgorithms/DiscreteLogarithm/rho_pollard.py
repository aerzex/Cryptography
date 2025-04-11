import sys 
import os
import math
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(lib_path)
from NumberTheoreticAlgorithms.algorithms import algorithm_fast_pow, algorithm_comprasion, algorithm_rho_pollard_fact, algorithm_all_divisors

def algorithm_rho_pollard():
    u, v = 2, 2
    a = int(input("Enter number a: "))
    b = int(input("Enter number b: "))
    p = int(input("Enter number p: "))
    divs = algorithm_all_divisors(p - 1)
    r = p - 1
    for div in divs:
        if algorithm_fast_pow(a, div, p) == 1:
            r = div
            break
    c = [u, v]
    d = c
    for _ in range(1000):
        c = spfunc(a, b, c, p)
        d = spfunc(a, b, spfunc(a, b, d, p), p)
        c_i = (algorithm_fast_pow(a, c[0]) * algorithm_fast_pow(b, c[1])) % p
        d_i = (algorithm_fast_pow(a, d[0]) * algorithm_fast_pow(b, d[1])) % p
        if(c_i == d_i):
            a_d = (c[1] - d[1]) % (p - 1)
            b_d = (d[0] - c[0]) % (p - 1)
            return algorithm_comprasion(a_d, b_d, r)



def spfunc(a, b, c, p):
    c_i = (algorithm_fast_pow(a, c[0]) * algorithm_fast_pow(b, c[1])) % p
    if c_i < p // 2:
        return (c[0] + 1) % (p - 1), c[1] % (p - 1)
    else:
        return c[0] % (p - 1), (c[1] + 1) % (p - 1)
    
def algorithm_all_divisors(N):
    prime_factors = algorithm_rho_pollard_fact(N)
    if not prime_factors:
        return [1]  

    unique_factors = list(set(prime_factors))
    divisors = [1]

    for factor in unique_factors:
        max_power = prime_factors.count(factor)
        current_divisors = divisors.copy()

        for power in range(1, max_power + 1):
            for d in current_divisors:
                new_divisor = d * (factor ** power)
                if new_divisor not in divisors:
                    divisors.append(new_divisor)

    divisors.sort()
    return divisors

def main():
    print(algorithm_rho_pollard())

main()

