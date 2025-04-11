import random
import sys 
import os


lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(lib_path)
from NumberTheoreticAlgorithms.algorithms import algorithm_fast_pow, algorithm_euclid_extended, algorithm_Miller_Rabin_test

def algorithm_p_method(N):
    if algorithm_Miller_Rabin_test(N):
        return [N]
    if N == 1:
        return None

    a, b = random.randint(1, N - 1), random.randint(1, N - 1)
    divisors = []

    for _ in range(10000):
        if N == 1:
            break
        c = random.randint(1, 10)
        a = spfunc(a, N, c)
        b = spfunc(spfunc(b, N, c), N, c)
        d = algorithm_euclid_extended(abs(a - b), N)[0]

        if 1 < d < N:
            if algorithm_Miller_Rabin_test(d):
                divisors.append(d)
            else:
                divisors += algorithm_p_method(d)
            N //= d
        elif d == 4:
            divisors += [2, 2]
            N //= d
        else:
            a, b = random.randint(1, N - 1), random.randint(1, N - 1)

    if N > 1:
        divisors.append(N)

    return divisors

def spfunc(x, N, c=None):
    if c == None:
        return (algorithm_fast_pow(x, 2) + 1) % N
    else:
        return (algorithm_fast_pow(x, 2) + c) % N
    
def main():
    N = int(input("Enter number: "))
    print(algorithm_p_method(N))

if __name__ == "__main__":
    main()