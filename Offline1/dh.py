
import random
import time

_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71)


def is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # n-1 = 2^r * d(odd)
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for i in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for j in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits, rounds=50):
    if bits < 2:
        raise ValueError("bits must be >= 2")
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rounds):
            return candidate


def generate_suitable_prime(bits, rounds=50):
    while True:
        q = generate_prime(bits - 1, rounds)
        P = 2 * q + 1
        if P.bit_length() == bits and is_probable_prime(P, rounds):
            return P, q


def find_generator(P, q):
    while True:
        g = random.randrange(2, P - 1)
        if pow(g, 2, P) != 1 and pow(g, q, P) != 1:
            return g

def generate_public_parameters(bits, seed=None):
    if seed is not None:
        random.seed(seed)
    P, q = generate_suitable_prime(bits)
    g = find_generator(P, q)
    return P, g

def generate_private_key(bits):
    val = random.getrandbits(bits)
    val |= (1 << (bits - 1))
    return val


def derive_aes_key(shared_secret, key_bits):
    mask = (1 << key_bits) - 1  
    key_int = shared_secret & mask  
    return key_int.to_bytes(key_bits // 8, byteorder='big')

def dh_round(P, g, k):

    Ka = generate_private_key(k)
    Kb = generate_private_key(k)

    t0 = time.time()
    A = pow(g, Ka, P)                 
    t1 = time.time()

    B = pow(g, Kb, P)               
    t2 = time.time()

    s_alice = pow(B, Ka, P)          
    s_bob = pow(A, Kb, P)           
    t3 = time.time()

    assert s_alice == s_bob, "Shared secrets do not match!"

    time_A = t1 - t0
    time_B = t2 - t1
    time_s = t3 - t2  

    return time_A, time_B, time_s, A, B, s_alice


def run_report(key_sizes=(128, 192, 256), trials=5, seed=42):
    print(f"{'k':>5} | {'Time for A (s)':>16} | {'Time for B (s)':>16} | {'Time for shared key s (s)':>26}")
    print("-" * 75)

    results = {}
    for k in key_sizes:
        P, g = generate_public_parameters(k, seed=seed + k)

        sum_A = sum_B = sum_s = 0.0
        sample_values = None
        for trial in range(trials):
            tA, tB, ts, A, B, s = dh_round(P, g, k)
            sum_A += tA
            sum_B += tB
            sum_s += ts
            if sample_values is None:
                sample_values = (P, g, A, B, s)

        avg_A = sum_A / trials
        avg_B = sum_B / trials
        avg_s = sum_s / trials

        results[k] = (avg_A, avg_B, avg_s, sample_values)
        print(f"{k:>5} | {avg_A:>16.6f} | {avg_B:>16.6f} | {avg_s:>26.6f}")

    print()
    for k, (avg_A, avg_B, avg_s, (P, g, A, B, s)) in results.items():
        print(f"--- k = {k} sample values ---")
        print(f"P = {P}")
        print(f"g = {g}")
        print(f"A = {A}")
        print(f"B = {B}")
        print(f"shared secret s = {s}")
        print()

    return results
if __name__ == "__main__":
    run_report(key_sizes=(128, 192, 256), trials=5, seed=42)