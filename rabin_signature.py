import sympy
import random

from shared import hash_message

# Generate a prime p ≡ 3 mod 4
def generate_rabin_prime(bits):
    while True:
        p = sympy.randprime(2**(bits-1), 2**bits)
        if p % 4 == 3:
            return p

# Generate public/private keys
def keygen(bits):
    p = generate_rabin_prime(bits)
    q = generate_rabin_prime(bits)
    while p == q:
        q = generate_rabin_prime(bits)
    n = p * q
    return n, (p, q)

# Compute square root modulo prime (p ≡ 3 mod 4)
def sqrt_mod_prime(c, prime):
    return pow(c, (prime + 1) // 4, prime)

# Rabin signature
def sign(message, private_key):
    p, q = private_key
    n = p * q

    while True:
        # Random small integer for padding
        u = random.randint(0, n-1)
        c = hash_message(message + str(u)) % n

        # Ensure c is quadratic residue mod p and q
        if sympy.jacobi_symbol(c, p) != 1 or sympy.jacobi_symbol(c, q) != 1:
            continue

        # Square roots modulo each prime
        x_p = sqrt_mod_prime(c, p)
        x_q = sqrt_mod_prime(c, q)

        # CRT combination
        q_inv = pow(q, -1, p)
        p_inv = pow(p, -1, q)
        x = (x_p * q * q_inv + x_q * p * p_inv) % n
        return x, u

# Verification
def verify(message, signature, public_key):
    x, u = signature
    n = public_key
    c = hash_message(message + str(u)) % n
    return pow(x, 2, n) == c