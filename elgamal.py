import secrets
import math

# ---------------------
# Parameters (safe prime > 2^400)
# ---------------------
q = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
g = 2  # generator

# Key generation
def keygen():
    sk = secrets.randbelow(q - 2) + 1  # private key [1, q-1] TODO: what range should this be?

    while math.gcd(sk, q) != 1:
        sk = secrets.randbelow(q - 2) + 1

    pk = pow(g, sk, q) # public key
    return pk, sk

# Encryption
def encrypt(pk, m_int):
    """
    m_int: integer representation of the message
    Returns (c1, c2)
    """
    r = secrets.randbelow(q - 2) + 1 # ephemeral random

    while math.gcd(r, q) != 1:
        r = secrets.randbelow(q - 2) + 1

    c1 = pow(g, r, q)
    c2 = (m_int * pow(pk, r, q)) % q
    return c1, c2

# Decryption
def decrypt(c1, c2, sk):
    shared = pow(c1, sk, q) # shared = c1^sk % q = g^(r*sk) % q

    # multiplicative inverse mod q
    inv = pow(shared, -1, q) # inv = shared^-1 % q
    K_int = (c2 * inv) % q # C20K = C20K * pk^r * inv = C20K * g^(sk*r) * g^-(sk*r)
    return K_int
