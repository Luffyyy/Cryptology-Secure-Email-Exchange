import secrets
import hashlib

# Standard Group Parameters
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
G = 2

def keygen():
    """Generates a long-term DH Keypair for a user."""
    sk = secrets.randbelow(P - 2) + 1
    pk = pow(G, sk, P)
    return pk, sk

def encapsulate(recipient_pk):
    """
    Alice runs this to:
    1. Create an ephemeral DH key.
    2. Derive a shared secret.
    3. Return the 'Capsule' (c1) and the symmetric key.
    """
    # 1. Generate ephemeral key (the 'E' in DHKEM)
    r = secrets.randbelow(P - 2) + 1
    c1 = pow(G, r, P)  # This is the "Capsule" or public share
    
    # 2. Compute Shared Secret (Recipient_PK ^ r)
    shared_point = pow(recipient_pk, r, P)
    
    # 3. KDF (Key Derivation Function)
    # We hash the shared secret to create a fixed-length 32-byte key
    symmetric_key = hashlib.sha256(str(shared_point).encode()).digest()
    
    return c1, symmetric_key

def decapsulate(c1, recipient_sk):
    """
    Bob runs this to:
    1. Recompute the shared secret using the capsule and his private key.
    2. Derive the same symmetric key.
    """
    # 1. Compute Shared Secret (c1 ^ sk)
    shared_point = pow(c1, recipient_sk, P)
    
    # 2. KDF (Same as Alice)
    symmetric_key = hashlib.sha256(str(shared_point).encode()).digest()
    
    return symmetric_key