import hashlib

# Simple SHA-256 hash to integer
def hash_message(msg):
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)
