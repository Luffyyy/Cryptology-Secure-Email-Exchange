import hashlib

# Simple SHA-256 hash to integer
def hash_message(msg):
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16)
def hash_message_hex(msg):
    return hashlib.sha256(msg.encode()).hexdigest()