import secrets
import chacha20 as ch20
import elgamal as eg
import rabin_signature as rs

user_data = { 'alice': {}, 'bob': {} } # Dummy database

def send_message(from_user, to_user, msg):
    msg = f'\tFROM: {from_user}\n\tTO: {to_user}\n\tMessage: {msg}'
    # Alice (Sender, Creates a key for Chacha20 and sends an Email to Bob)
    
    ## Chacha20 Symmetric Algorithm
    chacha20_key = secrets.token_bytes(32)
    cipher_email = ch20.encrypt(msg.encode(), chacha20_key) # Alice sends

    ## KEM ElGamal: Get elgamal public gay from Bob
    elgamal_pk = begin_message_transaction(to_user)
    key_int = int.from_bytes(chacha20_key, "little")
    elgamal_c1, elgamal_c2 = eg.encrypt(elgamal_pk, key_int) # Alice sends

    ## Rabin Signature
    rabin_n, rabin_sk = rs.keygen(512)
    sign = rs.sign(msg, rabin_sk)

    ## Send the message to bob he recives it
    receive_message(to_user, cipher_email, elgamal_c1, elgamal_c2, sign, rabin_n)

def begin_message_transaction(user):
    # Bob (Reciever, creates public and private keys for KEM-ElGamal)
    pk, sk = eg.keygen()
    user_data[user]['elgamal_keys'] = (pk, sk)

    return pk

def receive_message(to_user, cipher_email, elgamal_c1, elgamal_c2, sign, rabin_n):
    # Bob (Decrypts key and decrypts email)
    sk = user_data[to_user]['elgamal_keys'][1]

    recovered_int = eg.decrypt(elgamal_c1, elgamal_c2, sk) # KEM-ElGamal Decrypt Chacha20 key
    recovered_bytes = recovered_int.to_bytes(32, "little")
    msg = ch20.encrypt(cipher_email, recovered_bytes).decode() # Chacha20 Decrypt message

    ## Verify signature
    if rs.verify(msg, sign, rabin_n):
        print(f'Signature: Verified\nGot message:\n{msg}')
    else:
        print(f'Rejected message: Received Invalid Signature.')


send_message('alice', 'bob', input('Enter a message to send to Bob: '))