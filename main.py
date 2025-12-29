import secrets
import chacha20 as ch20
import elgamal as eg
import rabin_signature as rs
import shared as sh
import json

user_data = {
    'alice': {
        'messages': []
    },
    'bob': {
        'messages': []
    }
} # Dummy database

def send_message(from_user, to_user, msg):
    msg = f'\tFROM: {from_user}\n\tMessage: {msg}'
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
        user_data[to_user]['messages'].append(msg)
    else:
        print(f'Rejected message: Received Invalid Signature.')


def check_password(username1, password1):
    with open("data.json", "r") as f:
        data = json.load(f)
    for user in data["users"]:
        if user["username"] == username1:
            return user["password"] == password1
    return False

start_action = int(input("Welcome!\nPress 1 to Log in\nPress 2 to exist\n"))
while start_action != 2:
    username = input('Enter Username: ')
    password = input('Enter your password: ')
    if not check_password(username, str(sh.hash_message_hex(password))):
        print("Username or password is incorrect.")
        start_action = int(input("Do you wish to try again?\n1 for yes\n2 for no\n"))
    else:
        print(f'Welcome {username}!')
        action = input('Click 1 to send a message\nClick 2 to read your messages\nClick 3 to log out\nClick 4 to exit\n')
        while True:
            if action == '1':
                print("Here is your contact lists:\n")
                counter = 0
                for user in user_data.keys():
                    if user != username:
                        counter += 1
                        print(f"{counter}. {user}")
                print("\nPlease state who you want to send a message to:\n")
                to_user1 = input()
                while to_user1 not in user_data:
                    to_user1 = input('User does not exist! please try again! \nEnter Username: ')
                if to_user1 in user_data:
                    send_message(username, to_user1, input('Enter a message to send: '))
                    print("Message sent successfully")
            elif action == '2':
                if not user_data[username]:
                    print("Your inbox is empty.")
                else:
                    print(f"Here are your messages for {username}:")
                    for i, msg in enumerate(user_data[username]['messages'], start=1):
                        print(f"{i}. {msg}")
            elif action == '3':
                print("Logged out successfully\n")
                start_action = int(input("Welcome!\n Press 1 to Log in\n Press 2 to exist\n"))
                break
            elif action == '4':
                start_action = 2
                break
            action = input('Click 1 to send a message\nClick 2 to read your messages\nClick 3 to log out\nClick 4 to exit\n')
print("Good bye!")