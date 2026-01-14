# IMPORTANT
# There are two default users:
## Username: alice Password: cha2
## Username: bob Password: cha0

import chacha20 as ch20
import dhkem as dhkem
import rabin_signature as rs
import shared as sh
import json
import subprocess
import platform
import getpass
import secrets

local_data = {
    'alice': {
        'messages': [],
    },
    'bob': {
        'messages': []
    }
}

public_data = {
    'alice': {},
    'bob': {}
}

current_user = None

def send_message(to_user, msg):
    msg = f'\tTo: {to_user}\n\tFrom: {current_user}\n{msg}'
    # Alice (Sender)

    ## KEM: Get encap key from Bob
    kem_ek = begin_message_transaction(to_user)
    capsule, chacha20_key = dhkem.encapsulate(kem_ek) # Get capsule + symmetric key (Chacha20)

    ## Chacha20 Symmetric Algorithm
    iv = secrets.token_bytes(12)
    cipher_email = ch20.encrypt(msg.encode(), chacha20_key, iv)

    ## Rabin Signature
    sign = rs.sign(msg, local_data[current_user]['rabin_sk'])

    ## Send the message to bob he recives it
    receive_message(to_user, current_user, cipher_email, iv, capsule, sign)

def begin_message_transaction(user):
    # Bob (Reciever)

    # KEM: Create encap and decap keys
    ek, dk = dhkem.keygen()
    local_data[user]['kem_keys'] = (ek, dk)

    return ek

def receive_message(to_user, from_user, cipher_email, iv, capsule, sign):
    # Bob (Decrypts key and decrypts email)
    sk = local_data[to_user]['kem_keys'][1]

    chacha20_key = dhkem.decapsulate(capsule, sk) # Decapsulate the capsule and get Chacha20 key
    msg = ch20.encrypt(cipher_email, chacha20_key, iv).decode() # Chacha20 decrypt message

    ## Verify signature
    if rs.verify(msg, sign, public_data[from_user]['rabin_n']):
        local_data[to_user]['messages'].append(msg)

def check_password(username1, password1):
    with open("data.json", "r") as f:
        data = json.load(f)
    for user in data["users"]:
        if user["username"] == username1:
            return user["password"] == password1
    return False


def clear_console_subprocess():
    if platform.system() == "Windows":
        subprocess.run("cls", shell=True)
    else:
        # For Linux and Mac
        subprocess.run("clear", shell=True)

START_MSG = 'Welcome!\n1. Login\n2. Exit\n\n'
LOGGED_MSG = '\n1. Send Message\n2. Read Messages\n3. Log Out\n4. Exit\n\n'

clear_console_subprocess()

def main():
    global current_user

    # Here we simulate rabin keys, one saved in database and one locally
    # Realistically this would be already present for registered users
    for user in local_data.keys():
        rabin_n, rabin_sk = rs.keygen(512) # This would idealy be 2048, but for the sake of performance let's imagine this is 2048 and not 512
        public_data[user]['rabin_n'] = rabin_n # This would be public to each so users can verify other users
        local_data[user]['rabin_sk'] = rabin_sk # This would be private of course

    start_action = int(input(START_MSG))
    while start_action != 2:
        clear_console_subprocess()
        username = input('Enter Username: ')
        password = getpass.getpass('Enter Password: ')
        if not check_password(username, str(sh.hash_message_hex(password))):
            clear_console_subprocess()
            print("Username or password is incorrect.\n")
            start_action = int(input("Try Again?\n1. Yes\n2. No\n\n"))
        else:
            clear_console_subprocess()
            current_user = username
            print(f'Welcome {current_user}!')
            action = input(LOGGED_MSG)
            while True:
                clear_console_subprocess()

                if action == '1':
                    print("Contact List:\n")
                    counter = 0
                    for user in local_data.keys():
                        if user != current_user:
                            counter += 1
                            print(f"{counter}. {user}")

                    to_user1 = input('\nTo: ')
                    while to_user1 not in local_data:
                        to_user1 = input('User does not exist! please try again! \nEnter Username: ')

                    if to_user1 in local_data:
                        subject = input("Subject: ")
                        msg = input('Message: ')
                        send_message(to_user1, f'\tSubject: {subject}\n\tMessage: {msg}')

                        clear_console_subprocess()
                        print("Message sent successfully")
                elif action == '2':
                    if not local_data[current_user]['messages']:
                        print("Your inbox is empty.")
                    else:
                        print(f"Inbox:")
                        for i, msg in enumerate(local_data[current_user]['messages'], start=1):
                            print(f"{i}.\n{msg}")
                elif action == '3':
                    print("Logged out successfully\n")
                    start_action = int(input(START_MSG))
                    break
                elif action == '4':
                    start_action = 2
                    break
                action = input(LOGGED_MSG)

        print("Good bye!")

main()