# The code uses sha256 algorithm to encrypt and decrypt a message.
# The message is encrypted and stored in a file encrypt.message
# The key is stored in a file secret.key

# assumptions:  cryptography module is installed in the virtualenv/OS (pip install cryptography),
#               Encrypting one message at a time

"""
Usage: this tool can be run from command line by passing argument as follows:

Encryption: python nautics.py --encrypt --message <some_message>
Decryption: python nautics.py --decrypt --message_file encrypted.message
"""

import argparse
from cryptography.fernet import Fernet

def generate_key():
    """
    Utility to generate and write key to file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as my_key:
        my_key.write(key)
    return key


def load_key():
    """
    Utility function to load the previously generated key
    """
    return open("secret.key", "rb").read()


def encrypt_message(message):
    """
    Encrypts a message and writes it to a file
    """
    key = generate_key()

    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    with open("encrypted.message", "wb") as my_message:
        my_message.write(encrypted_message)

    print ("Message encrypted and save to file encrypt.message")
    # print (encrypted_message)
    return None


def decrypt_message(encrypted_message_file="encrypted.message"):
    """
    Reads an encrypted message from file and decrypts it
    Excpetion if file doesn't exist
    """
    try:
        encrypted_message = open(encrypted_message_file, "rb").read()
    except Exception as e:
        print (str(e))
        return "Error opening file"

    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)

    print("The decoded message is: %s" % decrypted_message.decode())

    return decrypted_message.decode()



parser = argparse.ArgumentParser()
parser.add_argument("--encrypt", action="store_true")
parser.add_argument("--decrypt", action="store_true")
parser.add_argument("--message")
parser.add_argument("--message_file")

args = parser.parse_args()

if args.encrypt and args.message:
    encrypt_message(args.message)
elif args.decrypt and args.message_file:
    decrypt_message(args.message_file)
else:
    print ("Please enter valid arguments")
