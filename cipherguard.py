#!/usr/bin/env python3

import os
import sys
import argparse
import base64
from argparse import RawDescriptionHelpFormatter
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

### Argument Handling
desc = '''
_________ .__       .__                    ________                       .___
\_   ___ \|__|_____ |  |__   ___________  /  _____/ __ _______ _______  __| _/
/    \  \/|  \____ \|  |  \_/ __ \_  __ \/   \  ___|  |  \__  \\_  __ \/ __ | 
\     \___|  |  |_> >   Y  \  ___/|  | \/\    \_\  \  |  // __ \|  | \/ /_/ | 
 \______  /__|   __/|___|  /\___  >__|    \______  /____/(____  /__|  \____ | 
        \/   |__|        \/     \/               \/           \/           \/ 
'''

parser = argparse.ArgumentParser(
    prog='CipherGuard',
    description=desc + 'File encryption and decryption software.',
    epilog='Written by Nelson Lin',
    add_help=True,
    formatter_class=RawDescriptionHelpFormatter
)

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-e', '--encrypt', action='store_true', help='File encryption mode')
group.add_argument('-d', '--decrypt', action='store_true', help='File decryption mode')

parser.add_argument('-l', '--log', action='store_true', help='Print encryption / decryption log')
parser.add_argument('-r', '--recursive', action='store_true', help='Recursively encrypt / decrypt files in each subdirectory')
parser.add_argument('-f', '--file', nargs='+', help='Specify a file to encrypt / decrypt')
parser.add_argument('-p', '--password', nargs=1, help='Specify a passphrase key to encrypt / decrypt the files with')

args = parser.parse_args()
###

### Files to encrypt / decrypt
files = []
if args.file:
    files = args.file
else:
    files = [x for x in os.listdir() if os.path.isfile(x) and x != 'cipherguard.py' and x != 'key.key']

def recurse_dir(dirname):
    global files
    for file in os.listdir(dirname):
        file = dirname + '/' + file
        if os.path.isfile(file):
            files.append(file)
        elif os.path.isdir(file):
            recurse_dir(file)

if args.recursive:
    for file in os.listdir():
        if os.path.isdir(file) and file != '.git':
            dirname = './' + file
            recurse_dir(dirname)

if args.log:
    print(files)
###

# Password-based key
key = None
iv = None
if args.password and args.encrypt:
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        iterations=480000,
    )
    password = args.password[0].encode('utf-8')
    key = base64.urlsafe_b64encode(kdf.derive(password))
###

### Helpers
def get_pbk(iv):
    password = None
    if args.password:
        password = args.password[0].encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=iv,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def read_key_file():
    try:
        with open('key.key', 'rb') as f:
            key = f.read().decode('utf-8')
        return key
    except:
        print('Error: key.key file does not exist', file=sys.stderr)
        sys.exit(1)

def get_file_iv(file):
    try:
        with open(file, 'rb') as f:
            bytes = f.read()
            iv = bytes.split(b'\n')[1]
            key = get_pbk(iv)
            print(key)
            fernet = Fernet(key)
        return fernet
    except:
        print(f'Error: Cannot decrypt {file}. No IV was found in the file', file=sys.stderr)
###

### Perform encryption / decryption
if args.encrypt:
    print('Encrypting...')
    # Key generation
    if not key:
        key = Fernet.generate_key()
        with open('key.key', 'wb') as f:
            f.write(key)

    fernet = Fernet(key)

    for file in files:
        encrypted = ''
        with open(file, 'rb') as f:
            encrypted = fernet.encrypt(f.read())
        with open(file, 'wb') as f:
            f.write(encrypted)
            if iv:
                f.write('\n'.encode('utf-8'))
                f.write(iv)
        if args.log:
            print(file)
elif args.decrypt:
    print('Decrypting...')
    # Obtain key
    if not key:
        key = read_key_file()
    
    fernet = None
    if key:
        fernet = Fernet(key)

    # Files that could not be decrypted
    decrypt_error_files = list()
    for file in files:
        if args.password:
            fernet = get_file_iv(file)

        decrypted = ''
        try:
            with open(file, 'rb') as f:
                decrypted = fernet.decrypt(f.read())
            with open(file, 'wb') as f:
                f.write(decrypted)
            if args.log:
                print(file)
        except:
            decrypt_error_files.append(file)
            continue

    if decrypt_error_files:
        print(f'Could not decrypt files: {decrypt_error_files}')
###