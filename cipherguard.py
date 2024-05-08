#!/usr/bin/env python3

import os
import sys
import argparse
from argparse import RawDescriptionHelpFormatter
from cryptography.fernet import Fernet

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

args = parser.parse_args()
###

### Files to encrypt / decrypt
files = []
if args.file:
    files = args.file
else:
    files = [x for x in os.listdir() if os.path.isfile(x)]

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

### Perform encryption / decryption
if args.encrypt:
    print('Encrypting...')
    # Key generation
    key = Fernet.generate_key()
    with open('key.key', 'wb') as f:
        f.write(key)

    fernet = Fernet(key)

    for file in files:
        if os.path.isfile(file) and file != 'cipherguard.py' and file != 'key.key':
            encrypted = ''
            with open(file, 'rb') as f:
                encrypted = fernet.encrypt(f.read())
            with open(file, 'wb') as f:
                f.write(encrypted)
            if args.log:
                print(file)
elif args.decrypt:
    try:
        print('Decrypting...')
        # Obtain key
        key = ''
        with open('key.key', 'rb') as f:
            key = f.read().decode('utf-8')
        fernet = Fernet(key)

        for file in files:
            if os.path.isfile(file) and file != 'cipherguard.py' and file != 'key.key':
                decrypted = ''
                with open(file, 'rb') as f:
                    decrypted = fernet.decrypt(f.read())
                with open(file, 'wb') as f:
                    f.write(decrypted)
                if args.log:
                    print(file)
    except:
        print('Error decrypting', file=sys.stderr)
        sys.exit(1)
###