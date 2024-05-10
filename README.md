# CipherGuard
File encryption / decryption Python script.

---
# Setup
Download `cipherguard.py` and execute the script from a terminal.

Example:

```./cipherguard.py -h```

or

```python3 cipherguard.py -h```

---
# Usage
Display CipherGuard options with the help flag: `./cipherguard.py -h` or `./cipherguard.py --help`.

## Encrypting
Encrypt all files in the same directory as `cipherguard.py`.

```./cipherguard.py -e```

After encrypting, a new file `key.key` will be generated in the same directory as `cipherguard.py`, containing the decryption key to the encrypted files.

## Decrypting
Decrypt all files in the same directory as `cipherguard.py`.

```./cipherguard.py -d```

The key in `key.key` in the same directory key as `cipherguard.py` will be used to decrypt the files.
The key in `key.key` used to decrypt must be the same key that was generated when encrypting the files to recover the original files.

## Other Options
### Recursion
```./cipherguard.py -er```

```./cipherguard.py -dr```

Recursively encrypt / decrypt files in each sub-directory relative to the directory of the `cipherguard.py` file.

Example:
```
.
├── README.md
├── a.txt
├── cipherguard.py
├── folder1
│   ├── folder2
│   └── important.txt
├── key.key
├── b.txt
└── test.txt
```
`./cipherguard.py -er` will encrypt all files in the current directory, files in `folder1`, and files in `folder2`.

### Specify Files in Command-line Arguments
```./cipherguard.py -ef <file1> <file2> ...```

```./cipherguard.py -df <file1> <file2> ...```

Encrypts / decrypts only the files provided in the command-line arguments.

## Password-Based Encryption
CipherGuard supports encryption / decryption of files using password-based encryption (PBE).

Users can specify a passphrase to encrypt their files with, using the same passphrase to decrypt the files, eliminating the need to physically store the encryption keys.

```./cipherguard.py -ep myPassword```

```./cipherguard.py -dp myPassword```
