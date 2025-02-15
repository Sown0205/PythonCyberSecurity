# AES Cryptography Tool
This is my second program in this repo. It is a cryptograohy program that can encrypt the input file, generates a key to decrypt the file if the user wants to.

## Overview
This Python program illustrates a simple cryptography tool that can read a text file, encrypts it and generate a key for decryption later (if users want to).

The program use AES-256 encryption technique in CBC mode with a 32-bit AES key size, enhancing security for the file

Users then can save the key into a file if needed

To decrypt an encrypted file, input the encrypted file path, input the correct key provided earlier, then the program will automatically decrypt the file and returns the orginal file

## Required libraries and Modules

These modules and libraries are required to run the code

- argparse: Handles argument parses from the Linux CLI

- cryptography: Provides essential modules for cryptographic functions (encrypt, decrypt)

- os: Handles with files

To import these, open cmd and type

```bash
pip install argparse os cryptography
```

## How to run

You can clone this repo and use the code from the main file

```bash
git clone https://github.com/Sown0205/PythonCyberSecurity.git
sudo python3 AES_Cryptography_Tool.py <encrypt or decrypt>
```
There are 2 options: encrypt and decrypt

If users want to encrypt a file, type

```bash
sudo python3 AES_Cryptography_Tool.py encrypt
```

The program then will prompts the user to enter the file path that they want to encrypt:

```bash
Enter the file to encrypt: <path/to/your/file>
```

If file path not found, it will return an error

Else, the program will encrypt the file, generates a random 32-bit key size, and deletes the original file to erase track

The user then can save the key into a file if they want

```bash
Do you want to save the key to a file? (yes/no):
```