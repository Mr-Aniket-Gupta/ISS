



















































# Practical 1 Python program to illustrate Caesar Cipher Technique
text = input("Enter text: ")
shift = int(input("Enter shift value: "))
result = ""

for ch in text:
    if ch.isalpha():
        base = ord('A') if ch.isupper() else ord('a')
        result += chr((ord(ch) - base + shift) % 26 + base)
    else:
        result += ch

print("Encrypted text:", result)







# Practical 2 Python Code for implementing Railfence Cipher
def RailFence(txt):
    result = ""
    for i in range(len(txt)):
        if i % 2 == 0:
            result += txt[i]

    for i in range(len(txt)):
        if i % 2 != 0:
            result += txt[i]
    return result

string = input("Enter a string: ")
print("Encrypted:", RailFence(string))








# practical 3 Write a python code for implementing RSA Encryption and Decryption Algorithm.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

# Generate RSA key pair (1024 bits)
keyPair = RSA.generate(1024)

# Public key
pubKey = keyPair.publickey()
print(f"Public key: (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))

# Private key
print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))

# Message to encrypt (must be in bytes)
msg = b'Ismile Academy'

# Encryption
encryptor = PKCS1_OAEP.new(pubKey)
encrypted = encryptor.encrypt(msg)
print("Encrypted:", binascii.hexlify(encrypted))

# Decryption
decryptor = PKCS1_OAEP.new(keyPair)
decrypted = decryptor.decrypt(encrypted)
print("Decrypted:", decrypted.decode('utf-8'))





# Practical 4 Write a python code for implementing MD5 Algorithm
import hashlib

# Create MD5 hash objects
result = hashlib.md5(b'Ismile')
result1 = hashlib.md5(b'Esmile')

# Print the byte equivalent of the MD5 hashes
print("The byte equivalent of MD5 hash for 'Ismile' is:", result.digest())
print("The byte equivalent of MD5 hash for 'Esmile' is:", result1.digest())

# Print the hexadecimal equivalent (easier to read)
print("The hexadecimal equivalent of MD5 hash for 'Ismile' is:", result.hexdigest())
print("The hexadecimal equivalent of MD5 hash for 'Esmile' is:", result1.hexdigest())







# Practical 5 Write a python code for implementing SHA Algorithm
import hashlib

# Get input from the user
input_str = input("Enter the value to encode: ")

# Encode the input and generate SHA1 hash
result = hashlib.sha1(input_str.encode())

# Print the SHA1 hash in hexadecimal format
print("The hexadecimal equivalent of SHA1 is:")
print(result.hexdigest())







# Practical 6 Python code for implementing Diffie-Hellman Algorithm

P = 23  # Prime number (public)
G = 9   # Primitive root (public)

# Alice chooses a private key
a = 4
# Bob chooses a private key
b = 6

# Calculate public keys
x = (G ** a) % P  # Alice's public key
y = (G ** b) % P  # Bob's public key

# Exchange public keys and generate shared secret
ka = (y ** a) % P  # Secret key for Alice
kb = (x ** b) % P  # Secret key for Bob

print("Publicly Shared Values: P =", P, " G =", G)
print("Alice's Private Key:", a)
print("Bob's Private Key:", b)
print("Alice's Public Key:", x)
print("Bob's Public Key:", y)
print("Secret Key for Alice:", ka)
print("Secret Key for Bob:", kb)








# Practical 7 Write a python code implementing Hill Cipher Algorithm.
# Initialize matrices
keyMatrix = [[0] * 3 for i in range(3)]
messageVector = [[0] for i in range(3)]
cipherMatrix = [[0] for i in range(3)]

# Function to generate key matrix from key string
def getKeyMatrix(key):
    k = 0
    for i in range(3):
        for j in range(3):
            keyMatrix[i][j] = ord(key[k]) % 65
            k += 1

# Function to encrypt the message
def encrypt(messageVector):
    for i in range(3):
        cipherMatrix[i][0] = 0
        for x in range(3):
            cipherMatrix[i][0] += keyMatrix[i][x] * messageVector[x][0]
        cipherMatrix[i][0] = cipherMatrix[i][0] % 26

def HillCipher(message, key):
    # Generate key matrix
    getKeyMatrix(key)

    # Generate message vector
    for i in range(3):
        messageVector[i][0] = ord(message[i]) % 65

    # Encrypt the message
    encrypt(messageVector)

    # Generate ciphertext
    CipherText = []
    for i in range(3):
        CipherText.append(chr(cipherMatrix[i][0] + 65))

    print("Ciphertext:", "".join(CipherText))

# Driver code
def main():
    message = "ACT"
    key = "GYBNQKURP"
    HillCipher(message, key)

if __name__ == "__main__":
    main()






# Practical 8 Write a python code implementing monoalphabetic chipper
# Simple Python program for Monoalphabetic Cipher

import string
import random

# Create alphabet and random key
alphabet = string.ascii_uppercase
key = ''.join(random.sample(alphabet, len(alphabet)))

def encrypt(plaintext):
    plaintext = plaintext.upper()
    ciphertext = ''
    for ch in plaintext:
        if ch.isalpha():
            ciphertext += key[alphabet.index(ch)]
        else:
            ciphertext += ch
    return ciphertext

def decrypt(ciphertext):
    plaintext = ''
    for ch in ciphertext:
        if ch.isalpha():
            plaintext += alphabet[key.index(ch)]
        else:
            plaintext += ch
    return plaintext

# Example
text = "HELLO"
print("Original Text:", text)
print("Key:", key)

encrypted = encrypt(text)
print("Encrypted Text:", encrypted)

decrypted = decrypt(encrypted)
print("Decrypted Text:", decrypted)







