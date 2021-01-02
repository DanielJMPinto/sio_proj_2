import os
from math import ceil
from argparse import ArgumentParser
from base64 import b64encode, b64decode
from getpass import getpass
from secrets import token_bytes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes 
from cryptography.hazmat.backends import default_backend




def addPadding(messageBlock, algorithm_name):
    #select block length
    if algorithm_name == "3DES":
        LengthBlock = 8
    else:
        #AES-128
        LengthBlock = 16
    #missing space to complete block
    sizePadding = LengthBlock - (len(messageBlock) % LengthBlock)
    #block with de correct length -> message + padding
    messageBlock = messageBlock + bytes([sizePadding]*sizePadding)
    return messageBlock  
####################################################################################################

def removepadding(messageBlock):
    #select block length
    LengthBlock = len(messageBlock)
    #descovering the size of padding used
    sizePadding = int(messageBlock[-1])
    #removing padding
    messageBlock = messageBlock[:LengthBlock - sizePadding]
    return messageBlock 
####################################################################################################

def generate_key(algorithm_name, salt, password):  
    #password string to binary
    if type(password) != type(b""):
        password = password.encode()    

    #select key length
    if algorithm_name == '3DES':
        length = 24
    elif algorithm_name == 'ChaCha20':
        length = 32
    else:
        #AES-128
        length = 16
    pbkdf = PBKDF2HMAC(
        salt=salt,
        algorithm=hashes.SHA256(),
        iterations=10**5,
        length=length,
        backend=default_backend()
    )

    #generate key
    key = pbkdf.derive(password)    #type key == byte

    return key
####################################################################################################

def encrypt(password, message, algorithm_name, cipherMode_name=None):
    #encode message
    if type(message) != type(b""):
        message = message.encode()    

    #generate salt
    salt = os.urandom(16)
    #gemerate key
    key = generate_key(algorithm_name, salt, password)
    #algorithm and block length
    if algorithm_name == 'ChaCha20':
        nonce = token_bytes(16)
        algorithm = algorithms.ChaCha20(key, nonce)
        #chacha20 dont use block, but i will divide the message in blocks 
        blockLength = 128
    elif algorithm_name == '3DES':
        blockLength = 8
        algorithm = algorithms.TripleDES(key)
    else:
        #AES-128
        blockLength = 16
        algorithm = algorithms.AES(key)
    #gemerate iv
    iv = None
    if algorithm_name != "ChaCha20" and cipherMode_name != "ECB":
        iv = token_bytes(blockLength)
    #cipher mode
    if cipherMode_name == "CBC":
        cipher_mode = modes.CBC(iv)
    elif cipherMode_name == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode_name == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode_name == "ECB":
        cipher_mode = modes.ECB()
    else:
        #chacha20 -> no use cipher mode
        cipher_mode = None
    #cipher definition
    cipher = Cipher(algorithm, cipher_mode)
    #encrypt init
    encryptor = cipher.encryptor()
    #encrypted_message
    encrypted_message = b""
    #write salt, iv and nonce
    encrypted_message = encrypted_message + b64encode(salt)
    if iv != None:
        encrypted_message = encrypted_message + b64encode(iv)
    if algorithm_name == "ChaCha20":
        encrypted_message = encrypted_message + b64encode(nonce)
    #pointer to read message as blocks
    pointer = 0
    while True:
        block = message[pointer:pointer+blockLength]
        pointer += blockLength
        #last block length == blocklength
        if block == "":
            break
        #last block length < blockLength
        if len(block) != blockLength:
            break
        #encrypt block
        block = encryptor.update(block)
        #write
        encrypted_message = encrypted_message + b64encode(block)
    #padding
    if algorithm_name != "ChaCha20":
        block = addPadding(block, algorithm_name)
    #encrypt block
    block = encryptor.update(block)
    #write
    encrypted_message = encrypted_message + b64encode(block)

    return encrypted_message
####################################################################################################

def decrypt(password, encrypted_message, algorithm_name, cipherMode_name=None):
    message = ""
    #pointer to read message as blocks
    pointer = 0
    #get salt
    salt = encrypted_message[pointer:pointer+ceil(16/3)*4]
    pointer += ceil(16/3)*4
    salt = b64decode(salt)
    #gemerate key
    key = generate_key(algorithm_name, salt, password)
    #algorithm and block length
    if algorithm_name == 'ChaCha20':
        #geting nonce
        nonce = encrypted_message[pointer:pointer+ceil(16/3)*4]
        pointer += ceil(16/3)*4
        nonce = b64decode(nonce)
        algorithm = algorithms.ChaCha20(key, nonce)
        #chacha20 dont use block, but i will divide the message in blocks 
        blockLength = 128
    elif algorithm_name == '3DES':
        blockLength = 8
        algorithm = algorithms.TripleDES(key)
    else:
        #AES-128
        blockLength = 16
        algorithm = algorithms.AES(key)
    #get iv
    if algorithm_name != "ChaCha20" and cipherMode_name != "ECB":
        iv =  encrypted_message[pointer:pointer+ceil(blockLength/3)*4]
        pointer+=ceil(blockLength/3)*4
        iv = b64decode(iv)
    #cipher mode
    if cipherMode_name == "CBC":
        cipher_mode = modes.CBC(iv)
    elif cipherMode_name == "CFB":
        cipher_mode = modes.CFB(iv)
    elif cipherMode_name == "OFB":
        cipher_mode = modes.OFB(iv)
    elif cipherMode_name == "ECB":
        cipher_mode = modes.ECB()
    else:
        #chacha20 -> dont use cipher mode
        cipher_mode = None
    #cipher definition
    cipher = Cipher(algorithm, cipher_mode)
    #decrypt init
    decryptor = cipher.decryptor()
    
    nextBlock = b64decode(encrypted_message[pointer:pointer+ceil(blockLength/3)*4])
    pointer+=ceil(blockLength/3)*4
    while True:
        block = nextBlock
        nextBlock = b64decode(encrypted_message[pointer:pointer+ceil(blockLength/3)*4])
        pointer+=ceil(blockLength/3)*4
        #decrypt block
        block = decryptor.update(block)
        #block == last block
        if nextBlock == b"":
            break
        #write
        message = message + block.decode()
    #padding
    if algorithm_name != "ChaCha20":
        block = removepadding(block)
    #write
    message = message + block.decode()

    return message
####################################################################################################

#suported algorithm and cipher modes
cipherModes = ["ECB", "CBF","CBC", "OFB"]
cipherAlgorithms = ['3DES','AES-128','ChaCha20']
