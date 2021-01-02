from argparse import ArgumentParser
from getpass import getpass
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def generate_rsa_public_key(private_key, fileToSave_name=None):
    #generate public key
    public_key = private_key.public_key()
    if fileToSave_name != None:
        #serialization
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo)
        #write public key
        fileToSave_public_key = open(fileToSave_name, 'wb')
        fileToSave_public_key.write(pem)
        fileToSave_public_key.close()
    return public_key
####################################################################################################

def generate_rsa_private_key(keySize, fileToSave_name=None, password=None):
    #gemerate private key
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=keySize)
    #serialization
    if fileToSave_name != None:    
        #encryptation
        if password != None:
            password = password.encode()
            encrypt_algorithm = serialization.BestAvailableEncryption(password) 
        else:
            encrypt_algorithm = serialization.NoEncryption()
        #private bytes
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                        encryption_algorithm=encrypt_algorithm)
        #write private key
        fileToSave_private_key = open(fileToSave_name,'wb')
        fileToSave_private_key.write(pem)
        fileToSave_private_key.close()

    return private_key
####################################################################################################


def generate_rsa_key_pair(keySize,fileToSave_name=None, password=None):
    #private key
    private_key = generate_rsa_private_key(keySize, fileToSave_name,password)
    #public key
    if fileToSave_name != None:
        fileToSave_name = str(fileToSave_name+".pub")
    public_key = generate_rsa_public_key(private_key,fileToSave_name)
    
    return(private_key, public_key)
####################################################################################################

def load_rsa_public_key(sorceFile_name):
    #open public key file
    key_file = open(sorceFile_name, 'rb')
    #load public key
    public_key = serialization.load_pem_public_key(key_file.read())
    #close public key file
    key_file.close()

    return public_key
####################################################################################################

def load_rsa_private_key(sorceFile_name, password=None):
    #encode password
    if password != None:
        password = password.encode()
    #open private key file
    key_file = open(sorceFile_name, 'rb')
    private_key = serialization.load_pem_private_key(key_file.read(),
                                                     password=password)
    #close private key file
    key_file.close()

    return private_key
####################################################################################################

def rsa_sign(private_key,message):
    #message = message.encode()
    signature = private_key.sign(message,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                             salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA384())
    return signature
####################################################################################################

def rsa_verify(public_key, message, signature):
    #message = message.encode()
    try:
        public_key.verify(signature,
                      message,
                      padding.PSS(mgf=padding.MGF1(hashes.SHA384()),
                                  salt_length=padding.PSS.MAX_LENGTH),
                      hashes.SHA384())
    except:
        #print("invalid signature")
        return False
    else:
        #print("valid signature")
        return True
####################################################################################################    

def rsa_encryption(message, public_key, hashFunction_name=None):
    #define hash funcition
    if hashFunction_name == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hashFunction_name == "SHA-512":
        hashFunction = hashes.SHA512()
    else:
        hashFunction = hashes.SHA256()
    #encode message
    message = message.encode()
    #encryption
    ciphertext = public_key.encrypt(message,
                                    padding.OAEP(mgf=padding.MGF1(hashFunction),
                                                 algorithm=hashFunction,
                                                 label=None))
    return ciphertext
####################################################################################################    
def rsa_decryption(ciphertext, private_key,hashFunction_name=None):
    #define hash funcition
    if hashFunction_name == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hashFunction_name == "SHA-512":
        hashFunction = hashes.SHA512()
    elif hashFunction_name == "BLAKE-2":
        hashFunction = hashes.BLAKE2s(32)
    else:
        hashFunction = hashes.SHA256()
    #decryption
    plaintext = private_key.decrypt(ciphertext,
                                    padding.OAEP(mgf=padding.MGF1(algorithm=hashFunction),
                                                 algorithm=hashFunction,
                                                 label=None))
    #decode message
    plaintext = plaintext.decode()
    return plaintext
####################################################################################################    

hashFunctions = ["SHA-256", "SHA-384", "SHA-512"]




