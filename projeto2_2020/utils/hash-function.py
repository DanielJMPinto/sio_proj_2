from argparse import ArgumentParser
from cryptography.hazmat.primitives import hashes


def hash(sorceFile_name, hashFunction_name):
    #define hash funcition
    if hashFunction_name == "MD5":
        hashFunction = hashes.MD5()
    elif hashFunction_name == "SHA-384":
        hashFunction = hashes.SHA384()
    elif hashFunction_name == "SHA-512":
        hashFunction = hashes.SHA512()
    elif hashFunction_name == "BLAKE-2":
        hashFunction = hashes.BLAKE2s(32)
    else:
        hashFunction = hashes.SHA256()
    #block length
    blockLength = 32
    #open sorce file
    sorceFile = open(sorceFile_name, 'r')
    #messa digest init
    digest = hashes.Hash(hashFunction)
    block = "."
    while block != "":
        #read block
        block = sorceFile.read(blockLength)
        #update digest
        digest.update(block.encode())
    #get hash
    h = digest.finalize()
    #close file
    sorceFile.close()

    return h
####################################################################################################

hashFunctions = ["SHA-256", "SHA-384", "SHA-512", "MD5", "BLAKE-2"]
