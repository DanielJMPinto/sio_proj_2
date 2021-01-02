import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import random

sys.path.append(os.path.abspath('../cryptography'))
import diffiehellman
import symmetriccrypt


logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def cryptography():
    #diffie-hellman 
    #get dh parameters
    req = requests.get(f'{SERVER_URL}/api/dh-parameters')
    if req.status_code == 200:
        print("Got dh-parameters")
    dh_parameters = req.json()
    #generate private key
    dh_private_key = diffiehellman.dh_generate_private_key(dh_parameters)
    #public number y
    dh_public_number_y = diffiehellman.dh_generate_public_key(dh_private_key)
    
    #get server public number
    req = requests.post(f'{SERVER_URL}/api/dh-handshake', data=json.dumps([dh_public_number_y]).encode('latin'))   
    if req.status_code == 200:
        print("Got server public number")
    server_public_number_y = req.json()[0]
    
    #calculate secret key to encrypt comunication
    secret_key = diffiehellman.dh_calculete_common_secret(dh_private_key,server_public_number_y)
    print("Calculated secret key to encrypt comunication")
    
    #Negotiate a cipher suite
    req = requests.get(f'{SERVER_URL}/api/cipher-suite')
    if req.status_code == 200:
        print("Got ciphers list")
    cipher_list = req.json()
    #chose cipher to be used
    cipher_list[0] = random.choice(cipher_list[0])  # Algorithm , 
    if cipher_list[0] == 'ChaCha20':
        cipher_list[1] = None
    else:
        cipher_list[1] = random.choice(cipher_list[1])  # Cipher Mode
    cipher_list[2] = random.choice(cipher_list[2])  # Hash Functions
    print(f"chosen ciphers:\n\tAlgorithm: {cipher_list[0]}\n\tCipher Mode: {cipher_list[1]}\n\tHash Function: {cipher_list[2]}")
    #comunicate chosen ciphers to server
    req = requests.post(f'{SERVER_URL}/api/chosen-ciphers', data=json.dumps(cipher_list).encode('latin'))   
    if req.status_code == 200:
        print("Got server encrypted message")
    message = req.json()
    message = message["data"].encode('latin')
    #decrypt message
    message = symmetriccrypt.decrypt(secret_key,message,cipher_list[0], cipher_list[1])
    print(f"server message:  {message}")

    return dh_parameters, dh_private_key, secret_key, cipher_list

def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    #stablish cryptography with server 
    dh_parameters, dh_private_key, secret_key, cipher_list = cryptography()

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")

    media_list = req.json()


    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
    print("----")

    while True:
        selection = input("Select a media file number (q to quit): ")
        if selection.strip() == 'q':
            sys.exit(0)

        if not selection.isdigit():
            continue

        selection = int(selection)
        if 0 <= selection < len(media_list):
            break

    # Example: Download first file
    media_item = media_list[selection]
    print(f"Playing {media_item['name']}")

    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)