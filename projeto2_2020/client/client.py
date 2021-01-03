import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
import random

sys.path.append(os.path.abspath('../utils'))
import utils
import rsa_utils
import diffiehellman
import symmetriccrypt
import PyKCS11
import base64
from cryptography.x509 import ObjectIdentifier
from cryptography.hazmat.primitives import serialization



logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'
CLIENT_OID = ''

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
    message = symmetriccrypt.decrypt(secret_key,message,cipher_list[0], cipher_list[1]).decode()
    print(f"server message:  {message}")

    return dh_parameters, dh_private_key, secret_key, cipher_list



def auth():
    global CLIENT_OID
    client_nonce = os.urandom(64)
    #encrypt nonce
    encrypted_client_nonce = symmetriccrypt.encrypt(secret_key, client_nonce, cipher_list[0], cipher_list[1]).decode('latin')

    req = requests.post(f'{SERVER_URL}/api/server_auth', data=json.dumps({"nonce":encrypted_client_nonce}).encode())
    if req.status_code == 200:
       print("Received Server Certificate and Signed Nonce")
    
    
    #validate server certs
    data = req.json()
    
    #decrypt data
    server_nonce = data["server_nonce"].encode('latin')
    server_nonce = symmetriccrypt.decrypt(secret_key, server_nonce, cipher_list[0], cipher_list[1])
    signed_client_nonce = data["signed_client_nonce"].encode('latin')
    signed_client_nonce = symmetriccrypt.decrypt(secret_key, signed_client_nonce, cipher_list[0], cipher_list[1])
    server_certificate = data["server_certificate"].encode('latin')
    server_certificate = symmetriccrypt.decrypt(secret_key, server_certificate, cipher_list[0], cipher_list[1])
    
    
    server_certificate = utils.certificate_object_from_pem(server_certificate)
    
    cert_data = utils.load_cert_from_disk("../server_ca/SIOServerCA.pem")
    cert = utils.certificate_object_from_pem(cert_data)

    certificates={}
    certificates[cert.subject.rfc4514_string()] = cert

    chain=[]
    chain_completed = utils.build_certificate_chain(chain, server_certificate, certificates)
    
    if not chain_completed:
        print("Couldn't complete the certificate chain")
        return False
        
    else:
        valid_chain, error_messages = utils.validate_certificate_chain(chain)

        if not valid_chain:
            print(error_messages)
            return False  
        else:
            if not utils.verify_signature(server_certificate, signed_client_nonce, client_nonce):
                return False
    
    print("Sucsessfuly validated the server certicate chain and nonce signed by the server")
    #send cc info
    session_success, session_data = utils.cc_session()

    if not session_success:
        print("Error establishing a new citizen card session: {session_data}")
        return False
    print("Citizen Card Session Open")
    client_cert = utils.certificate_cc(session_data)
    

    
    #encrypt client certs
    client_cert_enc = symmetriccrypt.encrypt(secret_key, client_cert, cipher_list[0], cipher_list[1]).decode('latin')
    signed_server_nonce = utils.sign_nonce_cc(session_data, server_nonce)
    signed_server_nonce_enc = symmetriccrypt.encrypt(secret_key, signed_server_nonce, cipher_list[0], cipher_list[1]).decode('latin')
    
    client_certs = {}
    client_certs["client_cc_certificate"] = client_cert_enc
    client_certs["signed_server_nonce"] = signed_server_nonce_enc

    #finalize auth
    req = requests.post(f'{SERVER_URL}/api/client_auth', data=json.dumps(client_certs).encode())
    if req.status_code == 200:
       print("Server finished citizen card certificatcion chain")
    
    data = req.json()
    status = symmetriccrypt.decrypt(secret_key, data["status"], cipher_list[0], cipher_list[1])
    if  status.decode() == "True":
        print("Sucessfully authenticated CC")
        oid = ObjectIdentifier("2.5.4.5")
        CLIENT_OID = utils.certificate_object(client_cert).subject.get_attributes_for_oid(oid)[0].value
        return True
    else:
        print("Could not authenticated CC")
        return False

    
def rsa_exchange():
    private_key, public_key = rsa_utils.generate_rsa_key_pair(2048, "../client_rsa_keys/client_rsa_key")

    pubk_enc = symmetriccrypt.encrypt(
        secret_key, 
        public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), 
        cipher_list[0], 
        cipher_list[1]
    ).decode('latin')

    req = requests.post(f'{SERVER_URL}/api/rsa_exchange', 
            data=json.dumps({
                "client_rsa_pub_key": pubk_enc
            }).encode()
        )

    if req.status_code == 200:
       print("Received Server public rsa Key ")

    data = req.json()

    server_rsa_pub_key = data["server_rsa_pub_key"].encode()
    server_rsa_pub_key = symmetriccrypt.decrypt(secret_key, server_rsa_pub_key, cipher_list[0], cipher_list[1])

    fileToSave_public_key = open("../client_rsa_keys/server_rsa_pub_key.pub", 'wb')
    fileToSave_public_key.write(server_rsa_pub_key)
    fileToSave_public_key.close()


def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session
    headers = {"oid":CLIENT_OID}

    request = requests.Session()
    request.headers.update(headers)
    
    req = request.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")
    else:
        print(symmetriccrypt.decrypt(secret_key, req.json(), cipher_list[0], cipher_list[1]).decode())
        sys.exit(0)

    media_list_enc = req.json()
    media_list = []
    id = 0
    for item in media_list_enc:
        media_list.append({
            "id" : symmetriccrypt.decrypt(secret_key, media_list_enc[id]["id"], cipher_list[0], cipher_list[1]).decode(),
            "name" : symmetriccrypt.decrypt(secret_key, media_list_enc[id]["name"], cipher_list[0], cipher_list[1]).decode(),
            "description" : symmetriccrypt.decrypt(secret_key, media_list_enc[id]["description"], cipher_list[0], cipher_list[1]).decode(),
            "chunks" : int(symmetriccrypt.decrypt(secret_key, media_list_enc[id]["chunks"], cipher_list[0], cipher_list[1]).decode()),
            "duration" : int(symmetriccrypt.decrypt(secret_key, media_list_enc[id]["duration"], cipher_list[0], cipher_list[1]).decode())
        })
        id += 1

    # Present a simple selection menu    
    idx = 0
    print("MEDIA CATALOG\n")
    for item in media_list:
        print(f'{idx} - {media_list[idx]["name"]}')
        idx+=1
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
    print(media_item['chunks'])
    # Detect if we are running on Windows or Linux
    # You need to have ffplay or ffplay.exe in the current folder
    # In alternative, provide the full path to the executable
    if os.name == 'nt':
        proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
    else:
        proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

    # Get data from server and send it to the ffplay stdin through a pipe
    for chunk in range(media_item['chunks'] + 1):
        req = request.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        if not req.status_code == 200:
            print(symmetriccrypt.decrypt(secret_key, req.json()['error'], cipher_list[0], cipher_list[1]).decode())
            sys.exit(0)
        
        chunk = req.json()
       
        # TODO: Process chunk
        data = binascii.a2b_base64(symmetriccrypt.decrypt(secret_key, chunk['data'].encode('latin'), cipher_list[0], cipher_list[1]))
        data_signature = symmetriccrypt.decrypt(secret_key, chunk['data_signature'], cipher_list[0], cipher_list[1])

        if not rsa_utils.rsa_verify(rsa_utils.load_rsa_public_key("../client_rsa_keys/server_rsa_pub_key.pub"), data, data_signature):
            print("The file sent from the server is not of trust")
            sys.exit(0)
        print("Chunk has a valid signature")
        try:
            proc.stdin.write(data)
        except:
            req = request.get(f'{SERVER_URL}/api/finished?id={media_item["id"]}')
            if req.status_code == 200:
                print(symmetriccrypt.decrypt(secret_key, req.json(), cipher_list[0], cipher_list[1]).decode())
                
            break

if __name__ == '__main__':
    
    #stablish cryptography with server 
    dh_parameters, dh_private_key, secret_key, cipher_list = cryptography()
    #auth
    auth_result = auth()
    if auth_result:
        while True:
            rsa_exchange()
            main()
            time.sleep(1)
        # try:
        #     auth()
        #     main()
        #     time.sleep(1)
        # except Exception as e :
        #     print(e)
        #     sys.exit(0)

        
        