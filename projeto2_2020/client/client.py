import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys
sys.path.append(os.path.abspath('../utils'))
import utils
import rsa_utils
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

def auth():
    global CLIENT_OID
    client_nonce = os.urandom(64)
    
    req = requests.post(f'{SERVER_URL}/api/server_auth', data=json.dumps({"nonce":base64.b64encode(client_nonce).decode()}).encode())
    if req.status_code == 200:
       logger.debug(f"Got Server Certs and Signed Nonce")
    
    
    #validate server certs
    data = req.json()

    server_nonce = base64.b64decode(data["server_nonce"].encode())

    server_certificate = utils.certificate_object_from_pem(base64.b64decode(data["server_certificate"].encode()))
    signed_client_nonce = base64.b64decode(data["signed_client_nonce"].encode())

    cert_data = utils.load_cert_from_disk("../server_ca/SIOServerCA.pem")
    cert = utils.certificate_object_from_pem(cert_data)

    certificates={}
    certificates[cert.subject.rfc4514_string()] = cert

    chain=[]
    chain_completed = utils.construct_certificate_chain(chain, server_certificate, certificates)
    
    if not chain_completed:
        logger.debug(f"Couldn't complete the certificate chain")
        return False
        
    else:
        valid_chain, error_messages = utils.validate_certificate_chain(chain)

        if not valid_chain:
            logger.debug(error_messages)
            return False  
        else:
            if not utils.verify_signature(server_certificate, signed_client_nonce, client_nonce):
                return False
    
    #send cc info
    session_success, session_data = utils.cc_session()

    if not session_success:
        logger.debug(f"Error establishing a new citizen card session: {session_data}")
        return False

    client_cert = utils.certificate_cc(session_data)
    
    client_certs = {}
    client_certs["client_cc_certificate"] = base64.b64encode(client_cert).decode()
    client_certs["signed_server_nonce"] = base64.b64encode(utils.sign_nonce_cc(session_data, server_nonce)).decode()
    

    #finalize auth
    req = requests.post(f'{SERVER_URL}/api/client_auth', data=json.dumps(client_certs).encode())
    if req.status_code == 200:
       logger.debug(f"Server finished cc certificatcion chain")
    
    data = req.json()
    if data["status"]:
        logger.debug(f"Sucessfully authenticated CC")
        oid = ObjectIdentifier("2.5.4.5")
        CLIENT_OID = utils.certificate_object(client_cert).subject.get_attributes_for_oid(oid)[0].value
        return True
    else:
        logger.debug(f"Could not authenticated CC")
        return False

    
def rsa_exchange():
    private_key, public_key = rsa_utils.generate_rsa_key_pair(2048, "../client_rsa_keys/client_rsa_key")

    req = requests.post(f'{SERVER_URL}/api/rsa_exchange', 
            data=json.dumps({
                "client_rsa_pub_key":public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            }).encode()
        )

    if req.status_code == 200:
       logger.debug(f"Received Server public rsa Key ")

    data = req.json()

    server_rsa_pub_key = data["server_rsa_pub_key"].encode()

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
        print(req.json())
        sys.exit(0)

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
        req = request.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
        chunk = req.json()
       
        # TODO: Process chunk
        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        data_signature = chunk['data_signature'].encode('latin')

        if not rsa_utils.rsa_verify(rsa_utils.load_rsa_public_key("../client_rsa_keys/server_rsa_pub_key.pub"), data, data_signature):
            print("The file sent from the server is not of trust")
            sys.exit(0)
        
        try:
            proc.stdin.write(data)
        except:
            break

if __name__ == '__main__':
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

        
        