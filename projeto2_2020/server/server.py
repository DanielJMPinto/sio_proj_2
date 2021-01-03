#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import sys

sys.path.append(os.path.abspath('../utils'))
import utils
import rsa_utils
import symmetriccrypt
import diffiehellman
import base64
from cryptography.x509 import ObjectIdentifier
from cryptography.hazmat.primitives import serialization



logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4

class MediaServer(resource.Resource):
    isLeaf = True

    def __init__(self):
        self.server_nonce = None
        self.authorized_users = []
        #cryptography informations
        self.client_chosen_ciphers = None
        self.dh_parameters = None
        self.dh_private_key = None
        self.secret_key = None
        #catalog pass
        self.catalog_password = "Music"

    # Send the list of media files to clients
    def do_list(self, request):

        oid = request.getHeader('oid')
        if oid not in self.authorized_users:
           request.setResponseCode(401)
           return json.dumps(symmetriccrypt.encrypt(self.secret_key, 'Not Authorized', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')).encode()


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': symmetriccrypt.encrypt(self.secret_key, media_id, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'),
                'name': symmetriccrypt.encrypt(self.secret_key, media['name'], self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'),
                'description': symmetriccrypt.encrypt(self.secret_key, media['description'], self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'),
                'chunks': symmetriccrypt.encrypt(self.secret_key, str(math.ceil(media['file_size'] / CHUNK_SIZE)), self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'),
                'duration': symmetriccrypt.encrypt(self.secret_key, str(media['duration']), self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')


    # Send a media chunk to the client
    def do_download(self, request):

        oid = request.getHeader('oid')
        if oid not in self.authorized_users:
           request.setResponseCode(401)
           return json.dumps(symmetriccrypt.encrypt(self.secret_key, 'Not Authorized', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')).encode()

        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': symmetriccrypt.encrypt(self.secret_key, 'invalid media id', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': symmetriccrypt.encrypt(self.secret_key, 'media file not found', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')}).encode('latin')
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': symmetriccrypt.encrypt(self.secret_key, 'invalid chunk id', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        
        #minha ideia
        f = open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb')
        music = f.read()
        music = symmetriccrypt.decrypt(self.catalog_password, music, "AES-128", "CBC")
        pointer = offset
        data = music[pointer:pointer+CHUNK_SIZE]
        

        '''
        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)
        '''
        data_signature = rsa_utils.rsa_sign(rsa_utils.load_rsa_private_key("../server_rsa_keys/server_rsa_key"), data)

        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(
                {
                    'media_id': symmetriccrypt.encrypt(self.secret_key, media_id, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'), 
                    'chunk': symmetriccrypt.encrypt(self.secret_key, str(chunk_id), self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'), 
                    'data': symmetriccrypt.encrypt(self.secret_key, binascii.b2a_base64(data).decode('latin').strip(), self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin'),
                    'data_signature': symmetriccrypt.encrypt(self.secret_key, data_signature, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
                },indent=4
            ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': symmetriccrypt.encrypt(self.secret_key, 'unknown', self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')}, indent=4).encode('latin')

    def server_authenticate(self, request):
        #client only can call this method if cryptography already is stablished
        if self.secret_key == None:
            # o que devo retornar para o cliente nesse caso ?
            pass
        dict = request.content.read()
        data = json.loads(dict)
        logger.debug(f"Received Nonce from Client")

        #decrypt nonce
        client_nonce = data["nonce"].encode('latin')
        client_nonce = symmetriccrypt.decrypt(self.secret_key, client_nonce, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1])

        private_key = utils.load_private_key_file("../server_pk/SIOServerCertKey.pem")
        signed_client_nonce = utils.sign_with_pk(private_key, client_nonce)
        certificate = utils.load_cert_from_disk("../server_cert/SIOServerCert.pem")

        self.server_nonce = os.urandom(64)

        #encrypt
        certificate = symmetriccrypt.encrypt(self.secret_key, certificate, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
        signed_client_nonce = symmetriccrypt.encrypt(self.secret_key, signed_client_nonce, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
        server_nonce = symmetriccrypt.encrypt(self.secret_key, self.server_nonce, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')

        return json.dumps({
                "server_certificate": certificate,
                "signed_client_nonce": signed_client_nonce,
                "server_nonce": server_nonce
            }).encode('latin')

    def client_authenticate(self, request):
        dict = request.content.read()
        data = json.loads(dict)

        #decrypt nonce
        signed_server_nonce = data["signed_server_nonce"].encode('latin')
        signed_server_nonce = symmetriccrypt.decrypt(self.secret_key, signed_server_nonce, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1])
        client_cc_certificate = data["client_cc_certificate"].encode('latin')
        client_cc_certificate = symmetriccrypt.decrypt(self.secret_key, client_cc_certificate, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1])

        client_cc_certificate = utils.certificate_object(client_cc_certificate)
        logger.debug(f"Recived Client Certificate and signed Nonce")

        path = "../cc_certificates"
        certificates={}
        
        for filename in os.listdir(path):
            if filename.endswith(".pem"): 
                cert_data = utils.load_cert_from_disk(os.path.join(path, filename))
                cert = utils.certificate_object_from_pem(cert_data)
                certificates[cert.subject.rfc4514_string()] = cert
        
        chain = []
        chain_completed = utils.build_certificate_chain(chain, client_cc_certificate, certificates)

        if not chain_completed:
            logger.debug(f"Couldn't complete the certificate chain")
            status = False

        else:
            valid_chain, error_messages = utils.validate_certificate_chain(chain)

            if not valid_chain:
                logger.debug(error_messages)
                status = False
            else:
                status = utils.verify_signature(client_cc_certificate, signed_server_nonce, self.server_nonce)

        if status:
            logger.debug(f"Sucsessfuly validated the client certicate chain and nonce signed by the client")
            oid = ObjectIdentifier("2.5.4.5")
            self.authorized_users.append(client_cc_certificate.subject.get_attributes_for_oid(oid)[0].value)

            logger.debug(f"User logged in with success")

        status_enc = symmetriccrypt.encrypt(self.secret_key, str(status), self.client_chosen_ciphers[0], self.client_chosen_ciphers[1]).decode('latin')
            
        return json.dumps({
                "status":status_enc
            }).encode('latin')

    def rsa_exchange(self, request):
        private_key, public_key = rsa_utils.generate_rsa_key_pair(2048, "../server_rsa_keys/server_rsa_key")

        dict = request.content.read()
        data = json.loads(dict)

        client_rsa_pub_key = data["client_rsa_pub_key"].encode()
        client_rsa_pub_key = symmetriccrypt.decrypt(self.secret_key, client_rsa_pub_key, self.client_chosen_ciphers[0], self.client_chosen_ciphers[1])

        fileToSave_public_key = open("../server_rsa_keys/client_rsa_pub_key.pub", 'wb')
        fileToSave_public_key.write(client_rsa_pub_key)
        fileToSave_public_key.close()
        logger.debug(f"Received Client Public RSA Key")

        pubk_enc = symmetriccrypt.encrypt(
            self.secret_key, 
            public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), 
            self.client_chosen_ciphers[0], 
            self.client_chosen_ciphers[1]
        ).decode('latin')

        return json.dumps({
                "server_rsa_pub_key":pubk_enc
            }).encode('latin')
            

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            #elif request.uri == 'api/key':
            #...
            
            #cryptography methods
            elif request.path == b'/api/cipher-suite':
                # Return list to client
                # suported algorithms, cipher modes and hash functions
                cipherModes = ["ECB", "CFB","CBC", "OFB"]
                cipherAlgorithms = ['3DES','AES-128','ChaCha20']
                hashFunctions = ["SHA-256", "SHA-384", "SHA-512", "MD5", "BLAKE-2"]
                #ciphers
                ciphers_list = [cipherAlgorithms, cipherModes, hashFunctions]
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(ciphers_list, indent=4).encode('latin')
            elif request.path == b'/api/dh-parameters':
                dh_parameters = diffiehellman.dh_generate_parameters()
                self.dh_parameters = dh_parameters
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps(dh_parameters, indent=4).encode('latin')


            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
    
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'Received POST for {request.uri}')
        try:
            if request.uri == b'/api/server_auth':
                return self.server_authenticate(request)
            elif request.uri == b'/api/client_auth':
                return self.client_authenticate(request)
            elif request.uri == b'/api/rsa_exchange':
                return self.rsa_exchange(request)
            
            #cryptography methods
            if request.path == b'/api/dh-handshake':
                #client public key (public number y)
                client_public_number_y = json.loads(request.content.read())[0]
                #generate my private key
                self.dh_private_key = diffiehellman.dh_generate_private_key(self.dh_parameters)
                #my public key (public number y)
                dh_public_number_y = diffiehellman.dh_generate_public_key(self.dh_private_key)
                #calculete secret key to be used to encrypt comunication
                self.secret_key = diffiehellman.dh_calculete_common_secret(self.dh_private_key, client_public_number_y)
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps([dh_public_number_y], indent=4).encode('latin')
            elif request.path == b'/api/chosen-ciphers':
                #client public key (public number y)
                self.client_chosen_ciphers = json.loads(request.content.read())
                print(self.client_chosen_ciphers)

                message = "cryptography pattern established"
                message = symmetriccrypt.encrypt(self.secret_key,message,self.client_chosen_ciphers[0],self.client_chosen_ciphers[1])
                message = message.decode('latin')
                
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({"data":message}, indent=4).encode('latin')

            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()