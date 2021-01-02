#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import sys


sys.path.append(os.path.abspath('../cryptography'))
import symmetriccrypt
import diffiehellman



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
    
    #cryptography informations
    client_chosen_ciphers = None
    dh_parameters = None
    dh_private_key = None
    secret_key = None
    
    
    
    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'


        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
                })

        # Return list to client
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(media_list, indent=4).encode('latin')

    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'invalid media id'}).encode('latin')
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps({'error': 'media file not found'}).encode('latin')
        
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
            return json.dumps({'error': 'invalid chunk id'}).encode('latin')
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            return json.dumps(
                    {
                        'media_id': media_id, 
                        'chunk': chunk_id, 
                        'data': binascii.b2a_base64(data).decode('latin').strip()
                    },indent=4
                ).encode('latin')

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps({'error': 'unknown'}, indent=4).encode('latin')



    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'Received request for {request.uri}')

        try:
            if request.path == b'/api/protocols':
                return self.do_get_protocols(request)
            elif request.path == b'/api/cipher-suite':
                # Return list to client
                # suported algorithms, cipher modes and hash functions
                cipherModes = ["ECB", "CBF","CBC", "OFB"]
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

            #elif request.uri == 'api/key':
            #...
            #elif request.uri == 'api/auth':

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
                print(message)
                message = message.decode('latin')
                print(message)
                print(type(message))
                request.responseHeaders.addRawHeader(b"content-type", b"application/json")
                return json.dumps({"data":message}, indent=4).encode('latin')

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            print("c")
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()