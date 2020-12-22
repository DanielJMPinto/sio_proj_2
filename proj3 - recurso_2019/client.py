import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from utils import Crypto

logger = logging.getLogger('root')

STATE_NEGOTIATION = -3
STATE_DH = -2
STATE_ROTATION = -1
STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE = 3

STATE_VALIDATE_SERVER = 4
STATE_CLIENT_AUTH = 5
STATE_SERVER_AUTH = 6


class ClientProtocol(asyncio.Protocol):
    """
    Client that handles a single client
    """

    def __init__(self, file_name, loop):
        """
        Default constructor
        :param file_name: Name of the file to send
        :param loop: Asyncio Loop to use
        """

        self.file_name = file_name
        self.loop = loop
        self.state = 0    # Initial State
        self.buffer = ''  # Buffer to receive data chunks
        self.ppos = 0
        self.count = 0
        self.host_name="127.0.0.1"

        self.ciphers = ['AES','3DES','CHACHA20']
        self.modes = ['CBC','GCM']
        self.digest = ['SHA256','SHA384','SHA512','MD5','BLAKE2']
        self.ch_cipher = None
        self.ch_mode = None
        self.ch_digest = None
        self.crypto = Crypto(self.ch_cipher, self.ch_mode, self.ch_digest)

        self.encrypted_data = ''
        self.end = False            # Checks if transfer ended

        self.credentials = {}
        self.server_public_key = None
        self.nonce = os.urandom(16)
        self.server_nonce = None

        self.validation_type = "CHALLENGE" # CHALLENGE or CITIZEN_CARD
        self.rsa_public_key, self.rsa_private_key = self.crypto.key_pair_gen(4096)

        self.recv_encrypted_data = ''
        self.recv_decrypted_data = []

    def log_state(self, received):
        #states = ['NEGOTIATION', 'DH', 'ROTATION','CONNECT', 'OPEN', 'DATA', 'CLOSE']
        #logger.info("State: {}".format(states[self.state]))
        logger.info("Received: {}".format(received))

    def encrypt_message(self, message: dict) -> None:
        """
        Called when a secure message will be sent, in order to encrypt its content.

        :param message: JSON message of type OPEN, DATA or CLOSE
        """
        secure_message = {'type': 'SECURE_MESSAGE', 'content': None}
        content = json.dumps(message).encode()
        
        ct = self.crypto.encrypt(content)
        secure_message['content'] = base64.b64encode(ct).decode()
        self.encrypted_data += secure_message['content']

        return secure_message

    def send_mac(self) -> None:
        """
        Called when a secure message is sent and a MAC is necessary to check message authenticity.
        """
        self.crypto.mac_gen(base64.b64decode(self.encrypted_data))

        iv = '' if self.crypto.iv is None else base64.b64encode(self.crypto.iv).decode()
        tag = '' if self.crypto.tag is None else base64.b64encode(self.crypto.tag).decode()
        nonce = '' if self.crypto.nonce is None else base64.b64encode(self.crypto.nonce).decode()

        message = {'type': 'MAC', 'data': base64.b64encode(self.crypto.mac).decode(), 'iv': iv, 'tag': tag, 'nonce': nonce}
        self._send(message)
        self.encrypted_data = ''

    def process_mac(self,message: str) -> bool:
        """
        Processes a MAC message from the server.
        Checks the authenticity/integrity of a previous received message.

        :param message: The message to process.
        """
        logger.debug("Process MAC: {}".format(message))
        server_mac = base64.b64decode(message['data'])
        
        # Generate server MAC        
        self.crypto.mac_gen(base64.b64decode(self.recv_encrypted_data))
        logger.debug("Server mac: {}".format(server_mac))
        logger.debug("Client mac: {}".format(self.crypto.mac))
        
        if server_mac == self.crypto.mac:
            logger.info("Integrity control succeeded")
            return (True, None)
        else:
            return (False, 'Integrity control failed.')

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        logger.debug('Sending algorithms')

        logger.info('Connection to Server')
        logger.info('LOGIN_REQUEST')
        
        message = {'type':'NEGOTIATION','algorithms':{'symmetric_ciphers':self.ciphers,'cipher_modes':self.modes,'digest':self.digest}}

        # Generate a new NONCE
        self.crypto.auth_nonce = os.urandom(16)
        logger.debug(f"Nonce: {self.crypto.auth_nonce}")

        self._send(message)
        self.state = STATE_DH


    def data_received(self, data: str) -> None:
        """
        Called when data is received from the server.
        Stores the data in the buffer

        :param data: The data that was received. This may not be a complete JSON message
        :return:
        """
        logger.debug('Received: {}'.format(data))
        try:
            self.buffer += data.decode()
        except:
            logger.exception('Could not decode data from client')

        idx = self.buffer.find('\r\n')

        while idx >= 0:  # While there are separators
            frame = self.buffer[:idx + 2].strip()  # Extract the JSON object
            self.buffer = self.buffer[idx + 2:]  # Removes the JSON object from the buffer

            self.on_frame(frame)  # Process the frame
            idx = self.buffer.find('\r\n')

        if len(self.buffer) > 4096 * 1024 * 1024:  # If buffer is larger than 4M
            logger.warning('Buffer to large')
            self.buffer = ''
            self.transport.close()

    def on_frame(self, frame: str) -> None:
        """
        Processes a frame (JSON Object)

        :param frame: The JSON Object to process
        :return:
        """

        #logger.debug("Frame: {}".format(frame))

        try:
            message = json.loads(frame)
        except:
            logger.exception("Could not decode the JSON message")
            self.transport.close()
            return

        mtype = message.get('type', None)
        self.log_state(mtype)

        if mtype == 'NEGOTIATION_RESPONSE':
            logger.debug("NEGOTIATION RESPONSE")

            # Receive the chosen algorithms by the server 
            self.process_negotiation_response(message)

            # Generate DH client private and public keys
            bytes_public_key,p,g,y=self.crypto.dh_client()
            
            message = {'type':'DH_PARAMETERS','parameters':{'p':p,'g':g,'public_key':str(bytes_public_key,'ISO-8859-1')}}
            self._send(message)
            self.state = STATE_DH
            
            return

        elif mtype == 'DH_PARAMETERS_RESPONSE':
            logger.debug('DH_PARAMETERS_RESPONSE')
            public_key=bytes(message['parameters']['public_key'],'ISO-8859-1')
            
            #Create shared key with the server public key
            self.crypto.create_shared_key(public_key)
            
            # Generate a symmetric key
            self.crypto.symmetric_key_gen()
            logger.debug("Key: {}".format(self.crypto.symmetric_key))

            if self.state == STATE_ROTATION:
                self.state = STATE_OPEN
                self.send_file(self.file_name)
                
            elif self.state == STATE_DH:
                self.crypto.auth_nonce=os.urandom(16)
                message = {'type': 'SERVER_AUTH_REQUEST', 'nonce': base64.b64encode(self.crypto.auth_nonce).decode()}
                secure_message = self.encrypt_message(message)
                self.state = STATE_SERVER_AUTH
                self._send(secure_message)
                self.send_mac()

            return

        elif mtype == 'MAC':
            (ret,error)= self.process_mac(message)
            
            if ret:
                iv=base64.b64decode(message['iv'])
                tag=base64.b64decode(message['tag'])
                nonce=base64.b64decode(message['nonce'])
                
                if iv=='': iv=None
                if tag=='': tag=None
                if nonce=='': nonce=None
                
                self.recv_decrypted_data.append(self.crypto.decrypt(base64.b64decode(self.recv_encrypted_data.encode()),iv,tag,nonce))
                
                # process secure message
                self.process_secure()
            return

        elif mtype == 'INTEGRITY_CONTROL':
            flag = message['data']
            if flag == 'True':
                self._send(self.encrypt_message({'type': 'CLOSE'}))
                self.send_mac()
                logger.info("File transfer complete. Closing transport")
                self.transport.close()

        elif mtype == 'OK':  # Server replied OK. We can advance the state
            if self.state == STATE_OPEN:
                logger.info("Channel open")
                self.send_file(self.file_name)
            elif self.state == STATE_DATA:  # Got an OK during a message transfer.
                # Reserved for future use
                pass
            else:
                logger.warning("Ignoring message from server")
            return

        elif mtype == 'SECURE_MESSAGE':
            self.recv_encrypted_data += message['content']
            return

        elif mtype == 'CHALLENGE_REQUEST':
            self.process_challenge(message)
            return 

        elif mtype == 'CARD_LOGIN_RESPONSE':
            self.process_login_response(message)
            return

        elif mtype == 'SERVER_AUTH_RESPONSE':
            flag=self.process_server_auth(message)
            if not flag:
                message = {'type': 'SERVER_AUTH_FAILED'}
                secure_message = self.encrypt_message(message)
                self._send(secure_message)
                self.send_mac()
            if flag:

                #Generate a new NONCE
                self.crypto.auth_nonce=os.urandom(16)

                self.state=STATE_CLIENT_AUTH

                if self.validation_type == "CHALLENGE":
                    message = {'type': 'LOGIN_REQUEST', 
                    		   'nonce':  base64.b64encode(self.crypto.auth_nonce).decode(), 
                    		   'public_key': self.rsa_public_key}

                    secure_message = self.encrypt_message(message)
                    self._send(secure_message)
                    self.send_mac()
                elif self.validation_type == "CITIZEN_CARD":
                    message = {'type': 'CARD_LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode()}
                    secure_message = self.encrypt_message(message)
                    self._send(secure_message)
                    self.send_mac()
            
                return 
        
        elif mtype == 'AUTH_RESPONSE':
            if message['status'] == 'SUCCESS':
                logger.info('User authentication with success.')
                self.process_authentication(message)
            elif message['status'] == 'DENIED':
                logger.info('User authentication denied.')
            else:
                logger.info('User authentication failed.')
                self.nonce = os.urandom(16)
                message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode(), 'public_key': self.rsa_public_key}
                secure_message = self.encrypt_message(message)
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_CLIENT_AUTH 
            return
        
        elif mtype == 'FILE_REQUEST_RESPONSE':
            if message['status'] == 'PERMISSION_GRANTED':
                logger.info('Permission granted to transfer the file.')
                secure_message = self.encrypt_message({'type': 'OPEN', 'file_name': self.file_name})
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_OPEN
            else:
                logger.error('Permission denied to transfer the file.')
            return

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        
        else:
            logger.warning("Invalid message type")

        logger.debug('Closing')
        self.transport.close()
        self.loop.stop()

    def process_negotiation_response(self, message: str) -> bool:
        """
        Called when a response of type NEGOTIATION is received

        :param message: Received message
        """
        logger.debug("Process Negotiation: {}".format(message))

        self.crypto.cipher = message['chosen_algorithms']['symmetric_cipher']
        self.crypto.mode = message['chosen_algorithms']['cipher_mode']
        self.crypto.digest = message['chosen_algorithms']['digest']

        logger.info("Chosen algorithms: {} {} {}".format(self.crypto.cipher,self.crypto.mode,self.crypto.digest))
      
    def process_secure(self):
        """
        Handles a SECURE_MESSAGE message from the server, decrypting it

        The content is a JSON message that could be of type 
        CHALLENGE_REQUEST, 
        CARD_LOGIN_RESPONSE,
        SERVER_AUTH_RESPONDE,
        AUTH_RESPONSE,
        FILE_REQUEST_RESPONSE,
        """
        message = json.loads(self.recv_decrypted_data[0])
        mtype = message['type']
        logger.info("Process SECURE_MESSAGE: {}".format(mtype))

        if mtype == 'CHALLENGE_REQUEST':
            self.process_challenge(message)

        elif mtype == 'CARD_LOGIN_RESPONSE':
            self.process_login_response(message)
        
        elif mtype == 'SERVER_AUTH_RESPONSE':
            flag=self.process_server_auth(message)
            if not flag:
                message = {'type': 'SERVER_AUTH_FAILED'}
                secure_message = self.encrypt_message(message)
                self._send(secure_message)
                self.send_mac()
            if flag:

                #Generate a new NONCE
                self.crypto.auth_nonce=os.urandom(16)

                self.state=STATE_CLIENT_AUTH

                if self.validation_type == "CHALLENGE":
                    message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode(), 'public_key': self.rsa_public_key}

                    secure_message = self.encrypt_message(message)
                    self._send(secure_message)
                    self.send_mac()
                elif self.validation_type == "CITIZEN_CARD":
                    message = {'type': 'CARD_LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode()}
                    secure_message = self.encrypt_message(message)
                    self._send(secure_message)
                    self.send_mac()
        
        elif mtype == 'AUTH_RESPONSE':
            if message['status'] == 'SUCCESS':
                logger.info('User authentication with success.')
                self.process_authentication(message)
            elif message['status'] == 'DENIED':
                logger.info('User authentication denied.')
            else:
                logger.info('User authentication failed.')
                self.nonce = os.urandom(16)
                message = {'type': 'LOGIN_REQUEST', 'nonce':  base64.b64encode(self.crypto.auth_nonce).decode(), 'public_key': self.rsa_public_key}
                secure_message = self.encrypt_message(message)
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_CLIENT_AUTH 
        
        elif mtype == 'FILE_REQUEST_RESPONSE':
            if message['status'] == 'PERMISSION_GRANTED':
                logger.info('Permission granted to transfer the file.')
                secure_message = self.encrypt_message({'type': 'OPEN', 'file_name': self.file_name})
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_OPEN
            else:
                logger.error('Permission denied to transfer the file.')
        
        self.recv_encrypted_data = ''
        self.recv_decrypted_data = []
        return 


    def process_server_auth(self, message):
        """
        Called in order to a client authenticate the server
        Makes the validation of the server's signature, common name and chain
        """
        self.crypto.signature = base64.b64decode(message['signature'].encode())
        server_cert_bytes=base64.b64decode(message['server_cert'].encode())
        server_ca_cert_bytes=base64.b64decode(message['server_roots'].encode())

        self.crypto.server_cert=self.crypto.load_cert_bytes(server_cert_bytes)
        self.crypto.server_public_key=self.crypto.server_cert.public_key()
        self.crypto.server_ca_cert=self.crypto.load_cert_bytes(server_ca_cert_bytes)

        # Validate server signature
        flag1=self.crypto.rsa_signature_verification(self.crypto.signature,self.crypto.auth_nonce,self.crypto.server_public_key)
        logger.info(f'Server signature validation: {flag1}')

        #Validate common name
        flag2=self.host_name==self.crypto.get_common_name(self.crypto.server_cert)
        logger.info(f'Server common_name validation: {flag2}')

        #Validate chain
        flag3=self.crypto.validate_server_chain(self.crypto.server_cert,self.crypto.server_ca_cert)
        logger.info(f'Server chain validation: {flag3}')

        if flag1 and flag2 and flag3:
            logger.info("Server validated")
            return True
        else:
            return False

    def process_authentication(self, message):
        """
        Called when a client is authenticated to perform access control
        """
        secure_message = self.encrypt_message({'type': 'FILE_REQUEST'})
        self._send(secure_message)
        self.send_mac()
        self.state = STATE_OPEN
    
    def process_login_response(self, message):
        """
        Called when a client is authenticating with citzent card
        The client inserts it's username and creates a signature with it's card
        """
        self.credentials['username'] = input("Username: ")

        self.server_nonce = base64.b64decode(message['nonce'].encode())
        cert, signature = self.crypto.card_signing(self.crypto.auth_nonce+self.server_nonce)
   
        secure_message = self.encrypt_message({'type': 'AUTH_CERTIFICATE','cert':base64.b64encode(cert).decode(), 'signature': base64.b64encode(signature).decode(),'credentials':{'username':self.credentials['username']}})
        self._send(secure_message)
        self.send_mac()
    
    def process_challenge(self, message):
        """
        Called when a client is authenticating with challenge
        The client inserts it's username and password and creates a signature with it's private key 
        """
        self.credentials['username'] = input("Username: ")
        self.credentials['password'] = getpass.getpass("Password: ")

        self.server_nonce = str(base64.b64decode(message['nonce'].encode()))
        message = str(self.crypto.auth_nonce) + self.credentials['password'] + self.server_nonce
        private_key = self.crypto.load_private_key(base64.b64decode(self.rsa_private_key.encode()))
        self.signed_challenge = self.crypto.rsa_signing(message.encode(), private_key)

        message = {}
        message['type'] = 'CHALLENGE_RESPONSE'
        message['credentials'] = {}
        message['credentials']['username'] = self.credentials['username']
        message['credentials']['signed_challenge'] = base64.b64encode(self.signed_challenge).decode()
        self._send(message)

        return   

    def connection_lost(self, exc):
        """
        Connection was lost for some reason.
        :param exc:
        :return:
        """
        logger.info('The server closed the connection')
        self.loop.stop()

    def send_file(self, file_name: str) -> None:
        """
        Sends a file to the server.
        The file is read in chunks, encoded to Base64 and sent as part of a DATA JSON message
        :param file_name: File to send
        :return:  None
        """

        with open(file_name, 'rb') as f:
            message = {'type': 'DATA', 'data': None}
            read_size = 16 * 60
            #f.read(read_size * self.count)
            while True:
                if self.ppos != 0:
                    f.seek(self.ppos)
                    self.ppos = 0

                if self.count == 1000:
                    self.state = STATE_ROTATION

                    #Generate DH client private and public keys
                    bytes_public_key,p,g,y = self.crypto.dh_client()
                    message = {'type':'DH_PARAMETERS','parameters':{'p':p,'g':g,'public_key':str(bytes_public_key,'ISO-8859-1')}}
                    self.count=0
                    self.ppos=f.tell()
                    self._send(message)
                    break

                self.count += 1
                
                data = f.read(16 * 60)
                message['data'] = base64.b64encode(data).decode()
                #logger.debug("Data: {} read size {}".format(data,f.tell()))
                secure_message = self.encrypt_message(message)
                
                self._send(secure_message)
                self.send_mac()
                
                if len(data) != read_size:
                    self.end = True
                    break
            
            # When it ends create MAC
            if self.end:
                self._send(self.encrypt_message({'type': 'CLOSE'}))
                self.send_mac()
                logger.info("File transfer complete. Closing transport")
                self.transport.close()

    def _send(self, message: str) -> None:
        """
        Effectively encodes and sends a message
        :param message:
        :return:
        """
        logger.info("Send: {}".format(message['type']))
        logger.debug("Send: {}".format(message))

        message_b = (json.dumps(message) + '\r\n').encode()
        self.transport.write(message_b)


def main():
    parser = argparse.ArgumentParser(description='Sends files to servers.')
    parser.add_argument('-v', action='count', dest='verbose',
                        help='Shows debug messages',
                        default=0)
    parser.add_argument('-s', type=str, nargs=1, dest='server', default='127.0.0.1',
                        help='Server address (default=127.0.0.1)')
    parser.add_argument('-p', type=int, nargs=1,
                        dest='port', default=5000,
                        help='Server port (default=5000)')

    parser.add_argument(type=str, dest='file_name', help='File to send')

    args = parser.parse_args()
    file_name = os.path.abspath(args.file_name)
    level = logging.DEBUG if args.verbose > 0 else logging.INFO
    port = args.port
    server = args.server

    coloredlogs.install(level)
    logger.setLevel(level)

    logger.info("Sending file: {} to {}:{} LogLevel: {}".format(file_name, server, port, level))

    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: ClientProtocol(file_name, loop),
                                  server, port)
    loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()

if __name__ == '__main__':
    main()