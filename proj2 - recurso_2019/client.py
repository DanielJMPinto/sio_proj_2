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

        self.ciphers = ['AES','3DES','CHACHA20']
        self.modes = ['CBC','GCM']
        self.digest = ['SHA256','SHA384','SHA512']
        self.ch_cipher = None
        self.ch_mode = None
        self.ch_digest = None
        self.crypto = Crypto(self.ch_cipher, self.ch_mode, self.ch_digest)

        self.encrypted_data = ''
        self.end = False            # Checks if transfer ended

    def log_state(self, received):
        states = ['CONNECT', 'OPEN', 'DATA', 'CLOSE', 'NEGOTIATION', 'DH', 'ROTATION']
        logger.info("State: {}".format(states[self.state]))
        logger.info("Received: {}".format(received))

    def encrypt_message(self, message: dict) -> None:
        """
        Called when a secure message will be sent, in order to encrypt its payload.

        @param message: JSON message of type OPEN, DATA or CLOSE
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

    def connection_made(self, transport) -> None:
        """
        Called when the client connects.

        :param transport: The transport stream to use for this client
        :return: No return
        """
        self.transport = transport

        logger.debug('Connected to Server')
        logger.debug('Sending algorithms')
        
        message = {'type':'NEGOTIATION','algorithms':{'symmetric_ciphers':self.ciphers,'cipher_modes':self.modes,'digest':self.digest}}

        self._send(message)
        self.state = STATE_NEGOTIATION


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

        logger.debug("Frame: {}".format(frame))
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
                secure_message = self.encrypt_message({'type': 'OPEN', 'file_name': self.file_name})
                self._send(secure_message)
                self.send_mac()
                self.state = STATE_OPEN

            return

        elif mtype == 'INTEGRITY_CONTROL':
            flag = message['data']
            if flag == 'True':
                self._send(self.encrypt_message({'type': 'CLOSE'}))
                self.send_mac()
                logger.info("File transfer finished. Closing transport")
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

        elif mtype == 'ERROR':
            logger.warning("Got error from server: {}".format(message.get('data', None)))
        
        else:
            logger.warning("Invalid message type")

        logger.debug('Closing')
        self.transport.close()
        self.loop.stop()

    def process_negotiation_response(self, message: str) -> bool:
        """
        Called when a response of type NEGOTIATION is received.

        @param message: Received message
        """
        logger.debug("Process Negotiation: {}".format(message))

        self.crypto.cipher = message['chosen_algorithms']['symmetric_cipher']
        self.crypto.mode = message['chosen_algorithms']['cipher_mode']
        self.crypto.digest = message['chosen_algorithms']['digest']

        logger.info("Chosen algorithms: {} {} {}".format(self.crypto.cipher,self.crypto.mode,self.crypto.digest))
        

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
            while True:
                if self.ppos != 0:
                    f.seek(self.ppos)
                    self.ppos = 0

                if self.count == 20:
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
                logger.info("File transfer finished. Closing transport")
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