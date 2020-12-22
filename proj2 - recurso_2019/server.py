import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import re
import os
from aio_tcpserver import tcp_server
from utils import Crypto

logger = logging.getLogger('root')

STATE_NEGOTIATION = -3
STATE_DH = -2
STATE_ROTATION = -1
STATE_CONNECT = 0
STATE_OPEN = 1
STATE_DATA = 2
STATE_CLOSE= 3

#GLOBAL
storage_dir = 'files'

class ClientHandler(asyncio.Protocol):
	def __init__(self, signal):
		"""
		Default constructor
		"""
		self.signal = signal
		self.state = 0
		self.file = None
		self.file_name = None
		self.file_path = None
		self.storage_dir = storage_dir
		self.buffer = ''
		self.peername = ''
		self.ppos = 0
		self.change_key = False

		self.ciphers = ['AES','3DES','CHACHA20']
		self.modes = ['CBC','GCM']
		self.digest = ['SHA256','SHA384','SHA512']
		self.ch_cipher = None
		self.ch_mode = None
		self.ch_digest = None
		self.crypto = Crypto(self.ch_cipher, self.ch_mode, self.ch_digest)

		self.encrypted_data = ''
		self.decrypted_data = []

	def log_state(self, received):
		states = ['CONNECT', 'OPEN', 'DATA', 'CLOSE', 'NEGOTIATION', 'DH', 'ROTATION']
		logger.info("State: {}".format(states[self.state]))
		logger.info("Received: {}".format(received))

	def connection_made(self, transport) -> None:
		"""
		Called when a client connects

		:param transport: The transport stream to use with this client
		:return:
		"""
		self.peername = transport.get_extra_info('peername')
		logger.info('\n\nConnection from {}'.format(self.peername))
		self.transport = transport
		self.state = STATE_CONNECT


	def data_received(self, data: bytes) -> None:
		"""
        Called when data is received from the client.
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
		Called when a frame (JSON Object) is extracted

		:param frame: The JSON object to process
		:return:
		"""
		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode JSON message: {}".format(frame))
			self.transport.close()
			return

		mtype = message.get('type', "").upper()
		error = None
		self.log_state(mtype)
		if mtype == 'NEGOTIATION':
			logger.debug('NEGOTIATION RECEIVED')
			(ret,error) = self.process_negotiation(message)
			self.state = STATE_NEGOTIATION

		elif mtype == 'DH_PARAMETERS':
			logger.debug('DH ROTATION RECEIVED')
			ret = self.process_dh(message)

			# Generate a symmetric key
			self.crypto.symmetric_key_gen()
			logger.debug("Key: {}".format(self.crypto.symmetric_key))

			message={'type':'DH_PARAMETERS_RESPONSE',
					 'parameters':{'public_key':str(self.crypto.public_key,'ISO-8859-1')}}
			self._send(message)
			if self.state == STATE_DATA:
				self.state = STATE_ROTATION
			else:
				self.state = STATE_DH
			self.change_key = True

		elif mtype == 'MAC':
			(ret,error)= self.process_mac(message)

			if ret:
				iv = base64.b64decode(message['iv'])
				tag = base64.b64decode(message['tag'])
				nonce = base64.b64decode(message['nonce'])

				if iv == '': iv = None
				if tag == '': tag = None
				if nonce == '': nonce = None

				self.decrypted_data.append(self.crypto.decrypt(base64.b64decode(self.encrypted_data.encode()),iv,tag,nonce))

				# process secure message
				self.process_secure()

		elif mtype == 'OPEN':
			if self.state == STATE_DH: # Check if state equal DH
				ret = self.process_open(message)
			else:
				self._send({'type': 'OK'})
				self.state = STATE_OPEN
				ret=True

		elif mtype == 'SECURE_MESSAGE':
			self.encrypted_data += message['content']
			ret = True

		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'Check server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()
	
	
	def process_negotiation(self, message: str) -> bool:
		"""
		Processes a NEGOTIATION message from the client
		This message should contain the available algorithms

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Negotiation: {}".format(message))
		flag = None

		for cipher in self.ciphers:
			if cipher in message['algorithms']['symmetric_ciphers']:
				
				self.ch_chipher = cipher
				break
		if self.ch_chipher != 'CHACHA20':
			for mode in self.modes:
				if mode in message['algorithms']['cipher_modes']:
					if mode == 'GCM' and ch_chipher != 'AES':
						continue
					self.ch_mode = mode
					break
		else:
			self.ch_mode = ''
		
		for digest in self.digest:
			if digest in message['algorithms']['digest']:
				self.ch_digest = digest
				break

		#print(f"Teste: {self.ch_chipher} {self.ch_mode} {self.ch_digest}")
		if self.ch_chipher is not None and self.ch_mode is not None and self.ch_digest is not None:

			self.crypto.cipher = self.ch_chipher
			self.crypto.mode = self.ch_mode
			self.crypto.digest = self.ch_digest
			flag = True

		else:
			flag = False
			return (False,"Client algorithms not compatible with server algorithms")

		if flag:
			self._send({'type': 'NEGOTIATION_RESPONSE','chosen_algorithms':{'symmetric_cipher':self.crypto.cipher,'cipher_mode':self.crypto.mode,'digest':self.crypto.digest}})
			return (True,None)
		logger.debug("Choices {} {} {}".format(self.ch_chipher,self.ch_mode,self.ch_digest))


	def process_dh(self, message: str) -> bool:
		"""
		Processes a DH_PARAMETERS message from the client
		Computes a shared key necessary to the DH algorithm.

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process DH parameters: {}".format(message))

		g = message['parameters']['g']
		p = message['parameters']['p']
		bytes_public_key = bytes(message['parameters']['public_key'], 'ISO-8859-1')

		try:
			ret = self.crypto.dh_server(p,g,bytes_public_key)
			return ret
		except:
			return False

	def process_mac(self,message: str) -> bool:
		"""
		Processes a MAC message from the client
		Checks the authenticity and integrity of a message previous received

		:param message: The message to process.
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process MAC: {}".format(message))

		client_mac = base64.b64decode(message['data'])

		# Generate server MAC
		self.crypto.mac_gen(base64.b64decode(self.encrypted_data))
		logger.debug("Client mac: {}".format(client_mac))
		logger.debug("Server mac: {}".format(self.crypto.mac))

		if client_mac == self.crypto.mac:
			logger.info("Integrity control succeeded")
			return (True, None)
		else:
			return (False, 'Integrity control failed.')


	def process_open(self, message: str) -> bool:
		"""
		Processes an OPEN message from the client
		This message should contain the filename

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Open: {}".format(message))

		if self.state != STATE_DH:
			logger.warning("Invalid state. Discarding")
			return False

		if not 'file_name' in message:
			logger.warning("No filename in Open")
			return False

		# Only chars and letters in the filename
		file_name = re.sub(r'[^\w\.]', '', message['file_name'])
		file_path = os.path.join(self.storage_dir, file_name)
		if not os.path.exists("files"):
			try:
				os.mkdir("files")
			except:
				logger.exception("Unable to create storage directory")
				return False

		try:
			self.file = open(file_path, "wb")
			logger.info("File open")
		except Exception:
			logger.exception("Unable to open file")
			return False

		self._send({'type': 'OK'})

		self.file_name = file_name
		self.file_path = file_path
		self.state = STATE_OPEN
		return True


	def process_data(self, message: str) -> bool:
		"""
		Processes a DATA message from the client
		This message should contain a chunk of the file

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Data: {}".format(message))

		if self.state == STATE_OPEN or self.state == STATE_ROTATION:
			self.state = STATE_DATA
			# First Packet

		elif self.state == STATE_DATA:
			# Next packets
			pass

		else:
			logger.warning("Invalid state. Discarding")
			return False

		try:
			data = message.get('data', None)
			if data is None:
				logger.debug("Invalid message. No data found")
				return False

			bdata = base64.b64decode(message['data'])
			#text = self.encryption.decrypt(bdata, self.encryption.hashed_key, self.encryption.A, self.encryption.M)
		except:
			logger.exception("Could not decode base64 content from message.data")
			return False

		try:
			logger.debug("Writing data: {}".format(bdata))
			if self.change_key:
				self.change_key = False
				self.file.seek(self.ppos)
				self.ppos = 0
			self.file.write(bdata)
			self.ppos = self.file.tell()
			self.file.flush()
		except:
			logger.exception("Could not write to file")
			return False

		return True


	def process_secure(self):
		"""
		Processes a SECURE_MESSAGE message from the client
		Contains encrypted content (to be decrypted)
		The content has a JSON message that could be of type OPEN, DATA or CLOSE.
		"""
		logger.debug("Process Secure: {}".format(self.encrypted_data))
		message = json.loads(self.decrypted_data[0])
		mtype = message['type'] 
		
		if mtype == 'OPEN':
			if self.state == STATE_DH:
				ret = self.process_open(message)
			else:
				self._send({'type': 'OK'})
				self.state = STATE_OPEN
				ret = True
				
		elif mtype == 'DATA':
			message = {'type': 'DATA', 'data': ''}
			for m in self.decrypted_data:
				message['data'] += json.loads(m)['data']
			ret = self.process_data(message)
		elif mtype == 'CLOSE':
			ret = self.process_close(message)

		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'Check server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")
			if self.file is not None:
				self.file.close()
				self.file = None

			self.state = STATE_CLOSE
			self.transport.close()

		self.encrypted_data = ''
		self.decrypted_data = []
		return True	

	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))
		self.crypto.mac_gen(base64.b64decode(self.encrypted_data))

		logger.info("File transfer finished. Closing transport.")
		self.transport.close()

		if self.file is not None:
			self.file.close()
			self.file = None

		self.state = STATE_CLOSE

		logger.info("AWAITING client connection... (type escape sequence to exit)")

		return True


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
	global storage_dir

	parser = argparse.ArgumentParser(description='Receives files from clients.')
	parser.add_argument('-v', action='count', dest='verbose',
						help='Shows debug messages (default=False)',
						default=0)
	parser.add_argument('-p', type=int, nargs=1,
						dest='port', default=5000,
						help='TCP Port to use (default=5000)')

	parser.add_argument('-d', type=str, required=False, dest='storage_dir',
						default='files',
						help='Where to store files (default=./files)')

	args = parser.parse_args()
	storage_dir = os.path.abspath(args.storage_dir)
	level = logging.DEBUG if args.verbose > 0 else logging.INFO
	port = args.port
	if port <= 0 or port > 65535:
		logger.error("Invalid port")
		return

	if port < 1024 and not os.geteuid() == 0:
		logger.error("Ports below 1024 require eUID=0 (root)")
		return

	coloredlogs.install(level)
	logger.setLevel(level)

	logger.info("Port: {} LogLevel: {} Storage: {}".format(port, level, storage_dir))
	tcp_server(ClientHandler, worker=2, port=port, reuse_port=True)


if __name__ == '__main__':
	main()


