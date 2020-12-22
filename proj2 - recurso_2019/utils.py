import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class Crypto():

	def __init__(self, symmetric_cipher, cipher_mode, digest_function):
		self.cipher = symmetric_cipher
		self.mode = cipher_mode
		self.digest = digest_function
		self.symmetric_key=None
		self.public_key=None
		self.private_key=None
		self.shared_key=None
		self.mac=None
		self.iv=None
		self.tag=None 			# GCM tag
		self.nonce=None 		# ChaCha20 nonce

	# Generates shared key (server)
	def dh_server(self, p, g, bytes_public_key):
		pn = dh.DHParameterNumbers(p, g)
		parameters = pn.parameters(default_backend())
		self.private_key = parameters.generate_private_key()
		
		peer_public_key = self.private_key.public_key()
		self.public_key = peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
		
		public_key_client = crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
		self.shared_key = self.private_key.exchange(public_key_client)
		
		return True


	# Create shared key between client and server
	def create_shared_key(self, bytes_public_key):
		public_key_server = crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
		self.shared_key = self.private_key.exchange(public_key_server)


	# Generate shared key (client)
	def dh_client(self):
		parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

		self.private_key = parameters.generate_private_key()
		a_peer_public_key = self.private_key.public_key()
		p = parameters.parameter_numbers().p
		g = parameters.parameter_numbers().g
		y = peer_public_key.public_numbers().y

		self.public_key = peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,
														 crypto_serialization.PublicFormat.SubjectPublicKeyInfo)

		return(self.public_key, p, g, y)

	# Generates MAC with a digest function
	def mac_gen (self, my_text):

		if(self.digest == "SHA256"):
			a = hashes.SHA256()
		elif(self.digest == "SHA384"):
			a = hashes.SHA384()
		elif(self.digest == "SHA512"):
			a = hashes.SHA512()

		h = hmac.HMAC(self.symmetric_key, a, backend=default_backend())
		h.update(my_text)

		self.mac = binascii.hexlify(h.finalize()) 



	# Symmetric key derived from shared key
	def symmetric_key_gen(self):

		if(self.digest == "SHA256"):
			a = hashes.SHA256()
		elif(self.digest == "SHA384"):
			a = hashes.SHA384()
		elif(self.digest == "SHA512"):
			a = hashes.SHA512()
		else:
			raise Exception("Digest function unsupported")
        
		kdf = HKDF(
			algorithm=a,
			length=32,
			salt=None,
			info=b'handshake data',
			backend=default_backend()
		)
        
		key = kdf.derive(self.shared_key)

		if self.cipher == 'AES':
			self.symmetric_key = key[:16]
		elif self.cipher == '3DES':
 			self.symmetric_key = key[:8]
		elif self.cipher == 'CHACHA20':
			self.symmetric_key = key[:32]


    # Encryption with given ciphers and modes
	def encrypt(self, data):
		
		backend = default_backend()
		cipher = None
		block_size = 0
		mode = None
		value = os.urandom(16)

		if self.cipher != 'CHACHA20':
			self.iv = value
			if self.mode == 'CBC':
				if self.cipher == '3DES': self.iv = self.iv[:8]
				mode = modes.CBC(self.iv)
			elif self.mode == 'GCM':
				mode = modes.GCM(self.iv)
			else:
				raise Exception("Cipher mode unsupported")

		if self.cipher == 'AES':
			block_size = algorithms.AES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)		
		elif self.cipher == '3DES':
			block_size = algorithms.TripleDES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
		elif self.cipher == 'CHACHA20':
			self.nonce = value
			a = algorithms.ChaCha20(self.symmetric_key, self.nonce)
			cipher = Cipher(a, mode=None, backend=backend)
		else:
			raise Exception("Symmetric cipher unsupported")


		encryptor = cipher.encryptor()

		if (self.mode != 'GCM') and (self.cipher != 'CHACHA20'):
			padding = block_size - len(data) % block_size

			padding = 16 if padding and self.cipher == 'AES' == 0 else padding 
			padding = 8 if padding and self.cipher == '3DES' == 0 else padding 

			data += bytes([padding]*padding)
			ct = encryptor.update(data)

		elif self.cipher == 'CHACHA20':
			ct = encryptor.update(data)
		else:
			ct = encryptor.update(data)+encryptor.finalize()
			self.tag = encryptor.tag

		return ct


	def decrypt(self, data, iv=None, tag=None, nonce=None):
		backend = default_backend()
		cipher = None
		block_size = 0

		if self.cipher != 'CHACHA20':
			if self.mode == 'GCM':
				mode = modes.GCM(iv, tag)
			elif self.mode == 'CBC':
				if iv is not None:
					mode = modes.CBC(iv)
			else:
				raise Exception("Cipher mode not available")

		if self.cipher == 'AES':
			block_size = algorithms.AES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)
		elif self.cipher == '3DES':
			block_size = algorithms.TripleDES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
		elif algorithm == 'CHACHA20':
			a = algorithms.ChaCha20(self.symmetric_key, nonce)
			cipher = Cipher(a, mode=None, backend=backend)
		else:
			raise Exception("Symmetric cipher not available")
		
		decryptor = cipher.decryptor()
		ct = decryptor.update(data)+decryptor.finalize()
		
		if self.mode=='GCM' or self.cipher=='ChaCha20':
			return ct
		return ct[:-ct[-1]]

