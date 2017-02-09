#     enc - Run Module - A free utility for encrypting Python code bases.
#     Copyright (C) 2017 M. Tyler Springer

#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.

#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.

#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <http://www.gnu.org/licenses/>.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from collections import OrderedDict
import sys, ast

notify_when_run = False
canary_DNS_token = 'EXAMPLE.canarytokens.com'

class EncryptedFormat(object):
	def __init__(self):
		# Encryption format is the linear representation of the encrypted file
		# for example, the first byte of the file is the compression type
		# the second byte is the storage type. The next 16 bytes are the initialization vector
		# and the remainder of the file is the encrypted source.
		self.encryption_format = OrderedDict([
			('compression',1),
			('storage_type',1),
			('initialization_vector',16),
			('body',-1)
		]) #-1 means read until EOF
		self.values = dict.fromkeys(self.encryption_format.keys())

	def populate_fields(self, target_path):
		with open(target_path, 'r') as fin:
			for field in self.encryption_format:
				self.values[field] = fin.read(self.encryption_format[field])

class SourceDecryptor(object):
	def __init__(self):
		pass

	def decrypt_and_run_target(self, target_path, secret):
		vals = EncryptedFormat()
		vals.populate_fields(target_path)
		decrypted_data = self.decrypt_source(vals, secret)
		if vals.values['compression'] == 'c':
			decrypted_data = self.uncompress_source(decrypted_data)
		return self.run_source(decrypted_data, vals.values['storage_type'])

	def run_source(self, data, storage_type):
		if storage_type == 'a':
			import cPickle
			tree = cPickle.loads(data)
			#print astunparse.unparse(tree)
			return compile(tree, filename="<ast>", mode="exec")
		elif storage_type == 'r':
			return data
		else:
			print 'Unrecognized File Format. Aborting.'
			exit(1)

	def decrypt_source(self, values, secret):
		h = SHA256.new()
		h.update(bytes(secret))
		encryptor = AES.new(h.digest(), AES.MODE_CBC, values.values['initialization_vector'])
		try:
			decrypted_data = encryptor.decrypt(values.values['body']).rstrip(" ") # rstrip to remove any possible padding
			return decrypted_data
		except:
			print 'Failed to successfully decrypt file'
			exit(1)

	def uncompress_source(self, data):
		import zlib
		return zlib.decompress(data)

def notify():
	import socket
	return socket.gethostbyname(canary_DNS_token)

if __name__ == "__main__":
	if notify_when_run:
		import thread
		try:
			thread.start_new_thread(notify,())
		except:
			print "Fatal error...please try running again."
			exit(1)
	if len(sys.argv) < 2:
		print "Incorrect number of arguments. Usage is: ./run <encrypted_unit_path> [arg [arg ...]]"
		exit(1)
	sd = SourceDecryptor()
	secret = raw_input("Please enter password: ")
	tree = sd.decrypt_and_run_target(sys.argv[1], secret)
	del sys.argv[1]
	exec(tree)