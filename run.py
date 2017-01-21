from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from collections import OrderedDict
import sys, ast

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

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Incorrect number of arguments. Usage is: ./run <encrypted_unit_path>"
		exit(1)
	sd = SourceDecryptor()
	secret = raw_input("Please enter password: ")
	tree = sd.decrypt_and_run_target(sys.argv[1], secret)
	exec(tree)