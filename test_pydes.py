from pyDes import *

#############################################################################
# 				Examples				    #
#############################################################################
def _example_triple_des_():
	from time import time

	# Utility module
	from binascii import unhexlify as unhex

	# example shows triple-des encryption using the des class
	print ("Example of triple DES encryption in default ECB mode (DES-EDE3)\n")

	print ("Triple des using the des class (3 times)")
	t = time()
	k1 = des(unhex("133457799BBCDFF1"))
	k2 = des(unhex("1122334455667788"))
	k3 = des(unhex("77661100DD223311"))
	d = "Triple DES test string, to be encrypted and decrypted..."
	print ("Key1:      %r" % k1.getKey())
	print ("Key2:      %r" % k2.getKey())
	print ("Key3:      %r" % k3.getKey())
	print ("Data:      %r" % d)

	e1 = k1.encrypt(d)
	e2 = k2.decrypt(e1)
	e3 = k3.encrypt(e2)
	print ("Encrypted: %r" % e3)

	d3 = k3.decrypt(e3)
	d2 = k2.encrypt(d3)
	d1 = k1.decrypt(d2)
	print ("Decrypted: %r" % d1)
	print ("DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8)))
	print ("")

	# Example below uses the triple-des class to achieve the same as above
	print ("Now using triple des class")
	t = time()
	t1 = triple_des(unhex("133457799BBCDFF1112233445566778877661100DD223311"))
	print ("Key:       %r" % t1.getKey())
	print ("Data:      %r" % d)

	td1 = t1.encrypt(d)
	print ("Encrypted: %r" % td1)

	td2 = t1.decrypt(td1)
	print ("Decrypted: %r" % td2)

	print ("Triple DES time taken: %f (%d crypt operations)" % (time() - t, 6 * (len(d) / 8)))

def _example_des_():
	from time import time

	# example of DES encrypting in CBC mode with the IV of "\0\0\0\0\0\0\0\0"
	print ("Example of DES encryption using CBC mode\n")
	t = time()
	k = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0")
	data = "DES encryption algorithm"
	print ("Key      : %r" % k.getKey())
	print ("Data     : %r" % data)

	d = k.encrypt(data)
	print ("Encrypted: %r" % d)

	d = k.decrypt(d)
	print ("Decrypted: %r" % d)
	print ("DES time taken: %f (6 crypt operations)" % (time() - t))
	print ("")

def _filetest_():
	from time import time

	f = open("pyDes.py", "rb+")
	d = f.read()
	f.close()

	t = time()
	k = des("MyDESKey")

	d = k.encrypt(d, " ")
	f = open("pyDes.py.enc", "wb+")
	f.write(d)
	f.close()
	
	d = k.decrypt(d, " ")
	f = open("pyDes.py.dec", "wb+")
	f.write(d)
	f.close()
	print ("DES file test time: %f" % (time() - t))
	
def _profile_():
	try:
		import profile
	except:
		import cProfile as profile
	profile.run('_fulltest_()')
	#profile.run('_filetest_()')

def _fulltest_():
	# This should not produce any unexpected errors or exceptions
	from time import time
	from binascii import unhexlify as unhex
	from binascii import hexlify as dohex

	t = time()

	k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
	d = k.encrypt("DES encryption algorithm")
	if k.decrypt(d) != "DES encryption algorithm":
		print ("Test 1:  Error: Unencypted data block does not match start data")
	else:
		print ("Test 1:  Successful")

	k = des("\0\0\0\0\0\0\0\0", CBC, "\0\0\0\0\0\0\0\0")
	d = k.encrypt("Default string of text", '*')
	if k.decrypt(d, "*") != "Default string of text":
		print ("Test 2:  Error: Unencypted data block does not match start data")
	else:
		print ("Test 2:  Successful")

	k = des("\r\n\tABC\r\n")
	d = k.encrypt("String to Pad", '*')
	if k.decrypt(d) != "String to Pad***":
		print ("'%s'" % k.decrypt(d))
		print ("Test 3:  Error: Unencypted data block does not match start data")
	else:
		print ("Test 3:  Successful")

	k = des("\r\n\tABC\r\n")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080"), unhex("44"))
	if k.decrypt(d, unhex("44")) != unhex("000102030405060708FF8FDCB04080"):
		print ("Test 4a: Error: Unencypted data block does not match start data")
	elif k.decrypt(d) != unhex("000102030405060708FF8FDCB0408044"):
		print ("Test 4b: Error: Unencypted data block does not match start data")
	else:
		print ("Test 4:  Successful")

	k = des("\r\n\tkey\r\n")
	d = k.encrypt("String to Pad", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String to Pad":
		print ("'%s' != 'String to Pad'" % k.decrypt(d))
		print ("Test 5a: Error: Unencypted data does not match original data")
	# Try same with padmode set on the class instance.
	k = des("\r\n\tkey\r\n", padmode=PAD_PKCS5)
	d = k.encrypt("String to Pad", )
	if k.decrypt(d) != "String to Pad":
		print ("'%s' != 'String to Pad'" % k.decrypt(d))
		print ("Test 5b: Error: Unencypted data does not match original data")
	else:
		print ("Test 5:  Successful")

	k = triple_des("MyDesKey\r\n\tABC\r\n0987*543")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"))
	if k.decrypt(d) != unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"):
		print ("Test 6:  Error: Unencypted data block does not match start data")
	else:
		print ("Test 6:  Successful")

	k = triple_des("\r\n\tABC\r\n0987*543")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"))
	if k.decrypt(d) != unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"):
		print ("Test 7:  Error: Unencypted data block does not match start data")
	else:
		print ("Test 7:  Successful")

	k = triple_des("MyDesKey\r\n\tABC\r\n0987*54B", CBC, "12341234")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"))
	if k.decrypt(d) != unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080"):
		print ("Test 8:  Error: Triple DES CBC failed.")
	else:
		print ("Test 8:  Successful")

	k = triple_des("MyDesKey\r\n\tABC\r\n0987*54B", CBC, "12341234")
	d = k.encrypt(unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDC"), '.')
	if k.decrypt(d, '.') != unhex("000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDCB04080000102030405060708FF8FDC"):
		print ("Test 9:  Error: Triple DES CBC with padding failed.")
	else:
		print ("Test 9:  Successful")

	k = triple_des("\r\n\tkey\rIsGoodKey")
	d = k.encrypt("String to Pad", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String to Pad":
		print ("'%s' != 'String to Pad'" % k.decrypt(d))
		print ("Test 10: Error: Unencypted data does not match original data")
	else:
		print ("Test 10: Successful")

	k = triple_des("\r\n\tkey\rIsGoodKey")
	d = k.encrypt("String not need Padding.", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String not need Padding.":
		print ("'%s' != 'String not need Padding.'" % k.decrypt(d))
		print ("Test 11: Error: Unencypted data does not match original data")
	else:
		print ("Test 11: Successful")

	# Test PAD_PKCS5 with CBC encryption mode.

	k = des("IGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	d = k.encrypt("String to Pad", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String to Pad":
		print ("'%s' != 'String to Pad'" % k.decrypt(d))
		print ("Test 12: Error: Unencypted data does not match original data")
	else:
		print ("Test 12: Successful")

	k = des("IGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	d = k.encrypt("String not need Padding.", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String not need Padding.":
		print ("'%s' != 'String not need Padding.'" % k.decrypt(d))
		print ("Test 13: Error: Unencypted data does not match original data")
	else:
		print ("Test 13: Successful")

	k = triple_des("\r\n\tkey\rIsGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	d = k.encrypt("String to Pad", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String to Pad":
		print ("'%s' != 'String to Pad'" % k.decrypt(d))
		print ("Test 14: Error: Unencypted data does not match original data")
	else:
		print ("Test 14: Successful")

	k = triple_des("\r\n\tkey\rIsGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7")
	d = k.encrypt("String not need Padding.", padmode=PAD_PKCS5)
	if k.decrypt(d, padmode=PAD_PKCS5) != "String not need Padding.":
		print ("'%s' != 'String not need Padding.'" % k.decrypt(d))
		print ("Test 15: Error: Unencypted data does not match original data")
	else:
		print ("Test 15: Successful")

	k = triple_des("\r\n\tkey\rIsGoodKey", mode=CBC, IV="\0\1\2\3\4\5\6\7", padmode=PAD_PKCS5)
	d = k.encrypt("String to Pad.")
	if k.decrypt(d) != "String to Pad.":
		print ("'%s' != 'String to Pad.'" % k.decrypt(d))
		print ("Test 16: Error: Unencypted data does not match original data")
	else:
		print ("Test 16: Successful")

	print ("")
	print ("Total time taken: %f" % (time() - t))

if __name__ == '__main__':
	#_example_des_()
	#_example_triple_des_()
	_fulltest_()
	#_filetest_()
	#_profile_()
