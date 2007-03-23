#############################################################################
# 				  About					    #
#############################################################################

Author:   Todd Whiteman
Date:     12th September, 2005
Verion:   1.2
License:  Public Domain - free to do as you wish
Homepage: http://twhiteman.netfirms.com/des.html

This algorithm is a pure python implementation of the DES algorithm.
It is in pure python to avoid portability issues, since most DES 
implementations are programmed in C (for performance reasons).

Triple DES class is also implemented, utilising the DES base. Triple DES
is either DES-EDE3 with a 24 byte key, or DES-EDE2 with a 16 byte key.
See the "About triple DES" section below more info on this algorithm.

The code below is not written for speed or performance, so not for those
needing a fast des implementation, but rather a handy portable solution ideal
for small usages. It takes my AMD2000+ machine 1 second per 2.5 kilobyte to
encrypt or decrypt using the DES method. Thats very SLOW!!

#############################################################################
# 			     About triple DES				    #
#############################################################################

Triple DES is just running the DES algorithm 3 times over the data with the
specified key. The supplied key is split up into 3 parts, each part being 8
bytes long (the mandatory key size for DES).

The triple DES algorithm uses the DES-EDE3 method when a 24 byte key is
supplied. This means there are three DES operations in the sequence
encrypt-decrypt-encrypt with the three different keys. The first key will be
bytes 1 to 8, the second key bytes 9 to 16 and the third key bytes 17 to 24.

If a 16 byte key is supplied instead, the triple DES method used will be
DES-EDE2. This means there are three DES operations in the sequence
encrypt-decrypt-encrypt, but the first and third operations use the same key.
The first/third key will be bytes 1 to 8 and the second key bytes 9 to 16.


#############################################################################
# 			         Credits				    #
#############################################################################
Thanks go to:
 - David Broadwell:	Ideas, comments and suggestions
 - Mario Wolff:		Finding and debugging triple des CBC errors.


#############################################################################
# 				Installation				    #
#############################################################################

1. Extract the files from the pyDes archive.
2. Run the following command: python setup.py install

Note: 	On Unix, you'd run this command from a shell prompt; on Windows, you
	have to open a command prompt window (``DOS box'') and do it there;


#############################################################################
# 				pyDes usage				    #
#############################################################################

Class initialization
--------------------
pyDes.des(key, [mode], [IV])
pyDes.triple_des(key, [mode], [IV])

key  -> String containing the encryption key, 8 bytes for DES, 16 for Triple DES
mode -> Optional argument for encryption type, can be either
        pyDes.ECB (Electronic Code Book) or pyDes.CBC (Cypher Block Chaining)
IV   -> Optional argument, must be supplied if using CBC mode. Must be 8 bytes


Common methods
--------------
encrypt(data, [pad])
decrypt(data, [pad])

data -> String to be encrypted/decrypted
pad  -> Optional argument. For encryption, adds this characters to the end of
	the data string when data is not a multiple of 8 bytes. For decryption,
	will remove the trailing characters that match this pad character from
	the last 8 bytes of the unencrypted data string.

Example
-------

import pyDes

k = pyDes.des("DESCRYPT", pyDes.CBC, "\0\0\0\0\0\0\0\0")
d = k.encrypt("Please encrypt my string")
print "Encypted string: " + d
print "Decypted string: " + k.decrypt(d)

k = pyDes.triple_des("MySecretTripleDesKeyData")
d = k.encrypt("Encrypt this sensitive data", "*")
print "Encypted string: " + d
print "Decypted string: " + k.decrypt(d, "*")



See the module source (pyDes.py) for more examples of use.
You can slo run the pyDes.py file without and arguments to see a simple test.

Note: This code was not written for high-end systems needing a fast
      implementation, but rather a handy portable solution with small usage.
