from Crypto.Cipher import AES
from Crypto.Hash import MD5
import binascii, base64
import os, sys
from base64 import b64decode, b64encode

'''
* Let `l` be the length of the unpadded string
 * Let `m` be the amount of padding (`16 - (l % 16)`).
 * Append `m` bytes of the digit ` m` to the end of the input string.
 '''



BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def MD5_hash(content):
        h = MD5.new()
        h.update(content)
        return h.digest()

def get_master_key(salt, password):
        return salt+'$'+password

def run_self_tests():

        print 'Running self-tests...'

        print 'MD5 testing...',
        # MD5 test vectors taken from RFC 1321
        md5_test_vectors = {"":"d41d8cd98f00b204e9800998ecf8427e", "a":"0cc175b9c0f1b6a831c399e269772661", "abc":"900150983cd24fb0d6963f7d28e17f72"}

        try:
                for k, v in md5_test_vectors.iteritems():
                        assert v == MD5_hash(k).encode("hex")
                print '... [Passed]'
        except:
                print '[Failed]'
                sys.exit()

        print 'AES-CBC with 128-bit key testing...',
        # AES-CBC with 128-bit key test vectors taken from RFC 3602
        aes128_cbc_test_vectors = {"06a9214036b8a15b512e03d534120006|3dafba429d9eb430b422da802c9fac41|Single block msg":"e353779c1079aeb82708942dbe77181a", "6c3ea0477630ce21a2ce334aa746c2cd|c782dc4c098c66cbd9cd27d825682c81|This is a 48-byte message (exactly 3 AES blocks)":"d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684"}

        try:
                for k, v in aes128_cbc_test_vectors.iteritems():
                        assert binascii.unhexlify(v) == AES.new(binascii.unhexlify(k.split("|")[0]), AES.MODE_CBC, binascii.unhexlify(k.split("|")[1]) ).encrypt(k.split("|")[2])
                print '... [Passed]'
        except:
                print '[Failed]'
                sys.exit()

class Youber:

        run_self_tests() #Self tests are run as soon as Youber object is made to determine the crypto algorithms implemeted are running properly.

        def read_database(self, database, password):

                if os.path.isfile(database):
                        with open(database) as f:
                                print '\nReading database: %s\n' % database
                                s = f.read()

                                magic_number = binascii.hexlify(s[:4])

                                salt = s[4:8]
                                iv = s[8:24]
                                master_key = get_master_key(salt, password)

                                blob = s[24:88]
                                
                                aes_key = MD5_hash(master_key)

                                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                                plaintext = cipher.decrypt(blob)

                                randon_string = plaintext[:32]
                                
                                randon_string_md5 = plaintext[32:48]
                                
                                digest = MD5_hash(randon_string)

                                assert digest == randon_string_md5

                                key_value_pairs = s[88:]
                                i = 0
                                dictionary = {}
                                
                                while i < len(key_value_pairs):

                                        key_length = int(binascii.hexlify(key_value_pairs[i:(i+4)]), 16)
                                        i = i+4

                                        key = key_value_pairs[i:(i+key_length)]
                                        i = i+key_length

                                        value_length = int(binascii.hexlify(key_value_pairs[i:(i+4)]), 16)
                                        i=i+4

                                        value_blob = key_value_pairs[i:(i+value_length)]
                                        i=i+value_length

                                        value = unpad(cipher.decrypt(value_blob))

                                        value_md5 = key_value_pairs[i:(i+16)]
                                        i=i+16

                                        digest2 = MD5_hash(value)

                                        dictionary[key.rstrip("\x00")] = value.rstrip("\x00")
                                        
                                        assert digest2 == value_md5
                                        
                                return dictionary
                else:
                        return 'No such file at this path'

        def write_database(self, database, password, dictionary):

                magic_number = binascii.unhexlify('BADCAB00')

                salt = os.urandom(4)

                master_key = master_key = get_master_key(salt, password)

                aes_key = MD5_hash(master_key)

                iv = os.urandom(16)

                random_string = os.urandom(32)
                random_string_md5 = MD5_hash(random_string)
                trailing_zeros = '0'*16

                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                blob1 = cipher.encrypt(random_string+random_string_md5+trailing_zeros)

                key_value_pairs = ''
                for i in range(len(dictionary)):
                        key_value_pairs += binascii.unhexlify("%08X" % len(dictionary.keys()[i]))
                        key_value_pairs += dictionary.keys()[i]

                        encrypted_value = cipher.encrypt(pad(dictionary.values()[i]))
                        key_value_pairs += binascii.unhexlify("%08X" % len(encrypted_value))
                        key_value_pairs += encrypted_value
                        key_value_pairs += MD5_hash(dictionary.values()[i]) 

                print '\nWriting to database...',
                with open("test.db", "w") as db:
                        db.write(magic_number+salt+iv+blob1+key_value_pairs)
                        print '... [completed]'




                        


                
                                        















    
    
    
    


