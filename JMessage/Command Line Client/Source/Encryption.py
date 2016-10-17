from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import M2Crypto
from M2Crypto import DSA
from base64 import b64decode
import base64, os, binascii

from Signature import generateSignature
from Utilities import retrieveKey, writeToFile

BLOCK_SIZE = 16
def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def rsaKeyGen(user):
    rsa_key = RSA.generate(1024)
    rsa_public_key = rsa_key.publickey().exportKey('DER')

    #write rsa private key to file
    filename_rsa = '%s_rsa_key.der' % user
    writeToFile(filename_rsa, rsa_key.exportKey('DER'))

    return base64.b64encode(rsa_public_key)

def dsaKeyGen(user):
    dsa = DSA.gen_params(1024)
    dsa.gen_key()
    filename_dsa_private = '%s_dsa_private.pem' % user
    dsa.save_key(filename_dsa_private, cipher=None)
    filename_dsa_public = '%s_dsa_public.pem' % user
    dsa.save_pub_key(filename_dsa_public)

    lines_list_nonewline = []
    lines_list = open(filename_dsa_public).readlines()
    for i in lines_list:
        lines_list_nonewline.append(i.rstrip('\n'))
        
    return ''.join(lines_list_nonewline[1:-1])

def rsaEncryption(KEY, content):
    rsaKey64 = retrieveKey(KEY, 'RSA')
    rsaKeyDER = b64decode(rsaKey64)
    rsaKey = RSA.importKey(rsaKeyDER)
    cipher1 = PKCS1_v1_5.new(rsaKey)
    return cipher1.encrypt(content)

def aesEncryption( key, plaintext, iv):
    cryptor = M2Crypto.EVP.Cipher( alg='aes_128_ctr', key=key, iv=iv, op=1)
    ret = cryptor.update( plaintext )
    ret = ret + cryptor.final()
    return ret


def encrypt(KEY, msg, user):

    #0. convert message to UTF-8 encoded string
    message = msg.encode('utf-8')
    
    #1.
    aes_key = os.urandom(16)

    #2
    ciphertext1 = rsaEncryption(KEY, aes_key)

    #3
    sender_userid = str(user)
    msg_formatted = str(sender_userid) + ':' + message

    #4
    CRC = binascii.crc32(msg_formatted) & 0xFFFFFFFF
    crc_hex = '%08X' % CRC
    msg_crc = msg_formatted + binascii.unhexlify(crc_hex)

    #5
    msg_padded = pad(msg_crc)

    #6
    iv = os.urandom(16)

    #7
    cipher2 = aesEncryption( aes_key, msg_padded, iv)
    ciphertext2 = iv + cipher2    

    #8
    ciphertext1_base64 = base64.b64encode(ciphertext1)
    ciphertext2_base64 = base64.b64encode(ciphertext2)

    #9
    cipher_preDSA = (ciphertext1_base64 + " " + ciphertext2_base64)
    signature = generateSignature(cipher_preDSA, user)

    #10
    signature_base64 = base64.b64encode(signature)

    #11
    CIPHER = cipher_preDSA + " " + signature_base64

    return CIPHER

