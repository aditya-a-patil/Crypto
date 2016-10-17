from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import M2Crypto, binascii

from RESTCalls import lookupKey
from Signature import verifySignature
from Hash import computeSHA1
from Utilities import retrieveKey, retrieveCiphertext, decodeBase64, writeToFile, createPEM, deleteFile

def unpad(s):
    return s[0:-ord(s[-1])]

def rsaDecryption(user, cipher):
    rsa_privatekey_filename = '%s_rsa_key.der'%user
    f_rsa_pem = open(rsa_privatekey_filename,'r')
    rsaKey = RSA.importKey(f_rsa_pem.read())

    dsize = SHA.digest_size
    sentinel = Random.new().read(0+dsize)
    cipher1 = PKCS1_v1_5.new(rsaKey)
    return cipher1.decrypt(cipher, sentinel)

def aesDecryption( key, ciphertext, iv):
    cryptor = M2Crypto.EVP.Cipher( alg='aes_128_ctr', key=key, iv=iv, op=0)
    ret = cryptor.update( ciphertext )
    ret = ret + cryptor.final()
    return ret


def verifyCRC(msg_crc):
    msg_formatted = msg_crc[:-4]
    crc_old = msg_crc[-4:]
    crc_new = binascii.crc32(msg_formatted)
    crc_new = binascii.unhexlify('%08X' % (crc_new & 0xffffffff))

    if crc_old != crc_new:
        print False
    else:
        return True

def decrypt(KEY, cipher, sender, msgID, user):

    message = 'No new messages.'
    
    #1
    dsaKey = retrieveKey(KEY, 'DSA')

    #2
    ciphertext1_base64 = retrieveCiphertext(cipher, 0).encode('utf-8')
    ciphertext2_base64 = retrieveCiphertext(cipher, 1).encode('utf-8')
    message_base64 = (" ".join(cipher.split(" ")[:2])).encode('utf-8')
    signature_base64 = retrieveCiphertext(cipher, 2).encode('utf-8')

    #3
    ciphertext1 = decodeBase64(ciphertext1_base64)
    ciphertext2 = decodeBase64(ciphertext2_base64)
    signature = decodeBase64(signature_base64)

    #4    
    signature = verifySignature(dsaKey, message_base64, signature)
    if not signature:
        return message

    #5
    plaintext1_aes_key = rsaDecryption(user, ciphertext1)

    #6
    iv = ciphertext2[:16]
    
    ciphertext2 = ciphertext2[16:]
    msg_padded = aesDecryption(plaintext1_aes_key, ciphertext2, iv)

    #7
    msg_crc = unpad(msg_padded)

    #8
    msg_formatted = msg_crc[:-4]

    crc = verifyCRC(msg_crc)   
    if not crc:
        return message
    
    #9
    sender_userid = msg_formatted.split(":")[0]

    if sender_userid != sender:
        return message
    else:
        message = msg_formatted.split(":")[1]

    #10 - Send read receipt from client.py


    #11 - Output M
    return message

