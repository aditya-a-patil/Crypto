from M2Crypto import DSA

from Hash import computeSHA1
from Utilities import createPEM, writeToFile, deleteFile

def generateSignature(message, user):
    filename_dsa_private = '%s_dsa_private.pem' % user
    dsa = DSA.load_key(filename_dsa_private)
    cipher_preDSA_hash = computeSHA1(message)
    return dsa.sign_asn1(cipher_preDSA_hash)

def verifySignature(key, message, signature):
    key_pem = createPEM(key)
    filename = 'sender_dsa_key.pem'
    writeToFile(filename, key_pem)
    message_base64_hash = computeSHA1(message)
    dsa = DSA.load_pub_key(filename)
    verification = dsa.verify_asn1(message_base64_hash, signature)
    deleteFile(filename)
    return verification

