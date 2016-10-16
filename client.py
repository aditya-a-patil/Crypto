#!/usr/bin/python

import requests, json

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256
import M2Crypto
from M2Crypto import DSA
from base64 import b64decode
import os, sys, getopt, binascii, base64
import datetime, time

global server, port, url, user, key, lastMessageID
server = ''
port = ''
user = ''
url = {}
headers = {}
lastMessageID = 0

PRINT_WELCOME_MSG = 'Welcome to JMessage. Type (h)elp for commands.'
PRINT_COMMAND_ERROR = 'Command error... Please use'
PRINT_ARGUMENT_ERROR = 'Argument Error:\nusuage: client.py -s <server> -p <port> -u <username> -w <passowrd (default is NONE)>'
PRINT_GENKEYS = 'Generating a new keypair...'


#PKSC5 padding/unpadding
BLOCK_SIZE = 16
def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
def unpad(s):
    return s[0:-ord(s[-1])]

def setupNetworkStrings(server, port):

    if 'http' in server:
        host = server+':'+port
    else:
        host = 'http://'+server+':'+port

    url['lookupUsers'] = host+'/lookupUsers'
    url['lookupKey'] = host+'/lookupKey/'
    url['registerKey'] = host+'/registerKey/'
    url['getMessages'] = host+'/getMessages/'
    url['sendMessage'] = host+'/sendMessage/'
    headers['content-type'] = 'application/json'

def utc2DateTime(utc):
    return datetime.datetime.fromtimestamp(utc).strftime('%c')

def createPEM(key):
    header = '-----BEGIN PUBLIC KEY-----\n'
    footer = '\n-----END PUBLIC KEY-----'
    key_pem = header + key + footer
    return key_pem

def decodeBase64(strBase64):
    return base64.b64decode(strBase64)

def formatHex(raw, delimiter):
    return delimiter.join([raw[i:i+2] for i in range(0, len(raw), 2)])

def retrieveKey(KEY, mode):
    if mode == 'RSA':
        return KEY.split("%")[0]
    else:
        return KEY.split("%")[1]

def retrieveCiphertext(cipher, n):
    return cipher.split(" ")[n]

def writeToFile(filename, contents):
    f = open(filename,'w')
    f.write(contents)
    f.close()

def deleteFile(filename):
    os.remove(filename)

def rsaEncryption(KEY, content):
    rsaKey64 = retrieveKey(KEY, 'RSA')
    rsaKeyDER = b64decode(rsaKey64)
    rsaKey = RSA.importKey(rsaKeyDER)
    cipher1 = PKCS1_v1_5.new(rsaKey)
    return cipher1.encrypt(content)

def rsaDecryption(KEY, cipher):
    dsize = SHA.digest_size
    sentinel = Random.new().read(0+dsize)
    cipher1 = PKCS1_v1_5.new(KEY)
    return cipher1.decrypt(cipher, sentinel)

def computeSHA1(content):
    hashObj = SHA.new()
    hashObj.update(content)
    return hashObj.digest()

def generateSignature(message):
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
    
def aesEncryption( key, plaintext, iv):
    cryptor = M2Crypto.EVP.Cipher( alg='aes_128_ctr', key=key, iv=iv, op=1)
    ret = cryptor.update( plaintext )
    ret = ret + cryptor.final()
    return ret

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

def encrypt(KEY, msg):

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
    signature = generateSignature(cipher_preDSA)

    #10
    signature_base64 = base64.b64encode(signature)

    #11
    CIPHER = cipher_preDSA + " " + signature_base64

    return CIPHER

def decrypt(KEY, cipher, sender, msgID):

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
    rsa_privatekey_filename = '%s_rsa_key.der'%user
    f_rsa_pem = open(rsa_privatekey_filename,'r')
    rsaKey = RSA.importKey(f_rsa_pem.read())

    plaintext1_aes_key = rsaDecryption(rsaKey, ciphertext1)

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
        print 'bad user'
        return message
    else:
        message = msg_formatted.split(":")[1]

    #10 - Send read receipt
    if '>>>READMESSAGE' not in message:
        readrcpt = '>>>READMESSAGE %d' % msgID
        key = lookupKey(sender)
        if key.json()['status'] == 'found key':
            payload = prepareOutgoingMessage(key.json()['keyData'], readrcpt, sender)


    #11 - Output M
    return message


        
def lookupUsers():
    r = requests.get(url['lookupUsers'], headers=headers)
    return r

def lookupKey(username):
    r = requests.get(url['lookupKey']+str(username))
    return r

def registerKey():

    #generate RSA key-pair
    rsa_key = RSA.generate(1024)
    rsa_public_key = rsa_key.publickey().exportKey('DER')
    rsa_public_key_base64 = base64.b64encode(rsa_public_key)

    #write rsa private key to file
    filename_rsa = '%s_rsa_key.der' % user
    writeToFile(filename_rsa, rsa_key.exportKey('DER'))

    #DSA
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
    dsa_public_key_base64 = ''.join(lines_list_nonewline[1:-1])

    PUBLIC_KEY = rsa_public_key_base64 + '%' + dsa_public_key_base64
    #print PUBLIC_KEY

    # POST
    payload = {}
    payload['keyData'] = str(PUBLIC_KEY) 
    return requests.post(url['registerKey']+str(user), data=json.dumps(payload), headers=headers)


def getMessages():
    r = requests.get(url['getMessages']+str(user), headers=headers)
    return r

def prepareOutgoingMessage(pubKey, msg, ruser):
    
    cipherText = encrypt(pubKey, msg)
    payload = {}
    payload['recipient'] = ruser
    global lastMessageID
    lastMessageID = lastMessageID + 1
    payload['messageID'] = lastMessageID
    payload['message'] = cipherText
    
    r = requests.post(url['sendMessage']+user, data=json.dumps(payload), headers=headers)
    if r.json()["result"] == 1:
        print 'Message sent.'
    else:
        print 'Failed to send message. Try again later...'

def prepareIncomingMessage():
    msg = getMessages()
    if msg.json()['numMessages'] > 0:
        #print msg.text
        for i in range(msg.json()['numMessages']):
            sender = msg.json()['messages'][i]['senderID']
            key = lookupKey(sender)
            cipher = msg.json()['messages'][i]['message']
            msgID = msg.json()['messages'][i]['messageID']
            message = decrypt(key.json()['keyData'], cipher, sender, msgID)
            if message != 'No new messages.':
                print 'Message ID: %s' % msgID
                print 'From: %s' % sender
                print 'Time: %s' % utc2DateTime(msg.json()['messages'][i]['sentTime'])
            print message
            
    else:
        print 'No new messages.'


def listAllUsers():
    users = lookupUsers()
    for i in range(users.json()["numUsers"]):
        print '%d : %s' %(i, users.json()["users"][i])

def genKeys():
    print PRINT_GENKEYS
    r = registerKey()
    if r.json()["result"] == 1:
        print 'Successfully registered a public key for %s .' % user
    else:
        print 'Failed to register a public key for %s .' % user

def sendMessage(ruser):
    key = lookupKey(ruser)
    if key.json()['status'] == 'found key':
        msg = raw_input("Enter message: ")
        prepareOutgoingMessage(key.json()['keyData'], msg, ruser)
    else:
        print ('No key registered for this user')

def generateFingerprint(key):
    key = key.encode('utf-8')
    h = SHA256.new()
    h.update(key)
    fingerprint = h.hexdigest().upper()
    return formatHex(fingerprint, " ")
    
def fingerprint(ruser):
    key_self = lookupKey(user)
    key_user = lookupKey(ruser)
    if key_user.json()['status'] == 'found key':
        print 'Your key fingerprint:'
        print generateFingerprint(key_self.json()['keyData'])
        print 'Fingerprint for user %s:' % ruser
        print generateFingerprint(key_user.json()['keyData'])
    else:
        print ('No key registered for this user')

    
def printHelpMenu():
    print 'Available commands:'
    helpKey = ['get (or empty line)', 'c(ompose) <user>', 'f(ingerprint) <user>', 'l(ist)', 'genkeys', 'h(elp)', 'q(uit)']
    helpValue = ['check for new messages', 'compose a message to <user>', 'return the key fingerprint of <user>', 'lists all the users in the system', 'generates and registers a fresh keypair', 'help', 'quit']
    for i in range(len(helpKey)):
        print "\t %-23s %1s %2s" % (helpKey[i], '-', helpValue[i])
            
#main  

def main(argv):

    try:
        opts, args = getopt.getopt(argv,"hs:p:u:")
    except getopt.GetoptError:
        print 'Argument Error:\nusuage: client.py -s <server> -p <port> -u <username> -w <passowrd (default is NONE)>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'usage: assignment1.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>'
            sys.exit()
        elif opt == '-s':
            global server
            server = arg
        elif opt in ("-p"):
            global port
            port = arg
        elif opt in ("-u"):
            global user
            user = arg
        elif opt in ("-w"):
            global outputfile
            outputfile = arg

if __name__ == "__main__":

    try:
        if len(sys.argv) == 1:
            print PRINT_ARGUMENT_ERROR
            sys.exit(2)

        main(sys.argv[1:])

        setupNetworkStrings(server, port)

        genKeys()
        print PRINT_WELCOME_MSG

        while 1==1:
            option = raw_input('enter command> ')

            if option == 'get' or option == '':
                prepareIncomingMessage()
                
            elif 'c ' in option or 'compose ' in option:
                if option == 'c ' or option == 'compose ':
                    print '%s "c <user>" ' % PRINT_COMMAND_ERROR
                elif len(option.split(" ")) == 2:
                    sendMessage(option.split(" ")[1])
                else:
                    print '%s "c <user>" ' % PRINT_COMMAND_ERROR

            elif 'f ' in option or 'fingerprint ' in option:
                if option == 'f ' or option == 'fingerprint ':
                    print '%s "f <user>" ' % PRINT_COMMAND_ERROR
                elif len(option.split(" ")) == 2:
                    fingerprint(option.split(" ")[1])
                else:
                    print '%s "f <user>" ' % PRINT_COMMAND_ERROR

            elif option == 'genkeys':
                genKeys()

            elif option == 'l' or option == 'list':
                listAllUsers()
                
            elif option == 'h' or option == 'help':
                printHelpMenu()

            elif option == 'q' or option == 'quit':
                sys.exit(0)

    except KeyboardInterrupt:
        pass

    finally:
        print ('\nThank you for using JMessage. Goodbye!')
#        sys.exit(0)
        
        
