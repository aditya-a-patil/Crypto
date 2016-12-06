#!/usr/bin/python

from Encryption import rsaKeyGen, dsaKeyGen, encrypt
from Decryption import decrypt
from Fingerprint import fingerprintUser
from Utilities import utc2DateTime, formatHex, printHelpMenu
from RESTCalls import setupNetworkStrings, lookupKey, lookupUsers, registerKey, getMessages, sendMSG

#import requests, json
import json

#from Crypto import Random
#from Crypto.Cipher import PKCS1_v1_5
#from Crypto.PublicKey import RSA
#from Crypto.Hash import SHA256
#import M2Crypto
from M2Crypto import DSA
#from base64 import b64decode
import sys, getopt

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

def prepareOutgoingMessage(pubKey, msg, ruser):
    
    cipherText = encrypt(pubKey, msg, user)
    global lastMessageID
    lastMessageID = lastMessageID + 1
    sendMSG(ruser, lastMessageID, cipherText, user)

def prepareIncomingMessage():
    msg = getMessages(user)
    if msg.json()['numMessages'] > 0:
        print '\nReceived %d encrypted msg' % msg.json()['numMessages']
        for i in range(msg.json()['numMessages']):
            sender = msg.json()['messages'][i]['senderID']
            key = lookupKey(sender)
            cipher = msg.json()['messages'][i]['message']
            msgID = msg.json()['messages'][i]['messageID']
            message = decrypt(key.json()['keyData'], cipher, sender, msgID, user)
            
            if message != 'No new messages.':
                if '>>>READMESSAGE' not in message:
                    readrcpt = '>>>READMESSAGE %d' % msgID
                    key = lookupKey(sender)
                    if key.json()['status'] == 'found key':
                        payload = prepareOutgoingMessage(key.json()['keyData'], readrcpt, sender)

                print 'Message ID: %s' % msgID
                print 'From: %s' % sender
                print 'Time: %s' % utc2DateTime(msg.json()['messages'][i]['sentTime'])
            #print 'msgID %d' % msgID
            print message
            print 'Decryption done \n'
    else:
        print 'No new messages.'


def listAllUsers():
    users = lookupUsers()

def genKeys():
    print PRINT_GENKEYS
    rsa_public_key_base64 = rsaKeyGen(user)
    dsa_public_key_base64 = dsaKeyGen(user)
    PUBLIC_KEY = rsa_public_key_base64 + '%' + dsa_public_key_base64
    registerKey(PUBLIC_KEY, user)

def sendMessage(ruser):
    key = lookupKey(ruser)
    if key.json()['status'] == 'found key':
        msg = raw_input("Enter message: ")
        prepareOutgoingMessage(key.json()['keyData'], msg, ruser)
    else:
        print ('No key registered for this user')

    
            
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
                    fingerprintUser(user, option.split(" ")[1])
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
        #sys.exit(0)
        
        
