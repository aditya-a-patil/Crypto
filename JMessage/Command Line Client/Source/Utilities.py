import datetime, time
from base64 import b64decode
import base64
import os

def retrieveKey(KEY, mode):
    if mode == 'RSA':
        return KEY.split("%")[0]
    else:
        return KEY.split("%")[1]

def retrieveCiphertext(cipher, n):
    return cipher.split(" ")[n]

def createPEM(key):
    header = '-----BEGIN PUBLIC KEY-----\n'
    footer = '\n-----END PUBLIC KEY-----'
    key_pem = header + key + footer
    return key_pem

def writeToFile(filename, contents):
    f = open(filename,'w')
    f.write(contents)
    f.close()

def utc2DateTime(utc):
    return datetime.datetime.fromtimestamp(utc).strftime('%c')

def decodeBase64(strBase64):
    return base64.b64decode(strBase64)

def formatHex(raw, delimiter):
    return delimiter.join([raw[i:i+2] for i in range(0, len(raw), 2)])

def deleteFile(filename):
    os.remove(filename)

def printHelpMenu():
    print 'Available commands:'
    helpKey = ['get (or empty line)', 'c(ompose) <user>', 'f(ingerprint) <user>', 'l(ist)', 'genkeys', 'h(elp)', 'q(uit)']
    helpValue = ['check for new messages', 'compose a message to <user>', 'return the key fingerprint of <user>', 'lists all the users in the system', 'generates and registers a fresh keypair', 'help', 'quit']
    for i in range(len(helpKey)):
        print "\t %-23s %1s %2s" % (helpKey[i], '-', helpValue[i])

