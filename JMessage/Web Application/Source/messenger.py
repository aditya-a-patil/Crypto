import os
import sqlite3
import requests, json

from flask import Flask, jsonify, make_response, redirect, render_template, request, session, url_for

import settings

from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA, SHA256
import M2Crypto
from M2Crypto import DSA
from base64 import b64decode
import os, sys, getopt, binascii, base64
import datetime, time

app = Flask(__name__)
app.config.from_object(settings)

#JMessage Server settings:

global server, port, url, user, key, lastMessageID
server = ''
port = ''
user = ''
url = {}
headers = {}
lastMessageID = 0

def setupNetworkStrings(server):

    global url
    
    if 'http' in server:
        host = server
    else:
        host = 'http://'+server

    url['lookupUsers'] = host+'/lookupUsers'
    url['lookupKey'] = host+'/lookupKey/'
    url['registerKey'] = host+'/registerKey/'
    url['getMessages'] = host+'/getMessages/'
    url['sendMessage'] = host+'/sendMessage/'
    headers['content-type'] = 'application/json'

#PKSC5 padding/unpadding
BLOCK_SIZE = 16
def pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
def unpad(s):
    return s[0:-ord(s[-1])]

#JMessage functions

def formatHex(raw, delimiter):
    return delimiter.join([raw[i:i+2] for i in range(0, len(raw), 2)])

#genkeys

def writeToFile(filename, contents):
    f = open(filename,'w')
    f.write(contents)
    f.close()

def deleteFile(filename):
    os.remove(filename)

def registerKey():

    #generate RSA key-pair
    rsa_key = RSA.generate(1024)
    rsa_public_key = rsa_key.publickey().exportKey('DER')
    rsa_public_key_base64 = base64.b64encode(rsa_public_key)

    #write rsa private key to file
    filename_rsa = '%s_rsa_key.der' % session['username']
    writeToFile(filename_rsa, rsa_key.exportKey('DER'))

    #DSA
    dsa = DSA.gen_params(1024)
    dsa.gen_key()
    filename_dsa_private = '%s_dsa_private.pem' % session['username']
    dsa.save_key(filename_dsa_private, cipher=None)
    filename_dsa_public = '%s_dsa_public.pem' % session['username']
    dsa.save_pub_key(filename_dsa_public)

    lines_list_nonewline = []
    lines_list = open(filename_dsa_public).readlines()
    for i in lines_list:
        lines_list_nonewline.append(i.rstrip('\n'))
    dsa_public_key_base64 = ''.join(lines_list_nonewline[1:-1])

    PUBLIC_KEY = rsa_public_key_base64 + '%' + dsa_public_key_base64
    #print PUBLIC_KEY

    # POSTfrom Crypto.PublicKey import RSA

    payload = {}
    payload['keyData'] = str(PUBLIC_KEY) 
    return requests.post(url['registerKey']+session['username'], data=json.dumps(payload), headers=headers)


def genkeys():
    r = registerKey()
    if r.json()["result"] == 1:
        genKeyMsg = True
#        genKeyMsg = 'Successfully registered a public key for %s .' % session['username']
    else:
        genKeyMsg = False
#        genKeyMsg = 'Failed to register a public key for %s .' % session['username']

    return genKeyMsg


#lookup keys / key fingerprint
def lookupKey(username):
    r = requests.get(url['lookupKey']+username)
    return r

def generateFingerprint(key):
    key = key.encode('utf-8')
    h = SHA256.new()
    h.update(key)
    fingerprint = h.hexdigest().upper()
    return formatHex(fingerprint, " ")

def fingerprint(ruser):
    key_user = lookupKey(ruser)
    if key_user.json()['status'] == 'found key':
        return generateFingerprint(key_user.json()['keyData'])
    else:
        return 'No key registered for this user'


#decryption:


def utc2DateTime(utc):
    return datetime.datetime.fromtimestamp(utc).strftime('%c')

def createPEM(key):
    header = '-----BEGIN PUBLIC KEY-----\n'
    footer = '\n-----END PUBLIC KEY-----'
    key_pem = header + key + footer
    return key_pem

def decodeBase64(strBase64):
    return base64.b64decode(strBase64)

def retrieveKey(KEY, mode):
    if mode == 'RSA':
        return KEY.split("%")[0]
    else:
        return KEY.split("%")[1]

def retrieveCiphertext(cipher, n):
    return cipher.split(" ")[n]

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
    filename_dsa_private = '%s_dsa_private.pem' % session['username']
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
    sender_userid = session['username']
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
    rsa_privatekey_filename = '%s_rsa_key.der'%session['username']
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


#get message
def getMessages():
    getMsgURL = url['getMessages']+session['username']
    print getMsgURL
    r = requests.get(getMsgURL, headers=headers)
    return r

def prepareOutgoingMessage(pubKey, msg, ruser):
    
    cipherText = encrypt(pubKey, msg)
    payload = {}
    payload['recipient'] = ruser
    global lastMessageID
    lastMessageID = lastMessageID + 1
    payload['messageID'] = lastMessageID
    payload['message'] = cipherText
    
    r = requests.post(url['sendMessage']+session['username'], data=json.dumps(payload), headers=headers)
    if r.json()["result"] == 1:
        print 'Message sent.'
        return payload
    else:
        print 'Failed to send message. Try again later...'
       
# Helper functions
def _get_ONLY_users():
    users = requests.get(url['lookupUsers'], headers=headers)
    return [{'id': i, 'user': users.json()["users"][i],} for i in range(users.json()["numUsers"])]        
    
def _get_users():
    users = requests.get(url['lookupUsers'], headers=headers)
    return [{'id': i, 'user': users.json()["users"][i], 'fingerprint': fingerprint(users.json()["users"][i])} for i in range(users.json()["numUsers"])]        

def _get_message(id=None):

    """get message from server and update in DB"""

    msg = getMessages()
    if msg.json()['numMessages'] > 0:
        for i in range(msg.json()['numMessages']):
            sender = msg.json()['messages'][i]['senderID']
            key = lookupKey(sender)
            cipher = msg.json()['messages'][i]['message']
            msgID = msg.json()['messages'][i]['messageID']
            message = decrypt(key.json()['keyData'], cipher, sender, msgID)
            time = ''
            if message != 'No new messages.':
                time = utc2DateTime(msg.json()['messages'][i]['sentTime'])
            print message
            if '>>>READMESSAGE' in message:
                with sqlite3.connect(app.config['DATABASE']) as conn0:
                    c = conn0.cursor()
                    q = "UPDATE messages SET readRcpt=? WHERE id=?"
                    msgID = message.split(" ")[1]
                    c.execute(q, ('YES', msgID))
                    conn0.commit()
            else:
                with sqlite3.connect(app.config['DATABASE']) as conn1:
                    c = conn1.cursor()
                    q = "INSERT INTO messages VALUES (?,?,?,?,?,?)"
                    c.execute(q, (msgID, time, message, sender, session['username'], 'YES'))
                    conn1.commit()

    
    """Return a list of message objects (as dicts)"""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()

        if id:
            id = int(id)  # Ensure that we have a valid id value to query
            q = "SELECT * FROM messages WHERE sender=? OR recipient=? AND id=? ORDER BY dt DESC"
            rows = c.execute(q, (session['username'],session['username'],id,))

        else:
            q = "SELECT * FROM messages WHERE sender=? OR recipient=? ORDER BY dt DESC"
            rows = c.execute(q, (session['username'],session['username'],))

        return [{'id': r[0], 'dt': r[1], 'message': r[2], 'sender': r[3], 'recipient':r[4], 'readRcpt': r[5]} for r in rows]
    

def _add_message(message, recipient):

    key = lookupKey(recipient)
    if key.json()['status'] == 'found key':
        payload = prepareOutgoingMessage(key.json()['keyData'], message, recipient)
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            q = "INSERT INTO messages VALUES (?,?,?,?,?,?)"
            conn.execute(q, (payload['messageID'], utc2DateTime(int(time.time())),message, session['username'], payload['recipient'], 'NO'))
            conn.commit()
            return c.lastrowid

    else:
        print ('No key registered for this user')
        return 0




def _delete_message(ids):
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        q = "DELETE FROM messages WHERE id=?"

        # Try/catch in case 'ids' isn't an iterable
        try:
            for i in ids:
                c.execute(q, (int(i),))
        except TypeError:
            c.execute(q, (int(ids),))

        conn.commit()


# Standard routing (server-side rendered pages)
    
@app.route('/', methods=['GET', 'POST'])
def home():
    if not 'logged_in' in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        _add_message(request.form['message'], request.form['username'])
        redirect(url_for('home'))

    return render_template('index.html', messages=_get_message(), users=_get_ONLY_users())

@app.route('/genkey')
def genkey():
    genkeys()
    return redirect(url_for('home'))


@app.route('/users', methods=['GET'])
def users():
    if not 'logged_in' in session:
        return redirect(url_for('login'))
    
    return render_template('users.html', users=_get_users())


@app.route('/messages', methods=['GET', 'POST'])
def messages():
    if not 'logged_in' in session:
        return redirect(url_for('login'))

#    if request.method == 'POST':
        # This little hack is needed for testing due to how Python dictionary keys work
#        _delete_message([k[6:] for k in request.form.keys()])
#        redirect(url_for('messages'))

    messages = _get_message()
#    messages.reverse()
    return render_template('admin.html', messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if 1 == 2:
#        if request.form['username'] != app.config['USERNAME'] or request.form['password'] != app.config['PASSWORD']:
            error = 'Invalid username and/or password'
        else:
            session['server'] = request.form['server']
            session['username'] = request.form['username']
            session['logged_in'] = True
            global server
            server = session['server']
            setupNetworkStrings(server)
            genkeys()
            return redirect(url_for('home'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    
    session.pop('server', None)
    session.pop('username', None)
    session.pop('logged_in', None)
    return redirect(url_for('home'))


# RESTful routing (serves JSON to provide an external API)
@app.route('/messages/api', methods=['GET'])
@app.route('/messages/api/<int:id>', methods=['GET'])
def get_message_by_id(id=None):
    messages = _get_message()
    if not messages:
        return make_response(jsonify({'error': 'Not found'}), 404)

    return jsonify({'messages': messages})


@app.route('/messages/api', methods=['POST'])
def create_message():
    if not request.json or not 'message' in request.json or not 'sender' in request.json:
        return make_response(jsonify({'error': 'Bad request'}), 400)

    id = _add_message(request.json['message'], request.json['sender'])

    return get_message_by_id(id), 201


@app.route('/messages/api/<int:id>', methods=['DELETE'])
def delete_message_by_id(id):
    _delete_message(id)
    return jsonify({'result': True})


if __name__ == '__main__':

    # Test whether the database exists; if not, create it and create the table
    if not os.path.exists(app.config['DATABASE']):
        try:
            conn = sqlite3.connect(app.config['DATABASE'])

            # Absolute path needed for testing environment
            sql_path = os.path.join(app.config['APP_ROOT'], 'db_init.sql')
            cmd = open(sql_path, 'r').read()
            c = conn.cursor()
            c.execute(cmd)
            conn.commit()
            conn.close()
        except IOError:
            print "Couldn't initialize the database, exiting..."
            raise
        except sqlite3.OperationalError:
            print "Couldn't execute the SQL, exiting..."
            raise

    app.run(host='0.0.0.0')
