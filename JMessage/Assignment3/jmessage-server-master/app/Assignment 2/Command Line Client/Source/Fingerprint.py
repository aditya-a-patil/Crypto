from RESTCalls import lookupKey
from Utilities import formatHex
from Crypto.Hash import SHA256
import json

def generateFingerprint(key):
    key = key.encode('utf-8')
    h = SHA256.new()
    h.update(key)
    fingerprint = h.hexdigest().upper()
    return formatHex(fingerprint, " ")
    
def fingerprintUser(user, ruser):
    key_self = lookupKey(user)
    key_user = lookupKey(ruser)
    if key_user.json()['status'] == 'found key':
        print 'Your key fingerprint:'
        print generateFingerprint(key_self.json()['keyData'])
        print 'Fingerprint for user %s:' % ruser
        print generateFingerprint(key_user.json()['keyData'])
    else:
        print ('No key registered for this user')
