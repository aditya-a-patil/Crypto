import requests, json

global url, headers
url = {}
headers = {}


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


def lookupKey(username):
    r = requests.get(url['lookupKey']+str(username))
    return r

def lookupUsers():
    users = requests.get(url['lookupUsers'], headers=headers)
    for i in range(users.json()["numUsers"]):
        print '%d : %s' %(i, users.json()["users"][i])

def registerKey(PUBLIC_KEY, user):
    payload = {}
    payload['keyData'] = str(PUBLIC_KEY) 
    r = requests.post(url['registerKey']+str(user), data=json.dumps(payload), headers=headers)
    if r.json()["result"] == 1:
        print 'Successfully registered a public key for %s .' % user
    else:
        print 'Failed to register a public key for %s .' % user

def getMessages(user):
    r = requests.get(url['getMessages']+str(user), headers=headers)
    return r

def sendMSG(ruser, lastMessageID, cipherText, user):
    payload = {}
    payload['recipient'] = ruser
    payload['messageID'] = lastMessageID
    payload['message'] = cipherText
    
    r = requests.post(url['sendMessage']+user, data=json.dumps(payload), headers=headers)
    if r.json()["result"] == 1:
        print 'Message sent.'
    else:
        print 'Failed to send message. Try again later...'


