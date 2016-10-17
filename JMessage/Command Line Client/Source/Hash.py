from Crypto.Hash import SHA

def computeSHA1(content):
    hashObj = SHA.new()
    hashObj.update(content)
    return hashObj.digest()
