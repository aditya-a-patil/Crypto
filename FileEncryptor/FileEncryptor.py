from os import urandom
from Crypto.Hash import SHA
from Crypto.Cipher import AES
import sys, getopt

BLOCKSIZE = 64
key = ''
inputfile = ''
outputfile = ''

#---------------------------------
#   XOR Strings
#   Parameters:
#       xs, ys -> strings to be XORed
#   Output:
#       XOR of inputs returned
#   Description:
#       Perform logical XOR betweer the inputs.
#---------------------------------

def xor_strings(xs, ys):
    return ''.join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))

#---------------------------------
#   HMAC SHA1
#   Parameters:
#       key -> key required to compute HMAC
#       message -> message for which HMAC is to be computed
#   Output:
#       20-byte MAC tag object is returned
#   Descripition:
#       Computes MAC (defined in FIPS PUB 198-1) over SHA-1 cryptograpic
#       hash algorithm. This method makes SHA1 library call
#       from Crypto.Hash of PyCrypto.
#       As per the problem statement specification provided, key provided
#       will be 16-bytes hence appropriate padding with 0x00 is performed
#       to obtain the required 64-bytes length.
#---------------------------------

def HMAC_SHA1(key, message):

    if len(key) > BLOCKSIZE:
        key = SHA.new(key).hexdigest()
    else:
        key += b"\x00" * (BLOCKSIZE - len(key))

    ipad_key = b"\x36" * BLOCKSIZE
    opad_key = b"\x5C" * BLOCKSIZE

    ipad = (xor_strings(ipad_key.decode(), key.decode()))
    opad = (xor_strings(opad_key.decode(), key.decode()))

    inner_hash = SHA.new(ipad + message).digest()

    Tag = SHA.new(opad + inner_hash).digest()
    return Tag

#---------------------------------
#   Encryption:
#   Parameters:
#       key_mac -> key required to compute HMAC
#       key_enc -> key required to encrypt
#       message -> message for which encryption is to be performed
#   Output:
#       Cipher text is written to output file
#   Descripition:
#       Performs AES 128 CBC encryption.
#---------------------------------

def encryption(key_mac, key_enc, message):
    
    mac_tag = HMAC_SHA1(key_mac, message)

    #print '\n\n---- Encryption:'

    plaintext_hmac = message + mac_tag

    padding = ""
    n = len(plaintext_hmac)%16
    
    if n ==0:
        padding += b"\x10" * 16
    else:
        padding_len = 16 - n
        padding += chr(padding_len) * padding_len

    plaintext_padded = plaintext_hmac + padding

    iv = urandom(16)
    cipher = ""
    cipher_temp = ""
    n = len(plaintext_padded)/16
    for i in range(0, n):
        block = plaintext_padded[i*16:(i+1)*16]
        if(i == 0):
            cipher_temp = AES.new(key_enc).encrypt(xor_strings(block, iv))
        else:    
            cipher_temp = AES.new(key_enc).encrypt(xor_strings(block, cipher_temp))
        cipher += cipher_temp

    final_cipher = iv+cipher
    ciphertext = "".join(x.encode('hex') for x in final_cipher)
    #print ("\nCipher Text: " + ciphertext)

    f = open(outputfile, "wb")
    #f.write(ciphertext)   #Uncomment this line if you want to store your cipher text in readable HEX format
    f.write(final_cipher)   #Comment this line if you want to store your cipher text in readable HEX format
    f.close()
    print '\nEncryption Successful...\nCipher text written to output file.'

#---------------------------------
#   Decryption:
#   Parameters:
#       key_enc -> key required to decrypt
#       key_mac -> key required to verify HMAC
#       final_cipher -> ciphertext which needs to be decrypted
#   Output:
#       Deciphered text is written to output file
#   Descripition:
#       Performs AES 128 CBC decryption.
#---------------------------------

def decryption(key_enc, key_mac, final_cipher):

    iv = final_cipher[0:16]
    cipher = final_cipher[16:]
    n = len(cipher)/16
    plaintext_padded = ""
    plaintext = ""
    block1 = ""
    
    for i in range(0, n):
        block = cipher[i*16:(i+1)*16]
        if(i == 0):
            plaintext_padded += xor_strings(AES.new(key_enc).decrypt(block),iv)
        else:    
            plaintext_padded += xor_strings(AES.new(key_enc).decrypt(block),block1)
        block1 = block

    final = plaintext_padded[-1]
    final_int = int(final.encode('hex'), 16)
    pad = final * final_int
    if plaintext_padded[-final_int:] == pad:
        plaintext = plaintext_padded[:-final_int]
    else:
        print "INVALID PADDING"

    mac_tag1 = plaintext[-20:]
    plain = plaintext[:-20]
    mac_tag2 = HMAC_SHA1(key_mac, plain)
    if mac_tag2 == mac_tag1:
        #print '\n\nPlaintext: '+plain
        f = open(outputfile, "wb")
        f.write(plain)
        f.close()
        print '\nDecryption Successful...\nResult written to output file.'
    else:
        print "INVALID MAC!"

#---------------------------------
#   Main:
#   Parameters:
#       argv -> arguments passed by user
#   Output:
#       No output. key, input and output file are updated in respective variables
#   Descripition:
#       Parses arguments passed by user.
#---------------------------------

def main(argv):

    try:
        opts, args = getopt.getopt(argv,"hk:i:o:")
    except getopt.GetoptError:
        print 'Argument Error:\nusuage: assignment1.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'usage: assignment1.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>'
            sys.exit()
        elif opt in ("-k"):
            global key
            key = arg
        elif opt in ("-i"):
            global inputfile
            inputfile = arg
        elif opt in ("-o"):
            global outputfile
            outputfile = arg

if __name__ == "__main__":

    if len(sys.argv) == 1:
        print 'Argument Error:\nusuage: assignment1.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>'
        sys.exit(2)
        
    main(sys.argv[2:])
    mode = sys.argv[1]

    key_mac = key[-32:]
    key_enc = key[:32]

    if mode == 'encrypt':
        with open(inputfile, "rb") as f:
            message = f.read()
        f.close()
        encryption(key_mac, key_enc, message)
        
    elif mode == 'decrypt':
        with open(inputfile, "rb") as f:
            cipher = f.read()
        f.close()
        decryption(key_enc, key_mac, cipher)    #Comment this line if your cipher text is stored in HEX format
        #decryption(key_enc, key_mac, cipher.decode("hex")) #Uncomment this line if your cipher text is stored in HEX format

    else:
        print "Invalid mode!\nMode can be either 'encrypt' or 'decrypt'"
        print 'usage: assignment1.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>'

    
