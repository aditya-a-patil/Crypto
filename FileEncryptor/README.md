# README:

FileEncryptor is a mini-project assignment at an attempt to encrypt and decrypt files.
Encryption of file is done by first applying HMAC-SHA1 and then encryption under AES128-CBC.

# REQUIREMENTS:

This module requires the following module:
    *Python2.7
    *pyCrypto

# USUAGE:

Run the python file with following parameters:

    python FileEncryptor.py <mode> -k <32-byte key in hexadecimal> -i <input file> -o <output file>

    Where, 
        *mode can be either encrypt or decrypt,
        *the first 16 bytes of the key is the encryption key Kenc, and the next 16 bytes is the MAC key Kmac.
        *the input/output files can contain raw binary data or can be any format desired.

# EXAMPLE:

There are sample files included to verify that encryption and decryption is performed with no errors!

Key used for encrypting sample files is:
    4c1a03424b55e07fe7f27be1d58bb9324a9a5a04e8e99d0f45237d786d6bbaa7965c7808bbff1a91

# SPECIFICATION:

    Encrypt(kenc, kmac, M). Given a 16-byte secret key kenc, a 16-byte secret key kmac, and a variable-length octet string M, encrypt M as follows:
        1. First, apply the HMAC-SHA1 algorithm on input (kmac;M) to obtain a 20-byte MAC tag T.
        2. Compute M' = M||T.
        3. Compute M'' = M'||PS where PS is a padding string computed using the method of PKCS #5 as follows: first let n = |M'| mod 16. Now:
            (a) If n != 0, then set PS to be a string of 16 - n bytes, with each byte set to the value (16 - n)^2
            (b) If n = 0 then set PS to be a string consisting of 16 bytes, where each byte is set to 16 (0x10).
        4. Finally, select a random 16-byte Initialization Vector IV and encrypt the padded message M'' using AES-128 in CBC mode under key kenc:
                C' = AES-CBC-ENC(kenc; IV;M'')
        5. The output of the encryption algorithm is the ciphertext C = (IV || C').

    Decrypt(kenc; kmac;C). Given a 16-byte key kenc, a 16-byte key kmac and a ciphertext C, decryption is conducted as follows:
        1. First, parse C = (IV || C') and decrypt using AES-128 in CBC mode to obtain M'':
            M'' = AES-CBC-DEC(kenc; IV; C')
        2. Next, validate that the message padding is correctly structured. Let n be the value of the last byte in M''. Ensure that each of the final n bytes in M'' is equal to the value n. 
            If this check fails, output the distinguished error message "INVALID PADDING" and stop. Otherwise, strip the last n bytes from M'' to obtain M'.
        3. Parse M' as M||T where T is a 20-byte HMAC-SHA1 tag.
        4. Apply the HMAC-SHA1 algorithm on input (kmac;M) to obtain T'. If T != T' output the distinguished error message "INVALID MAC" and stop. Otherwise, output the decrypted message M.

# NOTE:
    
    This is not the most secure file encryption technique. DONOT use this for anything that matter. Things can and will go wrong.













