#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2022: 5 - T8
# ----------------------------------------------------------------------------------------
import struct
import hashlib
import base64
import subprocess
from Crypto.Cipher import ARC4


# ----------------------------------------------------------------------------------------
def unicode(s):
    return s.encode('utf-16')[2:]

def ascii(s):
    return s.decode('utf-16')


# ----------------------------------------------------------------------------------------
def decrypt_http_request(key, secret):
    print(f"[+] Decrypting HTTP request '{secret}' using key '{key}' ...")
    
    ciphertext = base64.b64decode(secret)

    print('[+] Ciphertext:', '-'.join('%02X' % x for x in ciphertext))

    # Key must be unicode.
    rc4_key = unicode(hashlib.md5(unicode(key)).hexdigest())
    rc4_cipher = ARC4.new(rc4_key)
    plaintext = rc4_cipher.decrypt(ciphertext)

    print(f"[+] Plaintext : {'-'.join('%02X' % x for x in plaintext)} "
          f"~> {ascii(plaintext)}")


# ----------------------------------------------------------------------------------------
def decrypt_http_response(key, secret, parse_plaintext=True):
    print(f"[+] Decrypting HTTP response '{secret}' using key '{key}' ...")
    
    ciphertext = base64.b64decode(secret)

    print('[+] Ciphertext:', '-'.join('%02X' % x for x in ciphertext[:32]))

    # Key must be unicode.
    rc4_key = unicode(hashlib.md5(unicode(key)).hexdigest())
    rc4_cipher = ARC4.new(rc4_key)
    plaintext = rc4_cipher.decrypt(ciphertext)

    print(f"[+] Plaintext : {'-'.join('%02X' % x for x in plaintext[:32])} ")

    if not parse_plaintext:
        return plaintext

    # Apply a 2nd layer of decryption to the plaintext:
    #
    # Split plaintext on commas (',') and we extract the first 2 DWORDs.
    # Then invoke the `u_custom_decrypt.c` function to generate a number.
    # Finally map this number into a character.
    flag = ''
    for chunk in plaintext.split(b',\x00'):        
        print(f"[+] Decrypting chunk : {'-'.join('%02X' % x for x in chunk[:16])} ")
        
        x = int(struct.unpack("<L", chunk[0:4])[0])
        y = int(struct.unpack("<L", chunk[4:8])[0])
        print(f"[+]    Extracting magic numbers: 0x{x:X} & 0x{y:X}")
        
        # Function `u_custom_decrypt` contains a lot of floating point operations
        # and Python messes up the calculations. It is simpler & safer to just do
        # the calculations in C. Hence, we invoke the function in C and we collect
        # the result. 
        result = subprocess.check_output(['./u_custom_decrypt', str(x), str(y)])
        result = int(result.strip())

        decrypted_char = ' abcdefghijklmnopqrstuvwxyz0_3'[result]

        print(f"[+]    Result: 0x{result:02x} ~> Decrypted character: '{decrypted_char}'")
        flag += decrypted_char

    print(f'[+] Decrypted flag: {flag}@flare-on.com')

    return flag


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] T8 crack started')

    # The key is the constant "F09" plus the last number from the user agent:
    #   User-Agent: Mozilla/4.0 (compatible; [....] .NET4.0E; 11950)
    key = 'FO9' + '11950'
    decrypt_http_request(key, 'ydN8BXq16RE=')
    
    flag = decrypt_http_response(
        key,
        'TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk'
        '6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4L'
        'u3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUy'
        'agT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KW'
        'gALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+L'
        'ezJEtrDXP1DJNg==')

    print('='*100)
    print('[+] Bonus: Decrypting 2nd HTTP message ...')

    # The 2nd HTTP message has the string CLR in user agent, so we use the flag as a key.
    key = flag + '@flare-on.com'
    decrypt_http_request(key, 'VYBUpZdG')

    plaintext = decrypt_http_response(
        key,
        'F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/'
        'Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYk'
        'mBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+',
        False)

    print(f'[+] Plaintext : {plaintext}')

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
[+] T8 crack started
[+] Decrypting HTTP request 'ydN8BXq16RE=' using key 'FO911950' ...
[+] Ciphertext: C9-D3-7C-05-7A-B5-E9-11
[+] Plaintext : 61-00-68-00-6F-00-79-00 ~> ahoy
[+] Decrypting HTTP response 'TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg==' using key 'FO911950' ...
[+] Ciphertext: 4D-D4-1D-05-16-B5-9F-11-94-D3-A7-5B-07-6E-C4-ED-24-3B-4C-9D-BE-71-DE-F3-B2-D2-D7-45-07-0B-6E-68
[+] Plaintext : E5-07-09-00-03-00-0F-00-0D-00-25-00-03-00-62-02-2C-00-DC-07-0A-00-06-00-0D-00-0D-00-25-00-09-00 
[+] Decrypting chunk : E5-07-09-00-03-00-0F-00-0D-00-25-00-03-00-62-02 
[+]    Extracting magic numbers: 0x907E5 & 0xF0003
[+]    Result: 0x09 ~> Decrypted character: 'i'
[+] Decrypting chunk : DC-07-0A-00-06-00-0D-00-0D-00-25-00-09-00-2A-03 
[+]    Extracting magic numbers: 0xA07DC & 0xD0006
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : E1-07-0C-00-04-00-07-00-0D-00-25-00-24-00-E5-00 
[+]    Extracting magic numbers: 0xC07E1 & 0x70004
[+]    Result: 0x13 ~> Decrypted character: 's'
[+] Decrypting chunk : E0-07-05-00-05-00-06-00-0D-00-25-00-0B-00-26-00 
[+]    Extracting magic numbers: 0x507E0 & 0x60005
[+]    Result: 0x1d ~> Decrypted character: '3'
[+] Decrypting chunk : E2-07-0A-00-01-00-08-00-0D-00-25-00-1F-00-45-03 
[+]    Extracting magic numbers: 0xA07E2 & 0x80001
[+]    Result: 0x1d ~> Decrypted character: '3'
[+] Decrypting chunk : E6-07-03-00-02-00-01-00-0D-00-25-00-32-00-DA-00 
[+]    Extracting magic numbers: 0x307E6 & 0x10002
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : DE-07-07-00-02-00-16-00-0D-00-25-00-36-00-D1-02 
[+]    Extracting magic numbers: 0x707DE & 0x160002
[+]    Result: 0x19 ~> Decrypted character: 'y'
[+] Decrypting chunk : DE-07-05-00-03-00-0E-00-0D-00-25-00-01-00-E8-00 
[+]    Extracting magic numbers: 0x507DE & 0xE0003
[+]    Result: 0x0f ~> Decrypted character: 'o'
[+] Decrypting chunk : DA-07-04-00-01-00-05-00-0D-00-25-00-3A-00-0B-00 
[+]    Extracting magic numbers: 0x407DA & 0x50001
[+]    Result: 0x15 ~> Decrypted character: 'u'
[+] Decrypting chunk : DD-07-0A-00-04-00-03-00-0D-00-25-00-16-00-16-03 
[+]    Extracting magic numbers: 0xA07DD & 0x30004
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : DE-07-01-00-02-00-0E-00-0D-00-25-00-10-00-C9-00 
[+]    Extracting magic numbers: 0x107DE & 0xE0002
[+]    Result: 0x0d ~> Decrypted character: 'm'
[+] Decrypting chunk : DC-07-0C-00-01-00-0A-00-0D-00-25-00-30-00-0C-02 
[+]    Extracting magic numbers: 0xC07DC & 0xA0001
[+]    Result: 0x1b ~> Decrypted character: '0'
[+] Decrypting chunk : E6-07-02-00-01-00-1C-00-0D-00-25-00-22-00-4B-01 
[+]    Extracting magic numbers: 0x207E6 & 0x1C0001
[+]    Result: 0x1b ~> Decrypted character: '0'
[+] Decrypting chunk : E6-07-09-00-05-00-09-00-0D-00-25-00-21-00-6D-01 
[+]    Extracting magic numbers: 0x907E6 & 0x90005
[+]    Result: 0x0e ~> Decrypted character: 'n'
[+] Decrypted flag: i_s33_you_m00n@flare-on.com
====================================================================================================
[+] Bonus: Decrypting 2nd HTTP message ...
[+] Decrypting HTTP request 'VYBUpZdG' using key 'i_s33_you_m00n@flare-on.com' ...
[+] Ciphertext: 55-80-54-A5-97-46
[+] Plaintext : 73-00-63-00-65-00 ~> sce
[+] Decrypting HTTP response 'F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYkmBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+' using key 'i_s33_you_m00n@flare-on.com' ...
[+] Ciphertext: 17-52-85-95-96-CD-1A-E2-90-C6-B4-C3-FC-E4-70-B9-D3-3C-4B-C9-0A-88-BE-45-F7-4E-98-95-1F-13-29-DF
[+] Plaintext : 31-D2-B2-30-64-8B-12-8B-52-0C-8B-52-1C-8B-42-08-8B-72-20-8B-12-80-7E-0C-33-75-F2-89-C7-03-78-3C 
[+] Plaintext : b"1\xd2\xb20d\x8b\x12\x8bR\x0c\x8bR\x1c\x8bB\x08\x8br \x8b\x12\x80~\x0c3u\xf2\x89\xc7\x03x<\x8bWx\x01\xc2\x8bz \x01\xc71\xed\x8b4\xaf\x01\xc6E\x81>Fatau\xf2\x81~\x08Exitu\xe9\x8bz$\x01\xc7f\x8b,o\x8bz\x1c\x01\xc7\x8b|\xaf\xfc\x01\xc7h!!!\x01hhineh machre ahYou'\x89\xe1\xfeI\x131\xc0QP\xff\xd7"
[+] Program finished! Bye bye :)
'''
# ----------------------------------------------------------------------------------------
