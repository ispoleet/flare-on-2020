#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 9 - Evil
# ----------------------------------------------------------------------------------------
import struct 
import zlib
from Crypto.Cipher import ARC4


ciphertext_b = [
    0x9C, 0x5C, 0x0C, 0x96, 0x6C, 0x7F, 0xD8, 0xB9,
    0xCC, 0x38, 0xF6, 0x17, 0x6D, 0xAA, 0xBA, 0x84,
    0xBD, 0x83, 0xD8, 0x74, 0x58, 0xD7, 0xD3, 0x32,
    0x4C, 0x59, 0x1D, 0xFE, 0x5C, 0x24, 0xFB, 0x2B,
    0x6B, 0x4F, 0xA9, 0x0F
]

ciphertext_c = [
    0x32, 0x38, 0xA7, 0x02, 0x70, 0xDF, 0xE7, 0x2B,
    0xF7, 0x7A, 0x77, 0xF5, 0x76, 0x29, 0x1B, 0xA2,
    0x87, 0xE4, 0xC2, 0xF9, 0x53, 0xCC, 0x3F, 0x6E,
    0xE8, 0x9A, 0xA6, 0x82, 0x0C, 0xBD, 0xA4, 0xD1,
    0x96, 0xE8, 0x7A, 0x89, 0x00, 0xC5,
]

key_a = bytes([
    0x55, 0x8B, 0xEC, 0x64, 0xA1, 0x00, 0x00, 0x00, 
    0x6A, 0xFF, 0x68, 0xD4, 0x21, 0x41, 0x00, 0x50
])


# ----------------------------------------------------------------------------------------
def decrypt(ciphertext, key):
    cipher = ARC4.new(key)
    return cipher.decrypt(bytes(ciphertext))


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Evil crack started.')

    ciphertext_a = open('pic.bmp', 'rb').read()
    open('pic_dec.bmp', 'wb').write(decrypt(ciphertext_a, key_a))

    print('[+] Plaintext B:', decrypt(ciphertext_b, key_a))
     
    key = b''
    for secret in ['L0ve', 's3cret', '5Ex', 'g0d']:
        key += struct.pack('>L', zlib.crc32((secret + '\0').encode('utf-8')))

    print('[+] Decryption key: ', ', '.join('0x%02X' % x for x in key))
    print('[+] Plaintext C:', decrypt(ciphertext_c, key))   
    
# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-2021/09_evil$ ./evil_crack.py 
[+] Evil crack started.
[+] Plaintext B: b'N3ver_G0nNa_g1ve_y0u_Up@flare-on.com'
[+] Decryption key:  0xE3, 0xFC, 0x31, 0xF4, 0xD8, 0xE9, 0xB0, 0x78, 0x77, 0x06, 0x6B, 0x5A, 0xA2, 0x4F, 0x5B, 0x95
[+] Plaintext C: b'n0_mOr3_eXcEpti0n$_p1ea$e@flare-on.com'
'''
# ----------------------------------------------------------------------------------------
