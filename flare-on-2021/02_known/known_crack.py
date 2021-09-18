#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 2 - Known
# ----------------------------------------------------------------------------------------
import os


# ----------------------------------------------------------------------------------------
def recover_key():
    print('[+] Recovering encryption key ...')

    ror = lambda a, b: ((a >> b) | (a << (8-b))) & 0xFF

    # The first 8 bytes of the png image are known, so we can recover the key.
    plain = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]    
    cipher = [0xc7, 0xc7, 0x25, 0x1d, 0x63, 0x0d, 0xf3, 0x56]

    # Reverse the algorithm:
    #
    #   void __cdecl u_rol_xor_qword_encrypt(char *a1_plain, const char *a2_key) {
    #       for ( i = 0; (char)i < 8; LOBYTE(i) = i + 1 )
    #           a1_plain[i] = __ROL1__(a2_key[i] ^ a1_plain[i], i) - i;
    #   }
    #
    key = ''.join('%c' % (ror(plain[i] + i, i) ^ cipher[i]) for i in range(8))

    print('[+] Key found:', key)

    return key


# ----------------------------------------------------------------------------------------
def decrypt_file(cipher, key):
    rol = lambda a, b: ((a << b) | (a >> (8-b))) & 0xFF

    # Pad ciphertext.
    cipher += b"\0"*(8-(len(cipher) % 8))

    # Decrypt into blocks of 8.
    plain = []
    for i in range(0, len(cipher), 8):        
        plain += [(rol(cipher[i+j] ^ ord(key[j]), j) - j) & 0xff for j in range(8)]

    return bytes(plain) 


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Known crack started.')

    key = recover_key()

    for encrypted_file in ['capa.png.encrypted',
                           'commandovm.gif.encrypted',
                           'critical_data.txt.encrypted',
                           'flarevm.jpg.encrypted',
                           'latin_alphabet.txt.encrypted']:
        print ('[+] Decrypting:', encrypted_file)

        cipher = open(os.path.join('Files', encrypted_file), 'rb').read()
        plain = decrypt_file(cipher, key)
        open(os.path.join('DecryptedFiles', os.path.splitext(encrypted_file)[0]), 'wb').write(plain)

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-challenges/flare-on-2021/02_known$ ./known_crack.py
    [+] Known crack started.
    [+] Recovering encryption key ...
    [+] Key found: No1Trust
    [+] Decrypting: capa.png.encrypted
    [+] Decrypting: commandovm.gif.encrypted
    [+] Decrypting: critical_data.txt.encrypted
    [+] Decrypting: flarevm.jpg.encrypted
    [+] Decrypting: latin_alphabet.txt.e
'''
# ----------------------------------------------------------------------------------------

