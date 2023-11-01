#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 04 - Aim Bot
# ----------------------------------------------------------------------------------------
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
import zlib


s1 = [
  0xC1, 0x8C, 0xED, 0x14, 0x93, 0xD7, 0xB6, 0x55, 0x9B, 0xCF, 
  0xB7, 0x54, 0x87, 0xC8, 0xB7, 0x55, 0x93, 0xCD, 0xAE, 0x57, 
  0x9B, 0xC0, 0xB6, 0x56, 0x86, 0x8B, 0xEC, 0x09, 0xC4, 0x99, 
  0xEB, 0x1D, 0xA9, 0xFB, 0x9A, 0x67
]

s2 = [
  0xCB, 0x99, 0xF7, 0x05, 0xC7, 0x99, 0xFB, 0x0B, 0xDD, 0xD8, 
  0xAC, 0x54, 0x99, 0xC8, 0x99, 0x65
]

s3 = [
  0x8B, 0x8E, 0xFC, 0x16, 0xDA, 0x91, 0xF6, 0x0A, 0x8B, 0xC2, 
  0xB9, 0x46, 0xA9, 0xFB, 0x9A, 0x67, 
]

s4 = [
  0xDD, 0x90, 0xFC, 0x44, 0xCD, 0x9D, 0xFA, 0x16, 0xD0, 0x88, 
  0xED, 0x0D, 0xC6, 0x96, 0xB9, 0x0B, 0xCF, 0xD8, 0xED, 0x0C, 
  0xC0, 0x8B, 0xB9, 0x06, 0xC5, 0x97, 0xFB, 0x44, 0xDE, 0x99, 
  0xEA, 0x44, 0xDA, 0x8D, 0xFA, 0x07, 0xCC, 0x8B, 0xEA, 0x02, 
  0xDC, 0x94, 0x99, 0x65,
]


dword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
list_2_dword = lambda a: a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24)


 # ----------------------------------------------------------------------------------------
def crack_keyC():
    keyA = 0x1337 + 8
    keyB = 0x616E6162    
    for keyC in range(0, 0x7FFFFFFF):
        keyC = 0x32b8408
        key = (keyA + keyB + keyC) & 0xFFFFFFFF
        
        decr = []
        for i in range(0, len(s1), 4):
            l = list_2_dword(s1[i:i+4])
            decr += dword_2_list(l ^ key)

        decr = ''.join(chr(x) for x in decr)
        if decr[:16].isprintable():
            print(f'[+] KeyC found: {keyC:08X}')
            return keyC

    raise Exception('KeyC not found :(')


 # ----------------------------------------------------------------------------------------
def decrypt_dll_strings():
    keyA = 0x1337 + 8
    keyB = 0x616E6162
    keyC = crack_keyC() # 0x32b8408
    key = (keyA + keyB + keyC) & 0xFFFFFFFF
    print(f'[+] String decryption Key: {key:08X}')

    for j, s in enumerate([s1, s2, s3, s4]):
        decr = []
        for i in range(0, len(s), 4):
            l = list_2_dword(s[i:i+4])
            # print(f'[+] List: {l:08X}')
            # print(f'[+] XOR : {l^key:08X}')
            decr += dword_2_list(l ^ key)

        decr = ''.join(chr(x) for x in decr)
        print(f'[+] Decrypted string for index #{j} is: {decr!r}')


# ----------------------------------------------------------------------------------------
def decrypt_shellcode_with_rc4(filename_in, filename_out, key):
    ciphertext = open(filename_in, 'rb').read()
    plaintext = ARC4.new(key).decrypt(bytes(ciphertext))

    print(f'[+] Decrypting {filename_in} with key {key}...')
    print(f"[+] Decrypted shellcode: {repr(plaintext[:32])}")
    print(f'[+] Saving shellcode to {filename_out} ...')

    open(filename_out, 'wb').write(plaintext)    


 # ----------------------------------------------------------------------------------------
def crack_shellcode_stage1():
    """
        To get the key:
        1. Run miner.exe
        2. Hit http://127.0.0.1:57328/2/summary on browser.
        3. Search for "version" string and get 16 characters from it.
    """
    ciphertext = open('glo_encr_shellcode.bin', 'rb').read()
    decryptor = AES.new(key=b'"version": "6.20', mode=AES.MODE_ECB)
    decrypted_data = decryptor.decrypt(ciphertext)

    print(f"[+] Decrypted shellcode: {repr(decrypted_data[:32])}")
    open('shellcode_stage1.bin', 'wb').write(decrypted_data)


# ----------------------------------------------------------------------------------------
def crack_shellcode_stage2():
    """
        Check config.vdf here: https://gist.github.com/Velaxtor/4695312

        "InstallConfigStore"
        {
            "Software"
            {
                ...
    """
    decrypt_shellcode_with_rc4(
        'glo_shellcode_stage2.bin',
        'shellcode_stage2.bin',
        b'"InstallConfigStore"'[:16]  # ssfn
    )


# ----------------------------------------------------------------------------------------
def crack_shellcode_stage3():
    """
        ispo@ispo-glaptop2:~/.config/discord$ hexdump -C Cookies | head
            00000000  53 51 4c 69 74 65 20 66  6f 72 6d 61 74 20 33 00  |SQLite format 3.|
    """
    decrypt_shellcode_with_rc4(
        'glo_shellcode_stage3.bin',
        'shellcode_stage3.bin',
        b'SQLite format 3\x00'
    )


# ----------------------------------------------------------------------------------------
def crack_shellcode_stage4():
    """
         "recentWalletFiles": [
            "/home/ispo/.sparrow/wallets/ispo_wallet.mv.db"
          ],
    """
    decrypt_shellcode_with_rc4(
        'glo_shellcode_stage4.bin',
        'shellcode_stage4.bin',
        b'recentWalletFiles'
    )


# ----------------------------------------------------------------------------------------
def crack_shellcode_stage5():
    """
        Do a known plaintext attack:

            key = 0x1234567 * secret;
            for ( i = 0; i < glo_shellcode_stage5_size / 4; ++i )
              glo_shellcode_stage5_ptr[i] ^= key;
            if ( !u_memcmp(glo_shellcode_stage5_ptr,
                           "the decryption of this blob was successful", 0x2Aui64) )
              __asm { jmp     rax }
    """
    known  = 0x20656874  # 'the d'
    cipher = 0x32513E04  # first 4 of shellcode
    key = known ^ cipher # 12345670
    print(f'[+] Stage #5 shellcode decryption key: 0x{key:08X}')

    ciphertext = open('glo_shellcode_stage5.bin', 'rb').read()
    ciphertext = list(ciphertext) + [0, 0, 0]  # Zero padding

    decrypted_data = []
    for i in range(0, len(ciphertext), 4):
        l = list_2_dword(ciphertext[i:i+4])
        decrypted_data += dword_2_list(l ^ key)

    decrypted_data = bytes(decrypted_data)
    print(f"[+] Decrypted shellcode: {repr(decrypted_data[:32])}")
    open('shellcode_stage5.bin', 'wb').write(decrypted_data)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Aimbot shellcode decryptor started.')
    
    decrypt_dll_strings()
    crack_shellcode_stage1()
    crack_shellcode_stage2()
    crack_shellcode_stage3()
    crack_shellcode_stage4()
    crack_shellcode_stage5()
   
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/04_aimbot$ ./aimbot_shellcode_decryptor.py 
[+] Aimbot shellcode decryptor started.
[+] KeyC found: 032B8408
[+] String decryption Key: 6499F8A9
[+] Decrypted string for index #0 is: 'http://127.0.0.1:57328/2/summary\x00\x03\x03\x03'
[+] Decrypted string for index #1 is: 'bananabot 5000\x00\x01'
[+] Decrypted string for index #2 is: '"version": "\x00\x03\x03\x03'
[+] Decrypted string for index #3 is: 'the decryption of this blob was successful\x00\x01'
[+] Decrypted shellcode: b'the decryption of this blob was '
[+] Decrypting glo_shellcode_stage2.bin with key b'"InstallConfigSt'...
[+] Decrypted shellcode: b'the decryption of this blob was '
[+] Saving shellcode to shellcode_stage2.bin ...
[+] Decrypting glo_shellcode_stage3.bin with key b'SQLite format 3\x00'...
[+] Decrypted shellcode: b'the decryption of this blob was '
[+] Saving shellcode to shellcode_stage3.bin ...
[+] Decrypting glo_shellcode_stage4.bin with key b'recentWalletFiles'...
[+] Decrypted shellcode: b'the decryption of this blob was '
[+] Saving shellcode to shellcode_stage4.bin ...
[+] Stage #5 shellcode decryption key: 0x12345670
[+] Decrypted shellcode: b'the decryption of this blob was '
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

