#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 9 - crackinstaller
# --------------------------------------------------------------------------------------------------
import copy
import hashlib


# Lambdas to convert DWORDs to lists and back
dword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
list_2_dword = lambda a: a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24)
str_2_dword  = lambda a: ord(a[0]) | (ord(a[1]) << 8) | (ord(a[2]) << 16) | (ord(a[3]) << 24)


# --------------------------------------------------------------------------------------------------
# Salsa 20 custom implementation.
def salsa20_keygen(key):   
    k = [list_2_dword(key[4*i:4*(i + 1)]) for i in xrange(8)]
    c = [str_2_dword("expa"), str_2_dword("nd 3"), str_2_dword("2-by"), str_2_dword("te k")]
    init_state = [
        c[0], c[1], c[2], c[3], 
        k[0], k[1], k[2], k[3],
        k[4], k[5], k[6], k[7], 
        0,    0,    0,    0
    ]

    print '[+] Salsa 20 initial state: %s' % ' '.join('%08X' % x for x in init_state)

    state = copy.deepcopy(init_state)

    # Original implementation has 20 rounds, but we only do 10 here.
    for i in range(10):  
        state[0] += state[4];    
        state[0] &= 0xFFFFFFFF
        state[12] = ((state[0] ^ state[12]) >> 16) | ((state[0] ^ state[12]) << 16) & 0xFFFFFFFF
        state[8] += state[12];
        state[8] &= 0xFFFFFFFF
        state[4] = ((state[8] ^ state[4]) >> 20) | ((state[8] ^ state[4]) << 12) & 0xFFFFFFFF
        state[0] += state[4];
        state[0] &= 0xFFFFFFFF
        state[12] = ((state[0] ^ state[12]) >> 24) | ((state[0] ^ state[12]) << 8) & 0xFFFFFFFF
        state[8] += state[12];
        state[8] &= 0xFFFFFFFF
        state[4] = ((state[8] ^ state[4]) >> 25) | ((state[8] ^ state[4]) << 7) & 0xFFFFFFFF
        state[1] += state[5];
        state[1] &= 0xFFFFFFFF
        state[13] = ((state[1] ^ state[13]) >> 16) | ((state[1] ^ state[13]) << 16) & 0xFFFFFFFF
        state[9] += state[13];
        state[9] &= 0xFFFFFFFF
        state[5] = ((state[9] ^ state[5]) >> 20) | ((state[9] ^ state[5]) << 12) & 0xFFFFFFFF
        state[1] += state[5];
        state[1] &= 0xFFFFFFFF
        state[13] = ((state[1] ^ state[13]) >> 24) | ((state[1] ^ state[13]) << 8) & 0xFFFFFFFF
        state[9] += state[13];
        state[9] &= 0xFFFFFFFF
        state[5] = ((state[9] ^ state[5]) >> 25) | ((state[9] ^ state[5]) << 7) & 0xFFFFFFFF
        state[2] += state[6];
        state[2] &= 0xFFFFFFFF
        state[14] = ((state[2] ^ state[14]) >> 16) | ((state[2] ^ state[14]) << 16) & 0xFFFFFFFF
        state[10] += state[14];
        state[10] &= 0xFFFFFFFF
        state[6] = ((state[10] ^ state[6]) >> 20) | ((state[10] ^ state[6]) << 12) & 0xFFFFFFFF
        state[2] += state[6];
        state[2] &= 0xFFFFFFFF
        state[14] = ((state[2] ^ state[14]) >> 24) | ((state[2] ^ state[14]) << 8) & 0xFFFFFFFF
        state[10] += state[14];
        state[10] &= 0xFFFFFFFF
        state[6] = ((state[10] ^ state[6]) >> 25) | ((state[10] ^ state[6]) << 7) & 0xFFFFFFFF
        state[3] += state[7];
        state[3] &= 0xFFFFFFFF
        state[15] = ((state[3] ^ state[15]) >> 16) | ((state[3] ^ state[15]) << 16) & 0xFFFFFFFF
        state[11] += state[15];
        state[11] &= 0xFFFFFFFF
        state[7] = ((state[11] ^ state[7]) >> 20) | ((state[11] ^ state[7]) << 12) & 0xFFFFFFFF
        state[3] += state[7];
        state[3] &= 0xFFFFFFFF
        state[15] = ((state[3] ^ state[15]) >> 24) | ((state[3] ^ state[15]) << 8) & 0xFFFFFFFF
        state[11] += state[15];
        state[11] &= 0xFFFFFFFF
        state[7] = ((state[11] ^ state[7]) >> 25) | ((state[11] ^ state[7]) << 7) & 0xFFFFFFFF
        state[0] += state[5];
        state[0] &= 0xFFFFFFFF
        state[15] = ((state[0] ^ state[15]) >> 16) | ((state[0] ^ state[15]) << 16) & 0xFFFFFFFF
        state[10] += state[15];
        state[10] &= 0xFFFFFFFF
        state[5] = ((state[10] ^ state[5]) >> 20) | ((state[10] ^ state[5]) << 12) & 0xFFFFFFFF
        state[0] += state[5];
        state[0] &= 0xFFFFFFFF
        state[15] = ((state[0] ^ state[15]) >> 24) | ((state[0] ^ state[15]) << 8) & 0xFFFFFFFF
        state[10] += state[15];
        state[10] &= 0xFFFFFFFF
        state[5] = ((state[10] ^ state[5]) >> 25) | ((state[10] ^ state[5]) << 7) & 0xFFFFFFFF
        state[1] += state[6];
        state[1] &= 0xFFFFFFFF
        state[12] = ((state[1] ^ state[12]) >> 16) | ((state[1] ^ state[12]) << 16) & 0xFFFFFFFF
        state[11] += state[12];
        state[11] &= 0xFFFFFFFF
        state[6] = ((state[11] ^ state[6]) >> 20) | ((state[11] ^ state[6]) << 12) & 0xFFFFFFFF
        state[1] += state[6];
        state[1] &= 0xFFFFFFFF
        state[12] = ((state[1] ^ state[12]) >> 24) | ((state[1] ^ state[12]) << 8) & 0xFFFFFFFF
        state[11] += state[12];
        state[11] &= 0xFFFFFFFF
        state[6] = ((state[11] ^ state[6]) >> 25) | ((state[11] ^ state[6]) << 7) & 0xFFFFFFFF
        state[2] += state[7];
        state[2] &= 0xFFFFFFFF
        state[13] = ((state[2] ^ state[13]) >> 16) | ((state[2] ^ state[13]) << 16) & 0xFFFFFFFF
        state[8] += state[13];
        state[8] &= 0xFFFFFFFF    
        state[7] = ((state[8] ^ state[7]) >> 20) | ((state[8] ^ state[7]) << 12) & 0xFFFFFFFF
        state[2] += state[7];
        state[2] &= 0xFFFFFFFF
        state[13] = ((state[2] ^ state[13]) >> 24) | ((state[2] ^ state[13]) << 8) & 0xFFFFFFFF
        state[8] += state[13];
        state[8] &= 0xFFFFFFFF
        state[7] = ((state[8] ^ state[7]) >> 25) | ((state[8] ^ state[7]) << 7) & 0xFFFFFFFF
        state[3] += state[4];
        state[3] &= 0xFFFFFFFF
        state[14] = ((state[3] ^ state[14]) >> 16) | ((state[3] ^ state[14]) << 16) & 0xFFFFFFFF
        state[9] += state[14];
        state[9] &= 0xFFFFFFFF
        state[4] = ((state[9] ^ state[4]) >> 20) | ((state[9] ^ state[4]) << 12) & 0xFFFFFFFF
        state[3] += state[4];
        state[3] &= 0xFFFFFFFF
        state[14] = ((state[3] ^ state[14]) >> 24) | ((state[3] ^ state[14]) << 8) & 0xFFFFFFFF
        state[9] += state[14];
        state[9] &= 0xFFFFFFFF
        state[4] = ((state[9] ^ state[4]) >> 25) | ((state[9] ^ state[4]) << 7) & 0xFFFFFFFF
  
    print '[+] Salsa 20 final (before adding initial) state: %s' % ' '.join('%08X' % x for x in init_state)
    
    # Add initial state to the current state.
    for i in range(16):
        state[i] += init_state[i]
        state[i] &= 0xFFFFFFFF
  
    return state


# --------------------------------------------------------------------------------------------------
# RC4 Implementation (copied from: https://github.com/bozhu/RC4-Python/blob/master/rc4.py)
def KSA(key):
    keylength = len(key)
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]  # swap

    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # swap
        K = S[(S[i] + S[j]) % 256]
        yield K

def RC4(key):
    S = KSA(key)
    return PRGA(S)


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Crackinstaller crack started.'

    print '* * * * * STEP 1 * * * * *'
    print '[+] Decrypting password ...'

    key_seed = "BBACABA"
    print '[+] Key seed: %s' % key_seed

    sha256 = hashlib.sha256(key_seed)
    print '[+] SHstate56(%s): %s' % (key_seed, sha256.hexdigest())

    salsa20_key = [ord(x) for x in sha256.digest()]
    print '[+] Salsa 20 key: %s' % ' '.join('%02X' % x for x in salsa20_key)
    
    key_stream = salsa20_keygen(salsa20_key)
    print '[+] Salsa 20 key stream: %s' % ' '.join('%08X' % x for x in key_stream)

    byte_stream = []
    for dword in key_stream:
        byte_stream += dword_2_list(dword)

    print '[+] Salsa 20 byte stream: %s' % ' '.join('%02X' % x for x in byte_stream)

    # Encrypted password
    cipher = '10 31 F0 8B 89 4E 73 B5 30 47 AD 6E 18 A9 5E'
    cipher = cipher.replace(" ", "").decode('hex')
    cipher = [ord(c) for c in cipher]
    print '[+] Ciphertext: %s' % ' '.join('%02X' % x for x in cipher)

    password = [byte_stream.pop(0) ^ c for c in cipher]
    print '[+] Plaintext: %s' % ' '.join('%02X' % x for x in password)
    print '[+] Password found!: %s' % ''.join(chr(x) for x in password)
    
    print '* * * * * STEP 2 * * * * *'
    print '[+] Decrypting flag ...'

    flag_cipher = '16 56 BC 86 9E E1 D1 02  65 C1 69 9F 10 0A AC C1' + \
                  'F6 E9 FD B4 CD 22 4A 35  9C 12 73 BD 2B 10 54 B9' + \
                  '43 D2 13 9A 84 65 AD B0  BF 5A 81 10'
    flag_cipher = flag_cipher.replace(" ", "").decode('hex')
    flag_cipher = [ord(c) for c in flag_cipher]
    print '[+] Flag ciphertext: %s' % ' '.join('%02X' % x for x in flag_cipher)

    print "[+] Generating RC4 stream with from key '%s' ..." % password
    keystream = RC4(password)
    
    flag = [c ^ keystream.next() for c in flag_cipher]
    print '[+] Plaintext: %s' % ' '.join('%02X' % x for x in flag)
    print '[+] Flag: %s' % ''.join(chr(x) for x in flag)
    
    print '[+] Program finished! Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
[+] Crackinstaller crack started.
* * * * * STEP 1 * * * * *
[+] Decrypting password ...
[+] Key seed: BBACABA
[+] SHstate56(BBACABA): 27d5f482adbb4032e97c76e83fe4e4fa0c29ed89641f014cb9b6f73b7c58057b
[+] Salsa 20 key: 27 D5 F4 82 AD BB 40 32 E9 7C 76 E8 3F E4 E4 FA 0C 29 ED 89 64 1F 01 4C B9 B6 F7 3B 7C 58 05 7B
[+] Salsa 20 initial state: 61707865 3320646E 79622D32 6B206574 82F4D527 3240BBAD E8767CE9 FAE4E43F 89ED290C 4C011F64 3BF7B6B9 7B05587C 00000000 00000000 00000000 00000000
[+] Salsa 20 final (before adding initial) state: 61707865 3320646E 79622D32 6B206574 82F4D527 3240BBAD E8767CE9 FAE4E43F 89ED290C 4C011F64 3BF7B6B9 7B05587C 00000000 00000000 00000000 00000000
[+] Salsa 20 key stream: AB9E7158 C14326AD 3CC40110 847FDD6B 5048164D 70F72098 9FEB029B 4E542E95 B1D4B0E0 BF4A78FF ADFDEF68 F1620AD1 4FB6B519 DA86E233 3659B396 66B9342B
[+] Salsa 20 byte stream: 58 71 9E AB AD 26 43 C1 10 01 C4 3C 6B DD 7F 84 4D 16 48 50 98 20 F7 70 9B 02 EB 9F 95 2E 54 4E E0 B0 D4 B1 FF 78 4A BF 68 EF FD AD D1 0A 62 F1 19 B5 B6 4F 33 E2 86 DA 96 B3 59 36 2B 34 B9 66
[+] Ciphertext: 10 31 F0 8B 89 4E 73 B5 30 47 AD 6E 18 A9 5E
[+] Plaintext: 48 40 6E 20 24 68 30 74 20 46 69 52 73 74 21
[+] Password found!: H@n $h0t FiRst!
* * * * * STEP 2 * * * * *
[+] Decrypting flag ...
[+] Flag ciphertext: 16 56 BC 86 9E E1 D1 02 65 C1 69 9F 10 0A AC C1 F6 E9 FD B4 CD 22 4A 35 9C 12 73 BD 2B 10 54 B9 43 D2 13 9A 84 65 AD B0 BF 5A 81 10
[+] Generating RC4 stream with from key '[72, 64, 110, 32, 36, 104, 48, 116, 32, 70, 105, 82, 115, 116, 33]' ...
[+] Plaintext: 53 30 5F 6D 40 6E 79 5F 63 6C 40 73 73 65 24 5F 69 6E 5F 74 68 33 5F 52 65 67 31 73 74 72 79 40 66 6C 61 72 65 2D 6F 6E 2E 63 6F 6D
[+] Flag: S0_m@ny_cl@sse$_in_th3_Reg1stry@flare-on.com
[+] Program finished! Bye bye :)
'''
# --------------------------------------------------------------------------------------------------
