#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 13 - y0da
# ----------------------------------------------------------------------------------------
import base64
from Crypto.Cipher import ARC4


dword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]


bufA = [
  0x7F, 0x2B, 0xD8, 0xF5, 0xC3, 0x44, 0x6D, 0xB7, 0x75, 0x95, 
  0x89, 0xA7, 0xB9, 0xC3, 0x2C, 0x3F, 0x9E, 0x91, 0xB8, 0xDC, 
  0x6E, 0x55, 0xA7, 0x51, 0xE6, 0x2C, 0x59, 0xBC, 0x9C, 0x12, 
  0x98, 0x06, 0x8B, 0xA0, 0x50, 0x79, 0x18, 0xAA, 0x29, 0x4E, 
  0x84, 0x96, 0x5F, 0xA6, 0x37, 0x9F, 0xED, 0x9A, 0x33, 0x3C, 
  0xED, 0x34, 0x2D, 0x63, 0x7F, 0x6C, 0x5A
]

bufB = [  # NOT USED.
  0x05, 0xAC, 0x00, 0x00, 0x00, 0xC3, 0x05, 0xE4, 0x00, 0x00, 
  0x00, 0xC3, 0x05, 0xE8, 0x00, 0x00, 0x00, 0xC3, 0x83, 0xC0, 
  0x5A, 0xC3, 0x83, 0xC0, 0x60, 0xC3, 0x83, 0xC0, 0x70, 0xC3, 
  0x83, 0xC0, 0x7B, 0xC3, 0x05, 0x8F, 0x00, 0x00, 0x00, 0xC3, 
  0x05, 0x96, 0x00, 0x00, 0x00, 0xC3, 0x03, 0x45, 0x24, 0xC3, 
  0x48, 0x83, 0xC5, 0x38, 0xC3, 0x39, 0x45, 0x24, 0xC3, 0xFF, 
  0xC0, 0xC3, 0x88, 0x04, 0x0A, 0xC3, 0x89, 0x55, 0x10, 0xC3, 
  0x4C, 0x89, 0x45, 0x18, 0xC3, 0x88, 0x45, 0x20, 0xC3, 0x89, 
  0x45, 0x24, 0xC3, 0x48, 0x89, 0x4D, 0x08, 0xC3, 0xC7, 0x45, 
  0x24, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x8B, 0x45, 0x24, 0xC3, 
  0x8B, 0x45, 0x48, 0xC3, 0x8B, 0x4D, 0x24, 0xC3, 0x48, 0x8B, 
  0x4D, 0x40, 0xC3, 0x48, 0x8B, 0x55, 0x40, 0xC3, 0x48, 0x8B, 
  0x55, 0x50, 0xC3, 0x0F, 0xB6, 0x04, 0x01, 0xC3, 0x0F, 0xB6, 
  0x45, 0x20, 0xC3, 0x0F, 0xB6, 0x0C, 0x0A, 0xC3, 0x0F, 0xB6, 
  0x4D, 0x20, 0xC3, 0xF7, 0xD8, 0xC3, 0xF7, 0xD0, 0xC3, 0x0B, 
  0xC1, 0xC3, 0xD1, 0xF8, 0xC3, 0xC1, 0xF8, 0x02, 0xC3, 0xC1, 
  0xF8, 0x03, 0xC3, 0xC1, 0xF8, 0x05, 0xC3, 0xC1, 0xF8, 0x06, 
  0xC3, 0xC1, 0xF8, 0x07, 0xC3, 0xD1, 0xE1, 0xC3, 0xC1, 0xE1, 
  0x02, 0xC3, 0xC1, 0xE1, 0x03, 0xC3, 0xC1, 0xE1, 0x05, 0xC3, 
  0xC1, 0xE1, 0x06, 0xC3, 0xC1, 0xE1, 0x07, 0xC3, 0x2D, 0xB1, 
  0x00, 0x00, 0x00, 0xC3, 0x2D, 0xB2, 0x00, 0x00, 0x00, 0xC3, 
  0x2D, 0xC3, 0x00, 0x00, 0x00, 0xC3, 0x2D, 0xC5, 0x00, 0x00, 
  0x00, 0xC3, 0x2D, 0xDC, 0x00, 0x00, 0x00, 0xC3, 0x2D, 0xF3, 
  0x00, 0x00, 0x00, 0xC3, 0x2D, 0xFF, 0x00, 0x00, 0x00, 0xC3, 
  0x83, 0xE8, 0x18, 0xC3, 0x83, 0xE8, 0x1A, 0xC3, 0x83, 0xE8, 
  0x1E, 0xC3, 0x83, 0xE8, 0x28, 0xC3, 0x83, 0xE8, 0x36, 0xC3, 
  0x83, 0xE8, 0x04, 0xC3, 0x83, 0xE8, 0x49, 0xC3, 0x83, 0xE8, 
  0x56, 0xC3, 0x83, 0xE8, 0x58, 0xC3, 0x2D, 0x81, 0x00, 0x00, 
  0x00, 0xC3, 0x2D, 0x90, 0x00, 0x00, 0x00, 0xC3, 0x2D, 0x9A, 
  0x00, 0x00, 0x00, 0xC3, 0x2B, 0x45, 0x24, 0xC3, 0x48, 0x83, 
  0xED, 0x38, 0xC3, 0x35, 0xA3, 0x00, 0x00, 0x00, 0xC3, 0x35, 
  0xB6, 0x00, 0x00, 0x00, 0xC3, 0x35, 0xBF, 0x00, 0x00, 0x00, 
  0xC3, 0x35, 0xC2, 0x00, 0x00, 0x00, 0xC3, 0x35, 0xC9, 0x00, 
  0x00, 0x00, 0xC3, 0x35, 0xCB, 0x00, 0x00, 0x00, 0xC3, 0x83, 
  0xF0, 0x0D, 0xC3, 0x35, 0xE1, 0x00, 0x00, 0x00, 0xC3, 0x35, 
  0xEB, 0x00, 0x00, 0x00, 0xC3, 0x83, 0xF0, 0x16, 0xC3, 0x83, 
  0xF0, 0x20, 0xC3, 0x83, 0xF0, 0x22, 0xC3, 0x83, 0xF0, 0x25, 
  0xC3, 0x83, 0xF0, 0x40, 0xC3, 0x83, 0xF0, 0x78, 0xC3, 0x83, 
  0xF0, 0x7C, 0xC3, 0x35, 0x8F, 0x00, 0x00, 0x00, 0xC3, 0x33, 
  0x45, 0x24, 0xC3, 0x33, 0xC0, 0xC3, 0x33, 0xC1, 0xC3, 0xFF, 
  0xC1, 0xC3, 0x8B, 0xC9, 0xC3, 0x81, 0xE1, 0xFF, 0x00, 0x00, 
  0x00, 0xC3, 0x8B, 0x55, 0x24, 0xC3, 0x83, 0xC2, 0x02, 0xC3, 
  0x8B, 0xD2, 0xC3, 0x4C, 0x8B, 0x45, 0x50, 0xC3, 0x41, 0x0F, 
  0xB6, 0x14, 0x10, 0xC3, 0xD1, 0xFA, 0xC3, 0x81, 0xE2, 0xFF, 
  0x00, 0x00, 0x00, 0xC3, 0x23, 0xCA, 0xC3, 0x83, 0xC1, 0x03, 
  0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
]


# ----------------------------------------------------------------------------------------
def crack_resource():
    ciphertext = open('M4ST3R_Y0D4.resource.bin', 'rb').read()
    key = b'patience_y0u_must_h4v3'

    decryptor = ARC4.new(key)
    plaintext = decryptor.decrypt(bytes(ciphertext))
    print('[+] Decrypted resource:', repr(plaintext[:32]))
    return plaintext


# ----------------------------------------------------------------------------------------
def u_custom_decrypt(a1):
    buf = [0]*0x22
    buf[ 0] = 0x67
    buf[ 1] = 0x95
    buf[ 2] = 0xC8
    buf[ 3] = 0x8D
    buf[ 4] = 0x91
    buf[ 5] = 0x31
    buf[ 6] = 0xC3
    buf[ 7] = 0x21
    buf[ 8] = 0x7E
    buf[ 9] = 0x4A
    buf[10] = 0x3A
    buf[11] = 0x4D
    buf[12] = 0x56
    buf[13] = 0x55
    buf[14] = 0x7F
    buf[15] = 0x58
    buf[16] = 0x5D
    buf[17] = 0x2D
    buf[18] = 0xB7
    buf[19] = 0xCD
    buf[20] = 0x25
    buf[21] = 0xFF
    buf[22] = 0x26
    buf[23] = 0x64
    buf[24] = 0x6D
    buf[25] = 0xBD
    buf[26] = 0xCC
    buf[27] = 0xDD
    buf[28] = 0x3A
    buf[29] = 0x50
    buf[30] = 0xC6
    buf[31] = 0x9C
    buf[32] = 0xBB
    buf[33] = 0xF9

    for i in range(0x22):
        v2 = (i + (i ^ buf[i])) & 0xFF
        v3 = (((8 * v2) | (v2 >> 5)) - 107) & 0xFF
        buf[i] = (i ^ -(((-(~(~((((32 * v3) | (v3 >> 3)) - i) ^ 0xC3) - i) ^ 0xA9) - 60) ^ 0x1C) + 73)) - 30
        buf[i] &= 0xff
    
    return buf[a1 & 0x1F]


# ----------------------------------------------------------------------------------------
def lcg(a1):
    return (1103515245 * a1 + 12345) & 0x7FFFFFFF


# ----------------------------------------------------------------------------------------
def shuffle(a2):
    a1 = [a2] + [0]*624
    for i in range(1, 624):
        a1[624] = i
        a1[a1[624]] = (a1[624] + 0x6C078965 * ((a1[a1[624] - 1] >> 30) ^ a1[a1[624] - 1])) 
        a1[a1[624]] &= 0xFFFFFFFF

    a1[624] = 624
    return a1


# ----------------------------------------------------------------------------------------
def u_select_num_n_shuffle(a1):
    v8 = [0]*4
    v8[0] = 0
    v8[1] = 0x9908B0DF

    if a1[624] >= 0x270:
        if a1[624] >= 0x271:
            a1 = shuffle(4357)

        for i in range(227):
            v2 = a1[i + 1] & 0x7FFFFFFF | a1[i] & 0x80000000
            a1[i] = v8[v2 & 1] ^ (v2 >> 1) ^ a1[i + 397]
        
        i += 1 # In C. at this point `i` is 227, but in python is 226. Fix it.
    
        while i < 623:
            v5 = a1[i + 1] & 0x7FFFFFFF | a1[i] & 0x80000000
            a1[i] = v8[v5 & 1] ^ (v5 >> 1) ^ a1[i - 227]
            i += 1

        v6 = a1[0] & 0x7FFFFFFF | a1[623] & 0x80000000
        a1[623] = v8[v6 & 1] ^ (v6 >> 1) ^ a1[396]
        a1[624] = 0

    v3 = a1[a1[624]]
    a1[624] += 1
    v4 = ((((v3 >> 11) ^ v3) << 7) & 0x9D2C5680) ^ (v3 >> 11) ^ v3

    return ((((v4 << 15) & 0xEFC60000) ^ v4) >> 18) ^ ((v4 << 15) & 0xEFC60000) ^ v4


# ----------------------------------------------------------------------------------------
def u_num_shift(a1, a2):
    return a1 >> a2 if a2 > 0 else (a1 << -a2) & 0xFF


# ----------------------------------------------------------------------------------------
def sub_180012EDD(a1, a2):
    a3 = ''
    for i in range(8):
        v5 = 5 * i // 8
        v6 = 3 - 5 * i % 8

        if v5 >= a2:
            a3 += '='*(8 - i) # u_fill_in_with_equal          
            return a3

        v3 = u_num_shift(a1[v5], v6)
        if v6 < 0 and v5 < a2 - 1:
            v3 |= u_num_shift(a1[v5 + 1], v6 + 8)
        
        a3 += chr(u_custom_decrypt(v3))
    return a3

# ----------------------------------------------------------------------------------------
def u_encode_rop_result(a1_buf, a2_buflen):
    a3_out = ''

    i, j = 0, 0
    while i < a2_buflen:
        v3 = min(a2_buflen - i, 5)
        a3_out += sub_180012EDD(a1_buf[i:], v3)

        i += 5
        j += 8

    return a3_out

# ----------------------------------------------------------------------------------------
def rop(i, buf, buf2):
    # (v0 + 36) = i
    # (v0 + 64) = 0x19E0000 = buf that we are going to decrypt
    # (v0 + 32) = tmp 
    # (v0 + 80) = 0x19D0000 = buf2 = generated buf from `u_select_num_n_shuffle`
    tmp = buf[i]                   ; tmp &= 0xFF
    tmp = (32 * tmp) | (tmp >> 3)  ; tmp &= 0xFF
    tmp -= 84                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp -= 4                       ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = (32 * tmp) | (tmp >> 3)  ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = (4 * tmp) | (tmp >> 6)   ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp ^= 0xD                     ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += 123                     ; tmp &= 0xFF
    tmp ^= 0xBF                    ; tmp &= 0xFF
    tmp += 61                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += 96                      ; tmp &= 0xFF
    tmp = (8 * tmp) | (tmp >> 5)   ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 24                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += 13                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += 59                      ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = (2 * tmp) | (tmp >> 7)   ; tmp &= 0xFF
    tmp += 1                       ; tmp &= 0xFF
    tmp = (2 * tmp) | (tmp >> 7)   ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp ^= 0x8F                    ; tmp &= 0xFF
    tmp += 112                     ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 54                      ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 24                      ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp -= 86                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = (4 * tmp) | (tmp >> 6)   ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = (8 * tmp) | (tmp >> 5)   ; tmp &= 0xFF
    tmp ^= 0x40                    ; tmp &= 0xFF
    tmp += 102                     ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp ^= 0x16                    ; tmp &= 0xFF
    tmp += 127                     ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += 78                      ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += 112                     ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 40                      ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp += 36                      ; tmp &= 0xFF
    tmp = (2 * tmp) | (tmp >> 7)   ; tmp &= 0xFF
    tmp ^= 0x7C                    ; tmp &= 0xFF
    tmp = (tmp << 6) | (tmp >> 2)  ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp -= 106                     ; tmp &= 0xFF
    tmp ^= 0xA3                    ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = (4 * tmp) | (tmp >> 6)   ; tmp &= 0xFF
    tmp ^= 0xCB                    ; tmp &= 0xFF
    tmp =tmp ^ 0xFF #~tmp          ; tmp &= 0xFF
    tmp -= 26                      ; tmp &= 0xFF
    tmp ^= 0xB6                    ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += 79                      ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp ^= 0xE1                    ; tmp &= 0xFF
    tmp -= 113                     ; tmp &= 0xFF
    tmp = (tmp << 7) | (tmp >> 1)  ; tmp &= 0xFF
    tmp += 90                      ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp ^= 0x78                    ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp ^= 0xEB                    ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp ^= 0x25                    ; tmp &= 0xFF
    tmp = (2 * tmp) | (tmp >> 7)   ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp ^= 0xC9                    ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = (32 * tmp) | (tmp >> 3)  ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp -= 73                      ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 30                      ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = (8 * tmp) | (tmp >> 5)   ; tmp &= 0xFF
    tmp ^= 0x20                    ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp ^= 0x22                    ; tmp &= 0xFF
    tmp -= 88                      ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = (4 * tmp) | (tmp >> 6)   ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp -= 28                      ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp ^= i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp ^= 0xC2                    ; tmp &= 0xFF
    tmp -= i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF #~tmp         ; tmp &= 0xFF
    tmp += i                       ; tmp &= 0xFF
    tmp = tmp ^ 0xFF # ~tmp        ; tmp &= 0xFF
    tmp = -tmp                     ; tmp &= 0xFF
    tmp = (2 * tmp) | (tmp >> 7)   ; tmp &= 0xFF
    tmp &= 0xFF
    # v1 = buf2 #*(v0 + 80);

    # buf[i] = (4 * buf2[i + 3]) ^ (buf2[i + 2] >> 1) & (2 * buf2[i + 1]) ^ buf2[i] ^ tmp
    retv = (4 * buf2[i + 3]) ^ (buf2[i + 2] >> 1) & (2 * buf2[i + 1]) ^ buf2[i] ^ tmp
    retv &= 0xFF
    return retv, tmp


# ----------------------------------------------------------------------------------------
def gen_buf1(lcg_num):
    a1 = shuffle(lcg_num)

    buf1 = []
    for ii in range(0, 60, 4):
        num = u_select_num_n_shuffle(a1);
        buf1 += dword_2_list(num)[::-1]

    # print('[+] buf1:', ' '.join(f'{a:02X}' for a in buf1))
    return buf1


# ----------------------------------------------------------------------------------------
def gen_master_yoda_resp(buf1):
    """Generates the M4st3r Y0d4 response from an LCG number."""
    bufA_tmp = bufA[::]
    for i in range(0x38):
        retv, tmp = rop(i, bufA_tmp,  buf1)
        bufA_tmp[i] = retv

    # print('[+] New bufA:', ' '.join(f'{b:02X}' for b in bufA_tmp))
    result = u_encode_rop_result(bufA_tmp, 0x38)

    return f'M4st3r Y0d4 says {result}'
 

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] y0da crack started.')

    # jfif = crack_resource()
    # open('foo.jpg', 'wb').write(jfif)
    
    seed = 0x10D4
    for i in range(10):
        seed = lcg(seed)
        buf1 = gen_buf1(seed)
        resp = gen_master_yoda_resp(buf1)
        print(f'[+] LCG: 0x{seed:08X} ~> {resp}')

    print('[+] Getting flag ...')
    buf1 = [0]*60    
    for i in range(0x38):
        _, tmp = rop(i, bufA, buf1)
        bufA[i] = tmp
    bufA[0x38] = 0

    print(f'[+] Flat:', ''.join(chr(b) for b in bufA))


    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/13_y0da$ ./y0da_crack.py 
[+] y0da crack started.
[+] LCG: 0x5D1FF27D ~> M4st3r Y0d4 says OIZC4eMC/UnTPfDDMMaHeQXUHMPZy4LfSgg/HnB5SXVOIyKOBIHMe45B2KBCe5T/HRfRHZ4SKJe3eLJHeMe5IM5QQJ======
[+] LCG: 0x2C2A8572 ~> M4st3r Y0d4 says /SeOTX+LJS4/32+ynPBMPOe/I5MXw4HXyJRD4+QwP5KVafngPMgw+y+y/ne+/OBRMXaCnZI3JIa/D/ZeBJTVUnyCCC======
[+] LCG: 0x6AEFBDC3 ~> M4st3r Y0d4 says f/LB2wRf4Hw+K/TnnQeTeDUfXPSMVOfeMVK2eO+TaRw5+/O4nBe3eVHM+KSHRw4IKnKVIR4w4eX/BIMJ5DwJU34naC======
[+] LCG: 0x5BB76640 ~> M4st3r Y0d4 says XP4SMZH4yLD2ZnaaHTZyLHfH25MT+KDB2SDJwCUU44nOgLC43aUfODwQH53wZn3gBnUQeMPf5XnwJ2HfL+n5RKMfwQ======
[+] LCG: 0x43BE3979 ~> M4st3r Y0d4 says CSKPfMIDQ5n33Xn4H/Q/aDLHLPD3a2+4weUSXHe+BOTJfIfDng5yCwSUIKZCZaDJCX2H2fnTfw5M5+SPP/LwMMaVJ3======
[+] LCG: 0x7A1786BE ~> M4st3r Y0d4 says M2wgLBRT54aUXSQMOfTBJeQVyawwRH5gQwLyC/MaD4nUIBg+SUXOMDMwUVRfC53Og4MKQ5UyUZJ4QSVC2yU4Cny+TC======
[+] LCG: 0x1C06731F ~> M4st3r Y0d4 says B+TwnaLX3HIXLyV4yMn/TDCZQ/JffI3eeTynCQUXRXOe5/na2VCa5VyJLDgyMRnMPTfU+5n4MD4UP3LH4VZfnPVnnQ======
[+] LCG: 0x4ECCA66C ~> M4st3r Y0d4 says LORMB/fR35ySLgnTgwn22/CIfB52ZRaO4KKTIZOXT34R3MSZQ+JKHM2M3DZHDeS3XO2yOSXOM44CXfDCIVLgJPPn4Q======
[+] LCG: 0x0B5FF435 ~> M4st3r Y0d4 says 35/3PfXa/KVTJXJafgSP2ZP2K34aHeZ3XOR2nZSKJeILO/UgeSTZKaHHOQfnaRM2nMyfVR2U5gHHUOJDRVPOUQa2UC======
[+] LCG: 0x6A4150CA ~> M4st3r Y0d4 says XnnDIPf+UQnBKUR2XfK+CBMLQJ2HByQ3US4LeBKD2V//n2H4nyH+R4fXnILgVa3Hn/y/SHPZHnHeSHLOe+aMaZOTUf======
[+] Getting flag ...
[+] Flat: P0w3rfu1_y0u_h4v3_b3c0m3_my_y0ung_flareaw4n@flare-on.com
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------
