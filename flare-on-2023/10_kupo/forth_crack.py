#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 10 - Kupo
# ----------------------------------------------------------------------------------------


secret = [
  #0x2E, 0x00,

  0x1B, 0xD5, 0x78, 0xC3, 0x2F, 0x7C, 0xC2, 0xDA, 
  0x75, 0x2E, 0x78, 0x32, 0xD6, 0x7B, 0xD8, 0x23, 0x7D, 0xD9, 
  0x8A, 0x31, 0x3D, 0x86, 0xCC, 0x2C, 0x81, 0x2D, 0x7C, 0xC4, 
  0xD6, 0x74, 0x3F, 0x27, 0x82, 0xF6, 0x57, 0x34, 0xD8, 0x60, 
  0xC7, 0xE9, 0x32, 0xD0, 0xB1, 0x07, 0x21, 0x8F,# 0x5A, 0x0F
]


# ----------------------------------------------------------------------------------------
def decrypt(cipher, key):
    return [c ^ ord(key[i % len(key)]) for i, c in enumerate(cipher)]


# ----------------------------------------------------------------------------------------
def decode(buf):
    s = 0
    buf2 = []
    for i, b in enumerate(buf):
        buf2.append( (buf[i] + s) & 0xFF )
        s += buf[i]

    return buf2

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Kupo crack started.')


    ken_thompson_pw = 'p/q2-q4!'
    
    buf = secret
    print('~>', ' '.join(f'{x:02X}' for x in buf))
    
    #buf = decode(buf)
    #print('~>', ' '.join(f'{x:02X}' for x in buf))

    buf = decrypt(buf, ken_thompson_pw)
    print('~>', ' '.join(f'{x:02X}' for x in buf))

    buf = decode(buf)
    print('~>', ' '.join(f'{x:02X}' for x in buf))

    print(''.join(chr(x) for x in buf))
    print(' '.join(oct(x) for x in buf))
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
[+] Kupo crack started.
~> 1B D5 78 C3 2F 7C C2 DA 75 2E 78 32 D6 7B D8 23 7D D9 8A 31 3D 86 CC 2C 81 2D 7C C4 D6 74 3F 27 82 F6 57 34 D8 60 C7 E9 32 D0 B1 07 21 8F
~> 6B FA 09 F1 02 0D F6 FB 05 01 09 00 FB 0A EC 02 0D F6 FB 03 10 F7 F8 0D F1 02 0D F6 FB 05 0B 06 F2 D9 26 06 F5 11 F3 C8 42 FF C0 35 0C FE
~> 6B 65 6E 5F 61 6E 64 5F 64 65 6E 6E 69 73 5F 61 6E 64 5F 62 72 69 61 6E 5F 61 6E 64 5F 64 6F 75 67 40 66 6C 61 72 65 2D 6F 6E 2E 63 6F 6D
ken_and_dennis_and_brian_and_doug@flare-on.com
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

