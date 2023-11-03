#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 12 - HVM
# ----------------------------------------------------------------------------------------
from Crypto.Cipher import ARC4
import ida_bytes


# --------------------------------------------------------------------------------------------------
def decrypt_code(rip, r8, r9):
    """ """
    encr_code = [ida_bytes.get_byte(rip + i) for i in range(r9)]

    key = r8.to_bytes(8, byteorder = 'little')
    decryptor = ARC4.new(key)
    plaintext = decryptor.decrypt(bytes(encr_code))
    print(repr(plaintext[:32]))
    
    for i in range(r9):
        ida_bytes.patch_byte(rip + i, plaintext[i])

    return plaintext


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] HVM virtual code decryptor started.')

    decrypt_code(0x00B9, 0x6DDCB037965C7F34, 0x305)
    decrypt_code(0x03E3, 0xDD0B0F81680FD682, 0x2b)
    decrypt_code(0x0433, 0xB7C5680B4414A725, 0x69)
    decrypt_code(0x04c1, 0x395EE00667D5D2A6, 0x10d)
    decrypt_code(0x05F3, 0xD3A5541BC79F6DF3, 0x23B)
    decrypt_code(0x0853, 0x5329EFAA8087EA73, 0x2D)
    decrypt_code(0x08A5, 0xE40CC96CA6B628F0, 0x60)
    decrypt_code(0x092A, 0x81AE1AF7D4C34557, 0x125)
    decrypt_code(0x0A74, 0xE7D8AD8771E63F39, 0xB8)
    decrypt_code(0x0B51, 0x899409BA9B3B8017, 0x4E)
    decrypt_code(0x0BC4, 0x1ACF57FBE20BB050, 0x1B)

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
'''
# ----------------------------------------------------------------------------------------




