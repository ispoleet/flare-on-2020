#!/usr/bin/env python3
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 10 - break
# --------------------------------------------------------------------------------------------------
import struct
import idaapi
from Crypto.Cipher import AES


# --------------------------------------------------------------------------------------------------
def decrypt_aes_string(index):
    index ^= 0xAA

    addr = idaapi.get_dword(0x81A5140 + (index << 2))

    if index % 2 == 1:

        string = ''
        i = 0
        while True:
            ch = idaapi.get_byte(addr + i)
            if ch < 0x20 or ch > 0x7e:
                break
            string += chr(ch)
            i += 1

        decr_string = ''

        for i in range(len(string) >> 1):
            arg2, arg3 = ord(string[2*i]), ord(string[2*i + 1])
            eax = (16 * (arg2 - 1)) | (arg3 - 1) & 0xF
            eax &= 0xFF
            decr_string += chr(eax)
        
        return decr_string

    else:    
        key    = bytes(idaapi.get_byte(addr + i) for i in range(16))
        size   = idaapi.get_dword(addr + 16)
        cipher = bytes(idaapi.get_byte(addr + 20 + i) for i in range(size))

        decryptor = AES.new(key, AES.MODE_ECB)
        decrypted_data = decryptor.decrypt(cipher)

        return str(decrypted_data)


# --------------------------------------------------------------------------------------------------
def decrypt_xor_string(index):
    addr = idaapi.get_dword(0x81A51C0 + ((index ^ 0xAA) << 2))
    key  = bytes(idaapi.get_byte(addr + i) for i in range(4))
    size = idaapi.get_dword(addr + 4)
    cipher = bytes(idaapi.get_byte(addr + 8 + i) for i in range(size))
    plain  = ''.join(chr(cipher[i] ^ key[i % 4]) for i in range(size))

    return plain


# --------------------------------------------------------------------------------------------------
def is_printable(string):
    for s in string:
        if ord(s) == 0 or (ord(s) >= 0x20 and ord(s) <= 0x7e):
            pass
        else:
            return False

    return True


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Break string deobfuscation started.')

    str_tbl_1 = {i ^ 0xAA: decrypt_aes_string(i ^ 0xAA) for i in range(0, 26, 1)}

    for index, string in sorted(str_tbl_1.items()):
        if not is_printable(string):
            string = "[%s]" % ', '.join('0x%02X' % ord(s) for s in string)
        print('\t%X: %s,' % (index, string))

    print('[+] ' + '='*90)
    
    str_tbl_2 = {i ^ 0xAA: decrypt_xor_string(i ^ 0xAA) for i in range(38)}

    for index, string in sorted(str_tbl_2.items()):
        print('\t%X: %s,' % (index, string))

# --------------------------------------------------------------------------------------------------

