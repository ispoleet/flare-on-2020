#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 6 - codeit
# --------------------------------------------------------------------------------------------------
import struct
import hashlib
from Crypto.Cipher import AES


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Flare-On 2020: 6 - codeit'

    # Load sprite.bmp image and drop its first 54 bytes.
    with open('sprite.bmp') as fp:
        bmp = fp.read()
    bmp = bmp[54:]

    print '[+] First 16 bytes of sprite.bmp:', ' '.join('%02X' % ord(b) for b in bmp[:16])

    # --------------------------------------------------------------------------
    # Break computer name (aut01tfan1999)
    # --------------------------------------------------------------------------
    computer_name = ''
    ctr = 0

    for i in range(16):
        # Initialize value to 0.
        val = 0

        for j in range(6, -1, -1):
            val = (val + ((ord(bmp[ctr]) & 1) << j)) & 0xFF
            ctr += 1

        computer_name += chr(val)
        print '[+] Breaking character at %2d: %02X (%6s). Computer name: %s' % (
                i, val, repr(chr(val)), computer_name)

    computer_name = computer_name[:13]

    print '[+] Computer name:', computer_name

    # --------------------------------------------------------------------------
    # Apply function aregtfdcyni (fill_hash_data) 
    # --------------------------------------------------------------------------
    hash_data = ''
    ctr = 0
    for ch in computer_name:
        val = ord(ch)

        for j in range(6, -1, -1):
            val = (val + ((ord(bmp[ctr]) & 1) << j)) & 0xFF
            ctr += 1

        val = (val >> 1) + ((val & 1) << 7)         # ROR(val, 1)
        hash_data += chr(val)
        print '[+] Calcluating hash data for %c: %02X' % (ch, val)

    print '[+] Final hash data:', repr(hash_data)

    aes_key = hashlib.sha256(hash_data).digest()
    print '[+] Key hash (SHA256): ', ' '.join('%02X' % ord(h) for h in aes_key)

    iv = '\x00'*16
    cipher = (
        "CD4B32C650CF21BDA184D8913E6F920A" + \
        "37A4F3963736C042C459EA07B79EA443" + \
        "FFD1898BAE49B115F6CB1E2A7C1AB3C4" + \
        "C25612A519035F18FB3B17528B3AECAF" + \
        "3D480E98BF8A635DAF974E0013535D23" + \
        "1E4B75B2C38B804C7AE4D266A37B36F2" + \
        "C555BF3A9EA6A58BC8F906CC665EAE2C" + \
        "E60F2CDE38FD30269CC4CE5BB090472F" + \
        "F9BD26F9119B8C484FE69EB934F43FEE" + \
        "DEDCEBA791460819FB21F10F832B2A5D" + \
        "4D772DB12C3BED947F6F706AE4411A52"
    ).decode('hex')

    print '[+] Ciphertext size: %d' % len(cipher)
    print '[+] First 16 bytes of ciphertext:', ' '.join('%02X' % ord(c) for c in cipher[:16])
    print '[+] Key: ', ' '.join('%02X' % ord(h) for h in aes_key)
    print '[+] IV:', ' '.join('%02X' % ord(i) for i in iv)


    decryptor = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = decryptor.decrypt(cipher)
    print '[+] Plaintext:', repr(decrypted_data)

    # Format: 'FLARE|$WIDTH|$HEIGHT|$QR_CODE|ERALF'
    st = decrypted_data.find('FLARE') + 5
    end = decrypted_data.find('ERALF')
    width = struct.unpack('<L', decrypted_data[st:st+4])[0]
    height = struct.unpack('<L', decrypted_data[st+4:st+8])[0]
    st += 8

    qr_code = decrypted_data[st:end]

    print '[+] Width: %d' % width
    print '[+] Height: %d' % height
    print '[+] Encoded QR Code (%d bytes): %s' % (len(qr_code),
            ' '.join('%02X' % ord(q) for q in qr_code))

# --------------------------------------------------------------------------------------------------

