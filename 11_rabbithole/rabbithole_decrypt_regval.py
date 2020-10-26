#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 11 - rabbithole
# --------------------------------------------------------------------------------------------------
import sys
import struct
import hashlib
import aplib
from Crypto.Util.number import long_to_bytes
from serpent import serpent_cbc_decrypt


encr_RSA_pubkey = [
    0x36, 0x3C, 0xCD, 0x0C, 0xBC, 0xD0, 0x25, 0xA3, 0xD7, 0x8A, 0x5E, 0xA4, 0x38, 0x58, 0xC1, 0x6E,
    0x05, 0x18, 0x65, 0xAE, 0xEC, 0x99, 0x0C, 0x70, 0x01, 0xE7, 0xF2, 0x14, 0x94, 0xAC, 0x13, 0x60,
    0x94, 0xFA, 0xA2, 0xCC, 0xF4, 0x6A, 0xDB, 0xB1, 0x7D, 0x1E, 0xEA, 0x13, 0x63, 0x32, 0x50, 0x2D,
    0x25, 0x00, 0x16, 0xBC, 0x10, 0xD4, 0x50, 0xE0, 0x32, 0x7E, 0xC0, 0x72, 0x25, 0xF9, 0x1E, 0xE3,
    0x87, 0x40, 0xCB, 0xE8, 0x7D, 0xF8, 0x39, 0xE1, 0x66, 0x07, 0x76, 0xEE, 0xEC, 0x10, 0x9C, 0x90,
    0x7A, 0x40, 0xB1, 0x4D, 0xA2, 0xE7, 0xA7, 0x34, 0x97, 0x03, 0x8C, 0xFD, 0xB3, 0x8E, 0x3E, 0xBB,
    0x68, 0x0C, 0x00, 0xD9, 0x56, 0xD0, 0xD5, 0xDD, 0x48, 0x25, 0xE1, 0x2F, 0xD9, 0x57, 0x7D, 0x83,
    0xD7, 0xFA, 0xC0, 0x9F, 0x79, 0x0E, 0xAB, 0x2C, 0x4B, 0x3F, 0x17, 0x7A, 0x83, 0x0B, 0xC6, 0x45,
    0x0B, 0xC8, 0xB0, 0x35, 0xF3, 0x2B, 0x07, 0x55, 0xBB, 0xE6, 0x02, 0xC0, 0x19, 0x78, 0x7B, 0x34,
    0x0B, 0x59, 0xF9, 0x14, 0x59, 0x04, 0x2C, 0xA0, 0x30, 0xE9, 0xA3, 0x7F, 0x68, 0x39, 0x6B, 0xFD,
    0x09, 0x43, 0xF8, 0xBF, 0xA1, 0x78, 0x5E, 0x4E, 0xE7, 0x20, 0x53, 0x24, 0x04, 0x05, 0x4B, 0xA8,
    0x85, 0xA0, 0x4C, 0xD1, 0xE9, 0x3E, 0x1B, 0x58, 0xFE, 0x1E, 0xB6, 0xA1, 0x50, 0x81, 0x35, 0x87,
    0x25, 0x78, 0x4B, 0x4B, 0xD7, 0x21, 0xCE, 0x5B, 0x65, 0xED, 0xC3, 0x28, 0x65, 0x95, 0x34, 0x49,
    0x59, 0xCA, 0x69, 0x19, 0x8A, 0xCC, 0x3B, 0xB4, 0x14, 0xDF, 0x62, 0x71, 0x81, 0x30, 0x21, 0xBE,
    0xD7, 0x97, 0x2A, 0xF3, 0xF6, 0x92, 0xED, 0x59, 0x18, 0xEB, 0x8C, 0xFA, 0x8B, 0xD4, 0x56, 0xB0,
    0x3F, 0xDC, 0x58, 0x51, 0x0A, 0x15, 0x36, 0x5F, 0xF6, 0xB7, 0x81, 0x18, 0xE4, 0xA0, 0x13, 0x5F,
    0x09, 0xA7, 0x71, 0x75, 0x40, 0x43, 0xB6, 0x51, 0x4D, 0x7F, 0x7A, 0xD2, 0x6E, 0x57, 0x89, 0xAC
]


# --------------------------------------------------------------------------------------------------
def decrypt_RSA_public_key():
    serpent_key = '90982d21090ef347'    
    cipher      = ''.join(chr(x) for x in encr_RSA_pubkey)

    print '[+] Decrypting RSA public key using serpent key: %s' % serpent_key

    RSA_pubkey  = serpent_cbc_decrypt(serpent_key, cipher)
    RSA_pubkey  = RSA_pubkey[8:]                    # drop the first 8 bytes

    # From crypto/rsaref.h:
    #
    #   /* RSA public and private key. */
    #   typedef struct {
    #       unsigned int bits;                           /* length in bits of modulus */
    #       unsigned char modulus[MAX_RSA_MODULUS_LEN];                    /* modulus */
    #       unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
    #   } R_RSA_PUBLIC_KEY;
    key_size, = struct.unpack("<L", RSA_pubkey[:4])

    n = RSA_pubkey[4:4 + (key_size >> 3)]
    n = int(n.encode('hex'), 16)

    e = RSA_pubkey[4 + (key_size >> 3):4 + (key_size >> 3)*2]
    e = int(e.encode('hex'), 16)


    print '[+] RSA key size: %d bits' % key_size
    print '[+] RSA public modulus : %X' % n
    print '[+] RSA public exponent: %X' % e

    return e, n


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Rabbithole decrypt registry values script started.'
    
    if len(sys.argv) != 2:
        print 'Usage: %s <REGISTRY EXPORT>' % sys.argv[0]
        exit()

    # --------------------------------------------------------------------------
    # Step 1: Decrypt RSA public key using serpent decryption
    # --------------------------------------------------------------------------
    e, n = decrypt_RSA_public_key()  


    # --------------------------------------------------------------------------
    # Step 2: Load encrypted registry data
    # --------------------------------------------------------------------------
    filename = sys.argv[1] # 'WebsoftwareProcesstemplate_export.bin'
    with open(filename, 'rb') as fp:
        reg_data = fp.read()

    # last 128 bytes are the RSA cipher with the serpent key:
    #   if ( !RsaDecryptWithPublic_13F531684(v17, &v14, a2_InSize + a1_InBuf - 0x80, 0x80i64, a4_pRsaKey)
    #           || (v7 = a2_InSize - 128, v19 > v7) ) {
    RSA_cipher     = reg_data[len(reg_data) - 0x80:]
    serpent_cipher = reg_data[:len(reg_data) - 0x80]

    RSA_cipher     = int(RSA_cipher.encode('hex'), 16)

    print '[+] RSA cipher: %X' % RSA_cipher


    # --------------------------------------------------------------------------
    # Step 3: Decrypt the serpent key using RSA public key(last 128 bytes)
    # --------------------------------------------------------------------------
    print '[+] Decrypting RSA cipher using public key (c^e = m mod n) ...'

    # Decrypt ciphertext
    RSA_plain = pow(RSA_cipher, e, n)
    print '[+] RSA plaintext: %X' % RSA_plain

    RSA_plain = long_to_bytes(RSA_plain)[::-1]
      
    # From crypto/sign.c:
    #
    #   // File digital signature header structure.
    #   typedef union   _DS_HEADER
    #   {
    #       struct 
    #       {
    #           MD5     Md5;    // MD5 hash of the signed data buffer
    #           RC6_KEY Key;    // RC6 key used to encrypt the buffer
    #           ULONG   Size;   // Size of the buffer in bytes
    #           ULONG   Salt;   // Random value
    #       };
    #       CHAR    Padding[RSA_BLOCK_LENGTH / 2];
    #   } DS_HEADER, *PDS_HEADER;
    salt        = RSA_plain[:4]
    size        = RSA_plain[4:8]
    serpent_key = RSA_plain[8:24][::-1]
    md5         = RSA_plain[24:40][::-1]
    
    size = int(size.encode('hex'), 16)
    md5 = ''.join('%02X' % ord(x) for x in md5)

    print '[+] Registry data MD5: %s' %  ' '.join('%02X' % ord(x) for x in md5)
    print '[+] Registry data serpent key: %s' % ' '.join('%02X' % ord(x) for x in serpent_key)
    print '[+] Registry data size: 0x%x' % size
    print '[+] Random salt: %s' % ' '.join('%02X' % ord(x) for x in salt)

      
    # --------------------------------------------------------------------------
    # Step 4: Decrypt and verify registry data
    # --------------------------------------------------------------------------
    print '[+] Decrypting registry data: %s ...' % ' '.join('%02X' % ord(x) for x in
                                                            serpent_cipher[:32])    
    plain = serpent_cbc_decrypt(serpent_key, serpent_cipher)
    plain = plain[:size]

    print '[+] Plain registry value: %s ...' % ' '.join('%02X' % ord(x) for x in
                                                        plain[:32])

    # Verify hash
    md5hash = hashlib.md5()
    md5hash.update(plain)
    md5hash.hexdigest().upper()
    
    print '[+] Registry value MD5 hash: %s' % md5hash.hexdigest().upper()

    if md5hash.hexdigest().upper() == md5:
        print '[+] MD5 hashes match! Decryption was successful.'
    else:
        print '[!] Error. MD5 hashes mismatch :('
        exit()


    # --------------------------------------------------------------------------
    # Step 5: Decompress plaintext
    # --------------------------------------------------------------------------
    print '[+] Decompressing plaintext ...'
    
    if plain[20] == 'P' and plain[21] == 'p' and plain[22] == 'X':
        print '[+] PpX signature found.'
    else:
        print '[!] Warning. PpX signature not found. Continuing anyways...'
        
    # Drop the first 20 bytes
    plain = plain[20:]
  
    decompressed_plain = aplib.decompress(plain).do()
    
    print '[+] Deflating: %d -> %d bytes ...' % (len(plain), len(decompressed_plain[0]))
    print '[+] Decompressed registry data: %s ...' % ' '.join('%02X' % ord(x) for x in
                                                              decompressed_plain[0][:32])
    if decompressed_plain[0][0:4] == 'PX\x00\x00':
        print '[+] PX signature found: '
    else:
        print '[!] Error. Not a PX file'

    with open('%s_decrypted' % filename, 'wb') as fp:
        fp.write(decompressed_plain[0])

    print '[+] Program finished. Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare_on/11_rabbithole$ ./rabbithole_decrypt_regval.py MonitornewWarningmap_export.bin 
[+] Rabbithole decrypt registry values script started.
[+] Decrypting RSA public key using serpent key: 90982d21090ef347
[+] RSA key size: 1024 bits
[+] RSA public modulus : C3DA263DF172293373B0431EE00BAC4C3DB723BEE2D9CCC0A7EF8D0368C33C577DF7E64F09503437E9178533C9F3B4D4EEBD7FE1075E2E553939D43C25EB8A89A5FD7AD5F8A52C20713AE878CF2B1F322ACFE8B7C55DAD60B352061419FA713C903D9EFC36BAF95185880D03EC165A51186CF1C323BC58C40B85FCBC7FA162AD
[+] RSA public exponent: 10001
[+] RSA cipher: 2497081CDB954D07FA0B48D33532A15B36FF8FF98A990C12A6E3ECB7EC7E30CF71C92E97CA6C4B33ECC8C8E3EAAD53511CBABAF885F8360DE7E7F6F7FF419D29230709EC7D8A5BFBEC1A691DFFB9CC3245AD69D5C895DB9BF2DC23AD3191783EBE973DFCD37CFFBD2D43B2E3703744E0F88EAE88DD9D3A22BBA37668588A4E92
[+] Decrypting RSA cipher using public key (c^e = m mod n) ...
[+] RSA plaintext: 1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00CC56916163795999F4099E9D92D9FFB5FB44D53D3C930F5972EAC371C8072CCC820100001F2400E0
[+] Registry data MD5: 43 43 35 36 39 31 36 31 36 33 37 39 35 39 39 39 46 34 30 39 39 45 39 44 39 32 44 39 46 46 42 35
[+] Registry data serpent key: FB 44 D5 3D 3C 93 0F 59 72 EA C3 71 C8 07 2C CC
[+] Registry data size: 0x182
[+] Random salt: E0 00 24 1F
[+] Decrypting registry data: 06 36 3E 35 A4 CB 87 AB 6D 0F 9B 3D 19 8D A6 D6 C4 E3 68 4F 52 79 4B 05 D0 C3 8A A8 AA B9 55 41 ...
[+] Plain registry value: 84 A7 2D 46 14 00 00 00 6E 01 00 00 00 00 00 00 DC 02 00 00 17 E1 A0 02 03 06 5A 84 92 B8 01 11 ...
[+] Registry value MD5 hash: CC56916163795999F4099E9D92D9FFB5
[+] MD5 hashes match! Decryption was successful.
[+] Decompressing plaintext ...
[!] Warning. PpX signature not found. Continuing anyways...
[+] Deflating: 366 -> 732 bytes ...
[+] Decompressed registry data: 17 00 00 00 00 00 00 00 5A 84 92 B8 01 00 00 00 28 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ...
[!] Error. Not a PX file
[+] Program finished. Bye bye :)
ispo@ispo-glaptop:~/ctf/flare_on/11_rabbithole$ hexdump -C MonitornewWarningmap_export.bin_decrypted
00000000  17 00 00 00 00 00 00 00  5a 84 92 b8 01 00 00 00  |........Z.......|
00000010  28 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |(...............|
....
00000220  c0 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000230  68 74 74 70 73 3a 2f 2f  67 6c 6f 72 79 2e 74 6f  |https://glory.to|
00000240  2e 6b 61 7a 6f 68 69 6e  69 61 00 30 00 63 75 72  |.kazohinia.0.cur|
00000250  6c 6d 79 69 70 2e 6e 65  74 00 31 32 00 47 53 50  |lmyip.net.12.GSP|
00000260  79 72 76 33 43 37 39 5a  62 52 30 6b 31 00 33 30  |yrv3C79ZbR0k1.30|
00000270  30 00 33 30 30 00 33 30  30 00 33 30 30 00 33 30  |0.300.300.300.30|
00000280  30 00 31 30 30 30 00 36  30 00 36 30 00 31 30 00  |0.1000.60.60.10.|
00000290  30 00 30 00 31 00 6e 6f  2d 63 61 63 68 65 2c 20  |0.0.1.no-cache, |
000002a0  6e 6f 2d 73 74 6f 72 65  2c 20 6d 75 73 74 2d 72  |no-store, must-r|
000002b0  65 76 61 6c 69 64 61 74  65 00 33 30 30 30 30 30  |evalidate.300000|
000002c0  00 33 30 2c 20 38 2c 20  6e 6f 74 69 70 64 61 00  |.30, 8, notipda.|
000002d0  34 38 30 00 32 34 30 00  32 34 30 00              |480.240.240.|
000002dc
'''
# --------------------------------------------------------------------------------------------------
