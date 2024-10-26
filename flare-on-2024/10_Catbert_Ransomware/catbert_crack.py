#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 10 - Catbert Ransomware
# ----------------------------------------------------------------------------------------
import struct
import z3
from Crypto.Cipher import ARC4


# Helper lambdas for rotation.
rol8 = lambda a, b: ((a << b) | (a >> (8 - b))) & 0xFF
ror8 = lambda a, b: ((a >> b) | (a << (8 - b))) & 0xFF

rol32 = lambda a, b: ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF
ror32 = lambda a, b: ((a >> b) | (a << (32 - b))) & 0xFFFFFFFF

# ----------------------------------------------------------------------------------------
def get_encr_img(filename):
    """Extracts the encrypted part of an image."""
    data = open(filename, 'rb').read()
    assert data[0:4] == b'C4TB'

    print(f'[+] Loading image `{filename}` of {len(data)} bytes')

    encr_img_len = struct.unpack('<L', data[4:8])[0]
    print(f'[+] Encrypted image (0x{encr_img_len:X} bytes):')

    encr_img = bytearray(data[0x10:0x10 + encr_img_len])
    print('[+]  ', ' '.join(f'{b:02X}' for i, b in enumerate(encr_img[:16])),
          ' ... ', ' '.join(f'{b:02X}' for i, b in enumerate(encr_img[-16:])))

    return encr_img


# ----------------------------------------------------------------------------------------
def decrypt_img(filename, rc4_key):
    """Decrypts an image `filename` using a decryption key `rc4_key`."""
    encr_img = get_encr_img(filename)
    rc4_cipher = ARC4.new(rc4_key)
    plaintext = rc4_cipher.decrypt(encr_img)
    print(f'[+] Decrypting {filename} with key {rc4_key} ...')
    print(f'[+]    {plaintext[:32]!r}')

    open(filename.replace('.c4tb', ''), 'wb').write(plaintext)


# ----------------------------------------------------------------------------------------
def crack_catmeme1():
    """Cracks the password from the VM in image #1."""
    print('[+] Cracking key from VM #1 .....')

    key = bytearray(b'Da4ubicle1ifeb0b') # Original password
    print(f"[+] Initial key     : {key.decode('utf8')}")

    # 0385 | 01AB: (#24) ROL8         ; rol8(0x34, 0x4)           | S:[16h, 43h]
    key[2] = rol8(key[2], 4)  # Replace '4' with 'C' ~> 'DaCubicle1ifeb0b'
    print(f"[+] 1st Modification: {key.decode('utf8')}")

    # 1075 | 01C2: (#25) ROR8         ; ror8(0x31, 0x2)           | S:[16h, 4Ch]
    key[9] = ror8(key[9], 2)  # Replace '1' with 'L' ~> 'DaCubicleLifeb0b'
    print(f"[+] 2nd Modification: {key.decode('utf8')}")

    # 1474 | 01D9: (#24) ROL8         ; rol8(0x62, 0x7)           | S:[16h, 31h]
    # 1679 | 01F0: (#24) ROL8         ; rol8(0x62, 0x7)           | S:[16h, 31h]
    key[13] = rol8(key[13], 7)  # Replace 'b' with '1' ~> 'DaCubicleLife10b'
    key[15] = rol8(key[15], 7)  # Replace 'b' with '1' ~> 'DaCubicleLife101'

    print(f"[+] 3rd Modification: {key.decode('utf8')}")

    return bytes(key)


# ----------------------------------------------------------------------------------------
def crack_catmeme2():
    """Cracks the password from the VM in image #2."""
    print('[+] Cracking key from VM #2 .....')

    key = []
    xors = [
        0x59, 0xa0, 0x4d, 0x6a,
        0x23, 0xde, 0xc0, 0x24,
        0xe2, 0x64, 0xb1, 0x59,
        0x7,  0x72, 0x5c, 0x7f
    ]

    lcg = 0x1337
    for i in range(16):        
        lcg = (0x343FD * lcg + 0x269EC3) % 0x80000000

        key += [xors[i] ^ (lcg >> ((i % 4)*8)) & 0xFF]

        print(f'[+] Found key[{i:2d}] = {chr(key[i])} ~> {bytes(key)}')

    return bytes(key)


# ----------------------------------------------------------------------------------------
def crack_catmeme3():
    """Cracks the password from the VM in image #3."""
    print('[+] Cracking key from VM #3 .....')

    def part1():
        smt = z3.Solver()
        key = [z3.BitVec('key_%d' % i, 64) for i in range(4)]

        # Limit each character to printable ASCII.
        for c in key:
            smt.add(z3.And(c >= 0x20, c <= 0x7e))


        # -------------------------------------------------------------------------
        # Key is checked into three parts. 
        # Part 1:
        # -------------------------------------------------------------------------
        # a = 0x1505*33 + key[0] 
        # b = a*33 + key[1] 
        # c = b*33 + key[2] 
        # d = c*33 + key[3] 
        # d &= 0xffffffff
        # // d must be: 0x7C8DF4CB
        smt.add(
            ((
                (
                    (
                        (0x1505 * 33 + key[0]) * 33 + key[1]
                    ) * 33 + key[2]
                ) * 33
            ) + key[3]) & 0xFFFFFFFF 
            == 0x7C8DF4CB)

        while smt.check() == z3.sat:
            mdl = smt.model()
            key_first_4 = ''
            for i in range(4):
                c = mdl.evaluate(key[i]).as_long()
                key_first_4 += chr(c)
            
            print(f'[+] Key found: {key_first_4}')
            
            # We have many solutions. Find them all.
            smt.add(z3.Or([p != mdl.evaluate(p).as_long() for p in key]))
        else:
            print('All solutions found')
        
        return b'VerY'

    # Correct solution: 'VerY' (the only word which makes sense),
    k1 = part1()
    

    # -------------------------------------------------------------------------
    # Part 2: Only 4 ASCII characters. Just bruteforce.
    #
    #   a = ror32(key[4], 0xD) + key[5]
    #   b = ror32(a, 0xD) + key[6]
    #   c = ror32(b, 0xD) + key[7]
    #   d = ror32(ror32(ror32(key[4], 0xD) + key[5], 0xD) + key[6], 0xD) + key[7]
    #   // d must be 0x8B681D82
    # -------------------------------------------------------------------------
    def part2():
        for i in range(0x20, 0x7f):
            print(f'[+] Trying i = 0x{i:x} ...')
            for j in range(0x20, 0x7f):
                for k in range(0x20, 0x7f):
                    for l in range(0x20, 0x7f):
                        d = ror32(ror32(ror32(i, 0xD) + j, 0xD) + k, 0xD) + l
                        if d == 0x8B681D82:
                            key = bytes([i, j, k, l])
                            print(f'[+] Key found: {key}')

                            return key
    
    # Correct solution: 'DumB'
    k2 = part2()
    

    # -------------------------------------------------------------------------
    # Part 3: It does 2 checks. Use z3 again.
    # 
    # 1st check:
    #   v11 = 1
    #   v12 = 0
    #   for i in range(8, 16):
    #       v11 = v11 + key[i]
    #       v12 = (v12 + v11) % 0xfff1
    #   print(i, hex(v11), hex(v12))
    #
    #   a = (v12 << 16 | v11)
    #   // a must be 0xF910374
    #
    # 2nd check (Fowler-Noll-Vo hash):
    #   c = 0x1000193
    #   e = 0x811c9dc5
    #   for k in key:
    #       e = (e * c) % 0x100000000
    #       e ^= k
    #   // e must be 0x31F009D2
    # -------------------------------------------------------------------------
    def part3(k1, k2):
        smt = z3.Solver()
        key = [z3.BitVec('key_%d' % i, 64) for i in range(16)]

        # We already know the first 8 characters.
        for i, c in enumerate(b'VerYDumB'): # or `k1+k2 `
            smt.add(key[i] == c)

        # Limit each character to printable ASCII.
        for c in key[8:]:
            # smt.add(z3.And(c >= 0x20, c <= 0x7e))
            # Further limit down password to [0-9A-Za-z]
            smt.add(z3.Or(z3.And(c >= 0x30, c <= 0x39),
                          z3.And(c >= 0x41, c <= 0x5a),
                          z3.And(c >= 0x61, c <= 0x7a)))

        # Break it down into multiple equations to make things faster.
        v11 = [z3.BitVec('v11_%d' % i, 64) for i in range(9)]
        v12 = [z3.BitVec('v12_%d' % i, 64) for i in range(9)]
        
        smt.add(v11[0] == 1)
        smt.add(v12[0] == 0)

        for i in range(1, 9):
            smt.add(v11[i] == v11[i-1] + key[8+i-1])    
            smt.add(v12[i] == (v12[i-1] + v11[i])) # % 0xfff1) # We don't need this.
            smt.add(v12[i] < 0xFFFF)
            smt.add(v11[i] < 0xFFFF)

        smt.add(v12[8] == 0xF91)
        smt.add(v11[8] == 0x374)
        
        ee = [z3.BitVec('ee_%d' % i, 64) for i in range(17)]
        smt.add(ee[0] == 0x811c9dc5)

        # This is slow:
        #   e = 0x811c9dc5
        #   for k in key:
        #       e = (e * 0x1000193) & 0xFFFFFFFF
        #       e ^= k
        #   smt.add(e == 0x31F009D2)   
        for i in range(1, 17):
            smt.add(ee[i] == ((ee[i-1] * 0x1000193) & 0xFFFFFFFF) ^ key[i-1])
            smt.add(ee[i] <= 0xFFFFFFFF)

        smt.add(ee[16] == 0x31F009D2)

        print(f'[+] Checking satisfiability. It will take a while .....')
        if smt.check() == z3.sat:
            mdl = smt.model()
            key_last_8 = ''
            for i in range(16):
                c = mdl.evaluate(key[i]).as_long()
                key_last_8 += chr(c)
            
            print(f'[+] Key found: {key_last_8}')
            return key_last_8.encode('utf8')
        else:
            raise Exception('No solution found :(')

    final_key = part3(k1, k2)
    print(f'[+] Final decryption key: {final_key}')

    return final_key


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Catbert Ransomware crack started.')

    key1 = crack_catmeme1()     # b'DaCubicleLife101'
    decrypt_img('disk_files/catmeme1.jpg.c4tb', key1)

    key2 = crack_catmeme2()     # b'G3tDaJ0bD0neM4te'
    decrypt_img('disk_files/catmeme2.jpg.c4tb', key2)

    key3 = crack_catmeme3()     # b'VerYDumBpassword'
    decrypt_img('disk_files/catmeme3.jpg.c4tb', key3)

    print('[+] Decrypting final EFI file ...')

    data = open('disk_files/DilbootApp.efi.enc', 'rb').read()
    rc4_key = b'BureaucracY4Life'
    rc4_cipher = ARC4.new(rc4_key)
    plaintext = rc4_cipher.decrypt(data)
    print(plaintext[:32])
    open('disk_files/DilbootApp.efi', 'wb').write(plaintext)

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[00:08:21]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/10_Catbert_Ransomware]
└──> time ./catbert_crack.py 
[+] Catbert Ransomware crack started.
[+] Cracking key from VM #1 .....
[+] Initial key     : Da4ubicle1ifeb0b
[+] 1st Modification: DaCubicle1ifeb0b
[+] 2nd Modification: DaCubicleLifeb0b
[+] 3rd Modification: DaCubicleLife101
[+] Loading image `disk_files/catmeme1.jpg.c4tb` of 71625 bytes
[+] Encrypted image (0x11554 bytes):
[+]   8C F7 B3 F3 2A C7 A5 44 72 4E 75 A6 38 D4 D9 EF  ...  95 DA CB 30 33 6B 03 31 18 AE 41 A0 A9 45 88 18
[+] Decrypting disk_files/catmeme1.jpg.c4tb with key b'DaCubicleLife101' ...
[+]    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\xc0\x00\xc0\x00\x00\xff\xe1\x00"Exif\x00\x00MM'
[+] Cracking key from VM #2 .....
[+] Found key[ 0] = G ~> b'G'
[+] Found key[ 1] = 3 ~> b'G3'
[+] Found key[ 2] = t ~> b'G3t'
[+] Found key[ 3] = D ~> b'G3tD'
[+] Found key[ 4] = a ~> b'G3tDa'
[+] Found key[ 5] = J ~> b'G3tDaJ'
[+] Found key[ 6] = 0 ~> b'G3tDaJ0'
[+] Found key[ 7] = b ~> b'G3tDaJ0b'
[+] Found key[ 8] = D ~> b'G3tDaJ0bD'
[+] Found key[ 9] = 0 ~> b'G3tDaJ0bD0'
[+] Found key[10] = n ~> b'G3tDaJ0bD0n'
[+] Found key[11] = e ~> b'G3tDaJ0bD0ne'
[+] Found key[12] = M ~> b'G3tDaJ0bD0neM'
[+] Found key[13] = 4 ~> b'G3tDaJ0bD0neM4'
[+] Found key[14] = t ~> b'G3tDaJ0bD0neM4t'
[+] Found key[15] = e ~> b'G3tDaJ0bD0neM4te'
[+] Loading image `disk_files/catmeme2.jpg.c4tb` of 49312 bytes
[+] Encrypted image (0xBDF3 bytes):
[+]   2D 1E FF 7D C0 67 63 0C 10 C6 A7 2F DE F3 7B 24  ...  FA D5 70 BF 30 9C 78 22 64 AF C0 09 16 1C 0C 00
[+] Decrypting disk_files/catmeme2.jpg.c4tb with key b'G3tDaJ0bD0neM4te' ...
[+]    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\xc0\x00\xc0\x00\x00\xff\xe1\x00"Exif\x00\x00MM'
[+] Cracking key from VM #3 .....
[+] Key found: X%18
[+] Key found: WEPz
[+] Key found: WER8
[+] Key found: WDqz
[+] Key found: WDrY
[+] Key found: WF18
[+] Key found: WEQY
[+] Key found: WF/z
[+] Key found: WF0Y
[+] Key found: WDs8
[+] Key found: Vg/z
[+] Key found: VfPz
[+] Key found: X$Pz
[+] Key found: X$QY
[+] Key found: X$R8
[+] Key found: X%0Y
[+] Key found: X%/z
[+] Key found: X#qz
[+] Key found: X#rY
[+] Key found: X#s8
[+] Key found: Vg0Y
[+] Key found: Vg18
[+] Key found: Veqz
[+] Key found: Ves8
[+] Key found: VerY
[+] Key found: VfR8
[+] Key found: VfQY
All solutions found
[+] Trying i = 0x20 ...
[+] Trying i = 0x21 ...
[+] Trying i = 0x22 ...
[+] Trying i = 0x23 ...
[+] Trying i = 0x24 ...
[+] Trying i = 0x25 ...
[+] Trying i = 0x26 ...
[+] Trying i = 0x27 ...
[+] Trying i = 0x28 ...
[+] Trying i = 0x29 ...
[+] Trying i = 0x2a ...
[+] Trying i = 0x2b ...
[+] Trying i = 0x2c ...
[+] Trying i = 0x2d ...
[+] Trying i = 0x2e ...
[+] Trying i = 0x2f ...
[+] Trying i = 0x30 ...
[+] Trying i = 0x31 ...
[+] Trying i = 0x32 ...
[+] Trying i = 0x33 ...
[+] Trying i = 0x34 ...
[+] Trying i = 0x35 ...
[+] Trying i = 0x36 ...
[+] Trying i = 0x37 ...
[+] Trying i = 0x38 ...
[+] Trying i = 0x39 ...
[+] Trying i = 0x3a ...
[+] Trying i = 0x3b ...
[+] Trying i = 0x3c ...
[+] Trying i = 0x3d ...
[+] Trying i = 0x3e ...
[+] Trying i = 0x3f ...
[+] Trying i = 0x40 ...
[+] Trying i = 0x41 ...
[+] Trying i = 0x42 ...
[+] Trying i = 0x43 ...
[+] Trying i = 0x44 ...
[+] Key found: b'DumB'
[+] Checking satisfiability. It will take a while .....
[+] Key found: password
[+] Final decryption key: b'VerYDumBpassword'
[+] Loading image `disk_files/catmeme3.jpg.c4tb` of 97946 bytes
[+] Encrypted image (0x17AB3 bytes):
[+]   F4 0C 72 0B AC 40 16 2C A8 F0 61 A8 E5 6F D2 F8  ...  58 7A 9F 3F 61 E3 C5 41 38 F1 37 59 62 3B 6A C4
[+] Decrypting disk_files/catmeme3.jpg.c4tb with key b'VerYDumBpassword' ...
[+]    b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\xc0\x00\xc0\x00\x00\xff\xe1\x00"Exif\x00\x00MM'
[+] Decrypting final EFI file ...
b'MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[+] Program finished successfully. Bye bye :)

real    26m15.542s
user    26m14.944s
sys 0m0.204s
"""
# ----------------------------------------------------------------------------------------
