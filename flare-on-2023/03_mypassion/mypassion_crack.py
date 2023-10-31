#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 03 - My Passion
# ----------------------------------------------------------------------------------------
import datetime
import capstone
import zlib


# ----------------------------------------------------------------------------------------
def double_rc4_decrypt(key, ciphertext):
    S = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (S[i] + j + (key[i % len(key)])) % 256;
        S[i], S[j] = S[j], S[i]

    for i in range(256):
        j = (S[i] + j + (key[i % len(key)])) % 256;
        S[i], S[j] = S[j], S[i]

    i, j = 0, 0
    plaintext = []
    for c in range(len(ciphertext)):
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        S[i], S[j] = S[j], S[i]
        k = S[(S[j] + S[i]) % 256]
        plaintext.append(ciphertext[c] ^ k)

    ciphertext = plaintext[::]
    plaintext  = []

    i, j = 0, 0
    for c in range(len(ciphertext)):
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        S[i], S[j] = S[j], S[i]
        k = S[(S[j] + S[i]) % 256]
        plaintext.append(ciphertext[c] ^ k)


    return plaintext


# ----------------------------------------------------------------------------------------
def crack_stage_1_hidden_func():
    """Cracks the first part of the input in `hidden_func`."""
    cipher = [0x16, 0x17, 0x3B, 0x17, 0x56]
    ten = 'ten'
    for i in range(5):
        cipher[i] ^= ord(ten[i % 3])

    return ''.join(chr(c) for c in cipher)  # brUc3


# ----------------------------------------------------------------------------------------
def crack_stage_5_valid_shellcode():
    """Brute-forces a single byte and dumps all disassembly listings."""

    # Inside GetModuleHandle for KERNEL32.DLL
    #   Offsets: [0, 24, 25, 54, 29]
    shellcode_1 = [
      0x00, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 
      0x8B, 0x48, 0x18, 0x48, 0x8B, 0x51, 0x20, 0x48, 0x83, 0xEA, 
      0x10, 0x48, 0x8B, 0x42, 0x4C, 0x66, 0x83, 0x78, 0x10, 0x54, 
      0x75, 0x2E, 0x66, 0x83, 0x78, 0x0E, 0x32, 0x75, 0x27, 0x66, 
      0x83, 0x78, 0x0C, 0x33, 0x75, 0x20, 0x66, 0x83, 0x78, 0x0A, 
      0x4C, 0x74, 0x07, 0x66, 0x31, 0x78, 0x08, 0x6C, 0x75, 0x12, 
      0x0F, 0xB7, 0x40, 0x08, 0xB9, 0xDF, 0xFF, 0x00, 0x00, 0x66, 
      0x83, 0xE8, 0x45, 0x66, 0x85, 0xC1, 0x74, 0x12, 0x48, 0x8B, 
      0x45, 0x10, 0x48, 0x83, 0xEA, 0x10, 0x48, 0x83, 0x7A, 0x30, 
      0x00, 0x75, 0xB8, 0x33, 0xC0, 0xC3, 0x48, 0x8B, 0x42, 0x45, 
      0xC3
    ]

    # Inside GetProcAddress.
    shellcode_2_chunk_1 = [
        0x00, 0x03, 0xC8, 0x0F, 0xB7, 0x14, 0x79,
        0x69, 0x8B, 0x49, 0x1C, 0x49, 0x03, 0xC8, 0x8B, 0x04, 0x91, 0x49, 0x03, 
        0xC0, 0xEB, 0xDB,
    ]

    shellcode_2_chunk_2 = [
        0x00, 0xEB, 0x85, 0xD2, 0x74, 0x15, 0xFF, 0xC1, 0x41, 0x3B, 0x49, 0x18,
        0x72, 0xCE, 0x33, 0xC0
    ]

    shellcode_2_chunk_3 = [
        0x30, 0x8B, 0x49, 0x1C, 0x49, 0x03, 0xC8, 0x8B, 0x04, 0x91, 0x49, 0x03,
        0xC0
    ]

    def try_disasm(shellcode, base=0x15B0000):
        """Tries to disassemble a shellcode."""    
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        asm = []
        for insn in md.disasm(bytes(shellcode), base):
            asm.append(f'{insn.address:08X} {insn.mnemonic} {insn.op_str}')
       
        return '\n' + ';\n'.join(asm[:7])

    for i in range(0x20, 0x7f):      
        # # [0, 24, 25, 54, 29]  
        # shellcode_1[0x36] = i
        # disasm = try_disasm(shellcode_1[0x35:], 0x15b0035)

        shellcode_2_chunk_2[0] = i
        disasm = try_disasm(shellcode_2_chunk_2)

        if 'insb' in disasm or 'outsb' in disasm:
            pass  # Ignore in/out instructions

        print('~>', repr(chr(i)), hex(i), disasm)


# ----------------------------------------------------------------------------------------
def crack_stage_6_fwd(a):
    """Brute-force forward algorithm for stage 6."""
    arr = 'AZBQCEDTEXFHGOHLIMJFKKLDMVNNOUPBQWRYSGTIUPVAWCXJYRZS'
    for i in range(0x1A):
       if a == arr[1 + i*2]:
           sol = arr[2*i]
           break
    return sol


# ----------------------------------------------------------------------------------------
def crack_stage_8_custom_alg(v24):   
    """Computes the flag from a password (`v24`)."""
    DWORD = lambda b: b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

    A = 0xC6EF3720
    B = 0xC6EF3720
    C = 0xAEFCF63E
    D = 0xD5C5DD5A
    E = 0xC6EF3720
    
    while B != 0:
        v16 = (C ^ B) + DWORD(v24[4 * ((E >> 11) & 3):]) + ((16 * C) ^ (C >> 5))
        v16 &= 0xFFFFFFFF
        B += 0x61C88647
        D -= v16
        D &= 0xFFFFFFFF
        E = B
        C -= (D ^ B) + DWORD(v24[4 * (B & 3):]) + ((16 * D) ^ (D >> 5))

        A &= 0xFFFFFFFF
        B &= 0xFFFFFFFF
        C &= 0xFFFFFFFF
        D &= 0xFFFFFFFF
        E &= 0xFFFFFFFF

    X = C
    Y = 0xAB30F482
    Z = 0xBE54376B
    W = D
    U = 0xC6EF3720
    while A != 0:
        v20 = (Y ^ A) + DWORD(v24[4 * ((U >> 11) & 3):]) + ((16 * Y) ^ (Y >> 5))
        v20 &= 0xFFFFFFFF
        A += 0x61C88647
        Z -= v20
        Z &= 0xFFFFFFFF
        U = A
        Y -= (Z ^ A) + DWORD(v24[4 * (A & 3):]) + ((16 * Z) ^ (Z >> 5))

        X &= 0xFFFFFFFF
        Y &= 0xFFFFFFFF
        Z &= 0xFFFFFFFF
        W &= 0xFFFFFFFF
        U &= 0xFFFFFFFF
        A &= 0xFFFFFFFF

    return X, W & 0xFFFFFF, Y, Z,


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] My passion crack started.')

    '''
    # Finding all solutions for: 4*inp[1] + inp[2] = 0x127
    pairz = [f'{chr(i)}{chr(j)}'
                for i in range(0x21, 0x7f)
                    for j in range(0x21, 0x7f)   
                        if 4*i + j == 0x127]
    print(pairz)
    
    ['+{', ',w', '-s', '.o', '/k', '0g', '1c', '2_',
     '3[', '4W', '5S', '6O', '7K', '8G', '9C', ':?',
     ';;', '<7', '=3', '>/', '?+', "@'", 'A#']
    '''
    inp = '00g..R@'
    inp += crack_stage_1_hidden_func()  # brUc3
    inp += 'E'
    print(f'[+] Input after stage #1: {inp}')

    inp += '/1337pr.ost'
    print(f'[+] Input after stage #2: {inp}')

    inp += '/10abcd'
    print(f'[+] Input after stage #3: {inp}')

    wDay = datetime.datetime.today().day
    print(f"[+] Today's day of the month: {wDay}")
    inp += f'/{chr(31 + wDay)}pizza'
    print(f'[+] Input after stage #4: {inp}')

    # crack_stage_5_valid_shellcode().decode('utf-8'))
    inp += '/AMu$E`0R.kAZe'
    print(f'[+] Input after stage #5: {inp}')

    ff = 'RUECKWAERTSINGENIEURWESEN'
    inp += '/'
    for j in range(len(ff)):
        for n in [chr(0x41 + i) for i in range(26)]:
            if crack_stage_6_fwd(n) == ff[j]:
                inp += n

    print(f'[+] Input after stage #6: {inp}')
    
    inp += '/ob5cUr3'
    print(f'[+] Input after stage #7: {inp}')

    inp += '/fin/'
    print(f'[+] Input after stage #8: {inp}')


    print('[+] EXTRA TASKS ...')
    print('[+] Decrypting html file ...')
    with open('pr.ost', 'rb') as fp:
        content = fp.read()    
        content = content[0x50:len(content)-1]
    
    wDay = 4
    content = [(c - 31 - wDay) & 0xFF for c in content]
    orig = content[::]
    print(f"[+] First 20 bytes of pr.ost: {' '.join(f'{c:02X}' for c in content[:20])}")
    
    # We don't know which day `pr.ost` created, so we bruteforce the day.
    for wDay in range(1, 31+1):
        content = orig[::]
        content = [(c - wDay) & 0xFF for c in content]
        print(f"[+] Trying day #{wDay} and content: {' '.join(f'{c:02X}' for c in content[:20])}")

        plain = double_rc4_decrypt(b'REVERSEENGINEER', content)
        chksum = zlib.crc32(bytes(plain))
        print(f"[+] Decrypted result (CRC:{chksum:08X}h): {repr(''.join(chr(p) for p in plain[:48]))}")
        if chksum == 0x92A7A888:
            print('[+] Solution FOUND!')
            print('[+] Writing data to flag.html')
            with open('flag.html', 'wb') as fp:
                fp.write(bytes(plain))
            break

    print('[+] Building the 1st part of the flag ...')

    flag = ['?']*15
    flag[0] = inp[7]
    flag[1] = inp[0];
    flag[2] = inp[19]
    flag[3] = 'fin'[2]
    flag[4] = '_'
    flag[5] = inp[23]
    flag[6] = 'AMu$E`0R.kAZe'[6]
    flag[7] = chr(95)
    flag[8] = 'ob5cUr3'[2]
    flag[9] = chr(116)
    flag[10] = 'ob5cUr3'[5]
    flag[11] = 'AMu$E`0R.kAZe'[2];
    flag[12] = 'YPXEKCZXYIGMNOXNMXPYCXGXN'[5].lower() # +32
    flag[13] = inp[17]
    flag[14] = '_'
    flag = ''.join(flag)

    print(f'[+] Flag part 1: {flag}')
    
    pwd = 'oXiG3NisAMAZInG\0'.encode('utf-8')

    print('[+] Building the 2nd part of the flag ...')
    print(f'[+] Decryption password: {pwd}')

    a, b, c, d = crack_stage_8_custom_alg(pwd)
    a_ = a.to_bytes(4, byteorder = 'little')
    b_ = b.to_bytes(4, byteorder = 'little')
    c_ = c.to_bytes(4, byteorder = 'little')
    d_ = d.to_bytes(4, byteorder = 'little')

    flag += a_.decode('utf-8')
    flag += b_.decode('utf-8')[:3]
    flag += c_.decode('utf-8')
    flag += d_.decode('utf-8')[:3]

    print(f'[+] Final flag: {flag}com')

    if zlib.crc32(flag.encode('utf-8')) == 0x59B1D2F1:
        print('[+] Flag is correct.')
    else:
        print('[!] Error. Incorrect flag.')

# ----------------------------------------------------------------------------------------
r"""
[+] My passion crack started.
[+] Input after stage #1: 00g..R@brUc3E
[+] Input after stage #2: 00g..R@brUc3E/1337pr.ost
[+] Input after stage #3: 00g..R@brUc3E/1337pr.ost/10abcd
[+] Today's day of the month: 31
[+] Input after stage #4: 00g..R@brUc3E/1337pr.ost/10abcd/>pizza
[+] Input after stage #5: 00g..R@brUc3E/1337pr.ost/10abcd/>pizza/AMu$E`0R.kAZe
[+] Input after stage #6: 00g..R@brUc3E/1337pr.ost/10abcd/>pizza/AMu$E`0R.kAZe/YPXEKCZXYIGMNOXNMXPYCXGXN
[+] Input after stage #7: 00g..R@brUc3E/1337pr.ost/10abcd/>pizza/AMu$E`0R.kAZe/YPXEKCZXYIGMNOXNMXPYCXGXN/ob5cUr3
[+] Input after stage #8: 00g..R@brUc3E/1337pr.ost/10abcd/>pizza/AMu$E`0R.kAZe/YPXEKCZXYIGMNOXNMXPYCXGXN/ob5cUr3/fin/
[+] EXTRA TASKS ...
[+] Decrypting html file ...
[+] First 20 bytes of pr.ost: 32 D2 60 5C 18 A4 EF 78 71 EC BD B0 80 63 FF E2 00 61 7C 96
[+] Trying day #1 and content: 31 D1 5F 5B 17 A3 EE 77 70 EB BC AF 7F 62 FE E1 FF 60 7B 95
[+] Decrypted result (CRC:FDB831B0h): '\x1aG^U©~czc\x1avNwF$\x1anOn\x82O@\x08J\x87XC\x17I\x08\x10EEGÆ\x05nCR\x12[$&IJS\x86\x7f'
[+] Trying day #2 and content: 30 D0 5E 5A 16 A2 ED 76 6F EA BB AE 7E 61 FD E0 FE 5F 7A 94
[+] Decrypted result (CRC:2D18396Fh): "\x1bF_T¨\x7f`{|\x1bqOvE'\x1bopo\x83LA\x0fK\x86Y\\\x14vw\x17DDFÅ\x04m@S\x13Z''JMP\x87|"
[+] Trying day #3 and content: 2F CF 5D 59 15 A1 EC 75 6E E9 BA AD 7D 60 FC DF FD 5E 79 93
[+] Decrypted result (CRC:8BFBB05Bh): '\x04Y\\W«|ax}\x18pLuD&$lql\x84MF\x0et\x89Z]\x15wv\x16KGEÄ\x07lA\\\x14]&$KLQ\x84}'
[+] Trying day #4 and content: 2E CE 5C 58 14 A0 EB 74 6D E8 B9 AC 7C 5F FB DE FC 5D 78 92
[+] Decrypted result (CRC:66C580EFh): '\x05X]Vª}fy~\x19sMt{!%mrm\x85JG\ru\x88[^\x1atu\x15JFDË\x06cF]\x15\\)%DOn\x85z'
[+] Trying day #5 and content: 2D CD 5B 57 13 9F EA 73 6C E7 B8 AB 7B 5E FA DD FB 5C 77 91
[+] Decrypted result (CRC:87A4349Eh): '\x06[ZY\xadBg~\x7f\x16rJsz &jsb\x86KD\x0cv\x8b\\_\x1but\x14IyCÊ\x19bG^\x16_(*ENoz{'
[+] Trying day #6 and content: 2C CC 5A 56 12 9E E9 72 6B E6 B7 AA 7A 5D F9 DC FA 5B 76 90
[+] Decrypted result (CRC:D30DA89Bh): "\x07Z[X¬Cd\x7fx\x17}Kry#'ktc\x87HEsw\x8a]X\x18rs\x1bHxBÉ\x18aD_\x17^++FAl{x"
[+] Trying day #7 and content: 2B CB 59 55 11 9D E8 71 6A E5 B6 A9 79 5C F8 DB F9 5A 75 8F
[+] Decrypted result (CRC:FBB5036Ch): '\x00]X[¯@e|y\x14|Hqx" hu`\x98IJrp\x8d^Y\x19sr\x1aO{AÈ\x1b`EX\x18Q*(G@mxy'
[+] Trying day #8 and content: 2A CA 58 54 10 9C E7 70 69 E4 B5 A8 78 5B F7 DA F8 59 74 8E
[+] Decrypted result (CRC:268DE540h): '\x01\\YZ®Aj}z\x15\x7fIp\x7f-!iva\x99vKqq\x8c_Z\x1epq\x19Nz@Ï\x1agzY\x19P-)@Cjyv'
[+] Trying day #9 and content: 29 C9 57 53 0F 9B E6 6F 68 E3 B4 A7 77 5A F6 D9 F7 58 73 8D
[+] Decrypted result (CRC:FA28BF79h): '\x02_V]Hi, I see that you're currently hold 2 ida pro licenses, could you please release the one so I can open IDA pro? thanks in advance :)±Fkb{\x12~F\x7f~,"fwf\x9awHpr\x8f`[\x1fqp\x18M}\x7fÎ\x1df{Z\x1aS,.ABk~w'
[+] Trying day #10 and content: 28 C8 56 52 0E 9A E5 6E 67 E2 B3 A6 76 59 F5 D8 F6 57 72 8C
[+] Decrypted result (CRC:CBFC1059h): '\x03^W\\°Ghct\x13yG~}/#gxg\x9btIws\x8eaT\x1c~\x7f\x1fL|~Í\x1cex[\x1bR//BEh\x7ft'
[+] Trying day #11 and content: 27 C7 55 51 0D 99 E4 6D 66 E1 B2 A5 75 58 F4 D7 F5 56 71 8B
[+] Decrypted result (CRC:86691CADh): '\x0cQT_³Di`u\x10xD}|.,dyd\x9cuNv|qbU\x1d\x7f~\x1es\x7f}Ì\x1fdyd\x1cU.,CDi|u'
[+] Trying day #12 and content: 26 C6 54 50 0C 98 E3 6C 65 E0 B1 A4 74 57 F3 D6 F4 55 70 8A
[+] Decrypted result (CRC:922F17DDh): '\rPU^²Enav\x11{E|s)-eze\x9drOu}pcV"|}\x1dr~|3\x1e{~e\x1dT1-|Gf}r'
[+] Trying day #13 and content: 25 C5 53 4F 0B 97 E2 6B 64 DF B0 A3 73 56 F2 D5 F3 54 6F 89
[+] Decrypted result (CRC:C886E628h): '\x0eSRAµJofw.zB{r(.b{z\x9esLt~sdW#}|\x1cqq{2\x11z\x7ff\x1eW02}Fgrs'
[+] Trying day #14 and content: 24 C4 52 4E 0A 96 E1 6A 63 DE AF A2 72 55 F1 D4 F2 53 6E 88
[+] Decrypted result (CRC:779272FAh): '\x0fRS@´Klgp/eCzq+/c|{\x9fpM{\x7freP z{#ppz1\x10y|g\x1fV33~ydsp'
[+] Trying day #15 and content: 23 C3 51 4D 09 95 E0 69 62 DD AE A1 71 54 F0 D3 F1 52 6D 87
[+] Decrypted result (CRC:B84A9053h): '\x08UPC·Hmdq,d@yp*(`}x\x90q2zxufQ!{z"wsy0\x13x}``i20\x7fxepq'
[+] Trying day #16 and content: 22 C2 50 4C 08 94 DF 68 61 DC AD A0 70 53 EF D2 F0 51 6C 86
[+] Decrypted result (CRC:278143BCh): '\tTQB¶IRer-gAxw5)a~y\x91~3yytgR&xy!vrx7\x12\x7fraah51x{bqn'
[+] Trying day #17 and content: 21 C1 4F 4B 07 93 DE 67 60 DB AC 9F 6F 52 EE D1 EF 50 6B 85
[+] Decrypted result (CRC:331886CEh): "\nWNE¹NSjs*f~gv4*~\x7f~\x92\x7f0xzwhS'yx uuw6\x15~sbbk46yzcvo"
[+] Trying day #18 and content: 20 C0 4E 4A 06 92 DD 66 5F DA AB 9E 6E 51 ED D0 EE 4F 6A 84
[+] Decrypted result (CRC:EFD1C7EAh): "\x0bVOD¸OPkL+a\x7ffu7+\x7f`\x7f\x93|1\x7f{vil$fg'ttv5\x14}pccj77z}`wl"
[+] Trying day #19 and content: 1F BF 4D 49 05 91 DC 65 5E D9 AA 9D 6D 50 EC CF ED 4E 69 83
[+] Decrypted result (CRC:6A78D6C7h): '4)LG»LQhM(`|et64|a|\x94}6~dyjm%gf&{wu4\x17|qldm64{|atm'
[+] Trying day #20 and content: 1E BE 4C 48 04 90 DB 64 5D D8 A9 9C 6C 4F EB CE EC 4D 68 82
[+] Decrypted result (CRC:EC23A68Eh): '5(MFºMViN)c}dk15}b}\x95z7}exkn*de%zvt;\x16svmel95t\x7f~uj'
[+] Trying day #21 and content: 1D BD 4B 47 03 8F DA 63 5C D7 A8 9B 6B 4E EA CD EB 4C 67 81
[+] Decrypted result (CRC:B1F389D7h): '6+JI½RWnO&bzcj06zcr\x96{4|f{lo+ed$yis:)rwnfo8:u~\x7fjk'
[+] Trying day #22 and content: 1C BC 4A 46 02 8E D9 62 5B D6 A7 9A 6A 4D E9 CC EA 4B 66 80
[+] Decrypted result (CRC:A49A4E74h): "7*KH¼SToH'm{bi37{ds\x97x5cgzmh(bc+xhr9(qtogn;;vq|kh"
[+] Trying day #23 and content: 1B BB 49 45 01 8D D8 61 5A D5 A6 99 69 4C E8 CB E9 4A 65 7F
[+] Decrypted result (CRC:DD506503h): '0-HK¿PUlI$lxah20xephy:b`}ni)cb*\x7fkq8+puhha:8wp}hi'
[+] Trying day #24 and content: 1A BA 48 44 00 8C D7 60 59 D4 A5 98 68 4B E7 CA E8 49 64 7E
[+] Decrypted result (CRC:B3BA9472h): '1,IJ¾QZmJ%oy`o=1yfqif;aa|oj.`a)~jp?*wjii`=9pszif'
[+] Trying day #25 and content: 19 B9 47 43 FF 8B D6 5F 58 D3 A4 97 67 4A E6 C9 E7 48 63 7D
[+] Decrypted result (CRC:F39F729Bh): '2/FMAV[RK"nvon<2vgvjg8`b\x7fpk/a`(}mo>-vkjjc<>qr{ng'
[+] Trying day #26 and content: 18 B8 46 42 FE 8A D5 5E 57 D2 A3 96 66 49 E5 C8 E6 47 62 7C
[+] Decrypted result (CRC:EB36A423h): '3.GL@WXSD#iwnm?3whwkd9gc~qd,no/|ln=,uhkkb??ruxod'
[+] Trying day #27 and content: 17 B7 45 41 FD 89 D4 5D 56 D1 A2 95 65 48 E4 C7 E5 46 61 7B
[+] Decrypted result (CRC:92A7A888h): '<!DOCTYPE html><title>flare-on.com</title><style'
[+] Solution FOUND!
[+] Writing data to flag.html
[+] Building the 1st part of the flag ...
[+] Flag part 1: b0rn_t0_5truc7_
[+] Building the 2nd part of the flag ...
[+] Decryption password: b'oXiG3NisAMAZInG\x00'
[+] Final flag: b0rn_t0_5truc7_b4by@flare-on.com
[+] Flag is correct.
"""
# ----------------------------------------------------------------------------------------
