#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 6 - FlareSay
# ----------------------------------------------------------------------------------------
import copy
import hashlib


# Lambdas to convert DWORDs to lists and back
dword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
list_2_dword = lambda a: a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24)
str_2_dword  = lambda a: ord(a[0]) | (ord(a[1]) << 8) | (ord(a[2]) << 16) | (ord(a[3]) << 24)

rol4 = lambda n, c: ((n << c) | (n >> (32 - c))) & 0xFFFFFFFF

# ----------------------------------------------------------------------------------------
def calc_chksum(k):
    """Calculates the checksum of buffer."""
    chksum = 0

    for i in range(0, 16, 4):
        b1 = k[i + 0]
        b2 = k[i + 1]
        v7 = (b1 + rol4(chksum, 7)) ^ chksum
        v8 = (b2 + rol4(v7, 7)) ^ v7
        v9 = (k[i + 2] + rol4(v8, 7)) ^ v8
        chksum = (k[i + 3] + rol4(v9, 7)) ^ v9
        # print(f'[+] Checksum: {chksum:08X}')

    return chksum


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Flare say crack started.')

    for seed in range(65536):
        seq = []
        bignum = 0
        score = 0
        
        # Compute bignum and arrow sequence.
        prng = seed
        for rnd in range(128):  # Do 128 rounds.
            prng = (prng * 23167 + 12409) % 65536
            cx = (prng * 4) >> 16
            
            nxt = ['H', 'P', 'K', 'M']
            seq.append(nxt[cx])
            score += ord(nxt[cx])
            bignum = (bignum * 2**6 + bignum * 2**16 + score - bignum)
            bignum &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    
        # Convert bignum to bytes.
        bignum_bytes = []    
        for i in range(8):
            n = bignum & 0xFFFF
            bignum >>= 16    
            bignum_bytes += [n >> 8, n & 0xFF]

        bignum_bytes = bignum_bytes[::-1]  # Invert endianess.

        chksum = calc_chksum(bignum_bytes)    
        print(f"[+] Trying seed {seed} ... Checksum:{chksum:08X}h Bignum:{' '.join(f'{x:02X}' for x in bignum_bytes)}")

        if chksum == 0x31D9F5FF:
            print(f'[+] Seed FOUND: {seed}')
            print(f"[+] Arrow Sequence: {''.join(seq)}")
            print(f"[+] Bignum Bytes  : {' '.join(f'{x:02X}' for x in bignum_bytes)}")
            break

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/06_FlareSay$ ./flaresay_crack.py 
[+] Flare say crack started.
[+] Trying seed 0 ... Checksum:D3C3BC1Dh Bignum:38 FB A1 9F DB 42 18 37 8D 61 CB 55 52 A5 FA 74
[+] Trying seed 1 ... Checksum:6E4DA1A0h Bignum:C8 10 36 BA EE 5E D7 89 D3 C0 CC 73 00 C2 FC 38
[+] Trying seed 2 ... Checksum:1835D875h Bignum:AE D3 60 FA 42 0E BF 38 EB 8B 7B F9 70 A4 34 15
[+] Trying seed 3 ... Checksum:55A4ABA3h Bignum:31 8C 3C 21 4B DC C1 BB D6 2E A9 8A 27 6E 86 85
[+] Trying seed 4 ... Checksum:07C391EBh Bignum:07 96 D2 4E 53 B1 B8 F3 29 A2 BB 79 BB 94 8D E3
[+] Trying seed 5 ... Checksum:9A3B1494h Bignum:EC 32 4F FD A2 A8 BD AE F4 5C A5 56 08 1E E1 82
[+] Trying seed 6 ... Checksum:623BCA5Dh Bignum:6C 9E D8 B9 76 89 0E 7F 16 9E D9 12 C0 4B C0 09
......
[+] Trying seed 3078 ... Checksum:0AEA0C87h Bignum:61 68 AE F0 F2 BC 0D A0 C8 88 9E D4 9E 23 EC 91
[+] Trying seed 3079 ... Checksum:C385527Fh Bignum:02 2D 91 27 A3 CD CA 7E 3E C7 67 94 54 F0 C3 65
[+] Trying seed 3080 ... Checksum:50001DB8h Bignum:1B 64 52 A2 32 8E AF 7E 39 83 4C F3 4E 12 73 F6
[+] Trying seed 3081 ... Checksum:1048742Ah Bignum:52 19 D5 13 FE 83 48 5C EA A9 D7 D3 17 A7 48 CF
[+] Trying seed 3082 ... Checksum:31D9F5FFh Bignum:2B 4F 9D F2 E6 85 93 B8 12 D0 C1 C6 4C 4B 8B 30
[+] Seed FOUND: 3082
[+] Arrow Sequence: KPKMPHPMMHMMPMPKHMHKKMKKHKPPMKMPPKPHMPHHKPKHHPHMMHMMPHPMMMMKKMKKHMHKKKKPPKPPMKMPPPKHHPHHKPKMHHPMMHMMPHPKHMHKKMKKHKHPMKMPPKPPMPHH
[+] Bignum Bytes  : 2B 4F 9D F2 E6 85 93 B8 12 D0 C1 C6 4C 4B 8B 30
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

