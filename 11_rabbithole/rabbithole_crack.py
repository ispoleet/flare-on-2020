#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 11 - rabbithole
# --------------------------------------------------------------------------------------------------
import io
from serpent import serpent_cbc_decrypt
from zipfile import ZipFile 


DiMap = [
    0x04, 0x0C, 0x01, 0x81, 0xE1, 0x85, 0x1F, 0xEF, 0x8D, 0x89, 0x0F, 0xAB, 0x13, 0xA6, 0xA2, 0x64,
    0xEF, 0xF5, 0x44, 0xB7, 0x10, 0xD0, 0xA8, 0xF5, 0x73, 0x1F, 0x9C, 0xFF, 0x06, 0x9F, 0xFC, 0x23,
    0x08, 0x4A, 0x11, 0x3A, 0x92, 0x3C, 0x5F, 0x51, 0x71, 0x70, 0x9B, 0xD0, 0x76, 0x9F, 0x50, 0xE7,
    0x11, 0xA7, 0x22, 0xCE, 0x48, 0xC7, 0xF3, 0x69, 0x78, 0x72, 0x1C, 0xA2, 0x05, 0xB6, 0xF2, 0x31,
    0xA5, 0xA4, 0xBA, 0xA6, 0xF3, 0x71, 0xE0, 0x61, 0x4B, 0xAD, 0x55, 0x66, 0xBA, 0x34, 0x4F, 0xA0,
    0x49, 0x37, 0xE6, 0xEF, 0x58, 0x57, 0x56, 0x07, 0xB2, 0xFB, 0x13, 0x63, 0xBC, 0xC2, 0x0B, 0xE3,
    0xD2, 0x91, 0xF7, 0xB7, 0x1A, 0x76, 0x6A, 0x42, 0xE3, 0xE8, 0x2F, 0x09, 0x31, 0x2F, 0x4F, 0xE2,
    0x91, 0x44, 0x54, 0xEF, 0xC7, 0x8C, 0x23, 0x35, 0x0D, 0x25, 0xF1, 0xE1, 0x38, 0x80, 0x14, 0xB7,
    0xF2, 0x7C, 0x55, 0x38, 0x2A, 0x9B, 0xB4, 0x11, 0xD0, 0x63, 0x1F, 0x24, 0x28, 0x90, 0xF1, 0xF3,
    0xE7, 0xC8, 0x74, 0x46, 0x02, 0xEA, 0x66, 0xCE, 0x1B, 0xA9, 0x71, 0xCC, 0x1B, 0x12, 0xB3, 0x97,
    0x9E, 0x05, 0x8B, 0x19, 0x04, 0x73, 0x1F, 0x83, 0xE5, 0xD7, 0xDA, 0xF9, 0x05, 0x83, 0xF5, 0x71,
    0x70, 0xD4, 0x59, 0xC2, 0x1F, 0xD7, 0xD4, 0x7E, 0x6E, 0x77, 0x1A, 0xC3, 0x58, 0xCB, 0xB9, 0x34,
    0x1C, 0x81, 0x73, 0xC9, 0xDE, 0xA9, 0x64, 0x9A, 0x6E, 0xFD, 0x0F, 0xE2, 0xC3, 0x3D, 0xC3, 0xA3
]

# Serpent Key: GSPyrv3C79ZbR0k13
DiMap_decr = [ 
    0xFE, 0x77, 0x31, 0x7A, 0xF9, 0x21, 0xEF, 0x52, 0x96, 0x77, 0x20, 0xBF, 0x43, 0x46, 0xD5, 0x49, 
    0x06, 0x28, 0xD6, 0x28, 0x5B, 0xE0, 0xC5, 0x9D, 0x99, 0xB4, 0x04, 0xF1, 0xF2, 0xB8, 0x0F, 0x75, 
    0xF4, 0xAE, 0xDD, 0xE2, 0x09, 0xD6, 0xE0, 0x07, 0x19, 0x37, 0xF4, 0x7A, 0xDC, 0x4F, 0xB9, 0xCF, 
    0x9D, 0x43, 0x42, 0xD2, 0x35, 0xBA, 0x11, 0xCE, 0xCA, 0xCE, 0xDF, 0x30, 0x76, 0xF8, 0xEB, 0x8D, 
    0x5A, 0x69, 0x78, 0x6C, 0xC3, 0xEA, 0xAA, 0xC6, 0x42, 0xA7, 0x85, 0xFC, 0xB3, 0x20, 0xAE, 0xD2, 
    0x09, 0x78, 0x99, 0xB4, 0xB1, 0xBE, 0x01, 0x38, 0x10, 0xD7, 0x75, 0x9F, 0x47, 0x2F, 0x84, 0xB2, 
    0x94, 0x28, 0xCC, 0xAF, 0x20, 0xC3, 0xD9, 0xEA, 0x03, 0xE5, 0x75, 0xB0, 0x81, 0xC2, 0x0B, 0x05, 
    0x5A, 0x10, 0x2B, 0xF6, 0xC2, 0x3A, 0x7B, 0x14, 0x30, 0xD2, 0xE2, 0x2F, 0xFA, 0xEC, 0x5D, 0xDD, 
    0x30, 0x87, 0x71, 0x74, 0x2D, 0xC2, 0x19, 0x2D, 0x00, 0x83, 0x9B, 0xCE, 0x22, 0x80, 0xE8, 0xCD, 
    0x35, 0x23, 0xB5, 0x4E, 0xF7, 0x91, 0x25, 0x32, 0xE3, 0x38, 0x27, 0xF9, 0xAA, 0x0F, 0x2C, 0x0F, 
    0x7F, 0x6C, 0x08, 0x75, 0x06, 0xD6, 0x40, 0x1A, 0x1B, 0xDF, 0xF5, 0x81, 0xA7, 0xF1, 0xF2, 0x31, 
    0x8F, 0x2C, 0x9C, 0x48, 0x54, 0x89, 0xD7, 0x7B, 0x8B, 0xDB, 0xFE, 0x46, 0xC0, 0x7C, 0x3C, 0xC9, 
    0xBE, 0x31, 0xFA, 0x06, 0x8A, 0x33, 0x75, 0x82, 0x4A, 0x2F, 0x5B, 0x83, 0x7B, 0xB5, 0xCB, 0xAF,     
]


itoa = lambda a: ''.join([chr(a & 0xFF), chr((a >> 8) & 0xFF), chr((a >> 16) & 0xFF),
                          chr((a >> 24) & 0xFF)])
ror = lambda a, b: ((a >> b) | (a << (32 - b))) & 0xFFFFFFFF
rol = lambda a, b: ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF


# --------------------------------------------------------------------------------------------------
def gen_sid_magic(sid):
    sid = sid.split('-')[1:]                        # drop 'S' and split into parts
    sid = [int(s) for s in sid]                     # convert to list
    # print ['%X' % x for x in sid]

    magic = (sid[4] << 32) + (sum(sid[3:6]) )
    magic ^= (0xEDB88320 << 32) | 0xEDB88320
             
    return magic


# --------------------------------------------------------------------------------------------------
def custom_encrypt(sid_magic):
    numA = 0
    Ci = 0

    for i in range(0, len(DiMap_decr), 4):
        val = DiMap_decr[i] | (DiMap_decr[i+1] << 8) | (DiMap_decr[i+2] << 16) | (DiMap_decr[i+3] << 24)       
        Ci = Ci ^ (sid_magic & 0xFFFFFFFF) ^ ror(val, 4 * numA);
        numA ^= 1
        # print '%08X --> %08X' % (val, Ci)


# --------------------------------------------------------------------------------------------------
def custom_decrypt(sid_magic):                      # Inverse of custom_encrypt()
    numA      = 0
    Ci        = 0
    prev_val  = 0
    plaintext = ''

    for i in range(0, len(DiMap), 4):
        val = DiMap[i] | (DiMap[i+1] << 8) | (DiMap[i+2] << 16) | (DiMap[i+3] << 24)    
        Ci = rol(val ^ (sid_magic & 0xFFFFFFFF) ^ prev_val, (4*numA) % 32)      
        numA ^= 1
        prev_val = val

        plaintext += ''.join(x for x in itoa(Ci))

        print '[+]\t%08X --> %08X: %s' % (val, Ci, ' '.join('%02X' % ord(x) for x in itoa(Ci)))
        
    return plaintext


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Rabbithole crack started.'
    
    sid = "S-1-5-21-3823548243-3100178540-2044283163-513"
    magic = gen_sid_magic(sid)

    print '[+] SID: %s' % sid
    print '[+] SID magic number: %X' % magic

    flag = ''

    # custom_encrypt(magic)
    print '[+] Decrypting DiMap with custom algorithm ...'
    plaintext = custom_decrypt(magic)

    print '[+] Applying serpent on decrypted DiMap ...'

    serpent_key = 'GSPyrv3C79ZbR0k1'
    plaintext_final = serpent_cbc_decrypt(serpent_key, plaintext)

    print "[+] Storing final plaintext into 'flag.zip' ..."

    # Write flag into file
    with open('flag.zip', 'wb') as fp:
        fp.write(plaintext_final)

    print "[+] Dumping contents of zip file ..."

    # Process zip file
    with ZipFile(io.BytesIO(plaintext_final), 'r') as zip_fp: 
        # printing all the contents of the zip file      
        zip_fp.printdir() 
      
        # extract all files
        for fileinfo in zip_fp.infolist():            
            print "[+] Extracting '%s' ..." % fileinfo.filename
            print '[+] Contents:', zip_fp.read(fileinfo).decode('ascii')

    print '[+] Program finished. Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare_on/11_rabbithole$ ./rabbithole_crack.py 
[+] Rabbithole crack started.
[+] SID: S-1-5-21-3823548243-3100178540-2044283163-513
[+] SID magic number: 55707B4EFB307BFA
[+] Decrypting DiMap with custom algorithm ...
[+] 81010C04 --> 7A3177FE: FE 77 31 7A
[+] EF1F85E1 --> 52EF21F9: F9 21 EF 52
[+] AB0F898D --> BF207796: 96 77 20 BF
[+] 64A2A613 --> 49D54643: 43 46 D5 49
[+] B744F5EF --> 28D62806: 06 28 D6 28
[+] F5A8D010 --> 9DC5E05B: 5B E0 C5 9D
[+] FF9C1F73 --> F104B499: 99 B4 04 F1
[+] 23FC9F06 --> 750FB8F2: F2 B8 0F 75
[+] 3A114A08 --> E2DDAEF4: F4 AE DD E2
[+] 515F3C92 --> 07E0D609: 09 D6 E0 07
[+] D09B7071 --> 7AF43719: 19 37 F4 7A
[+] E7509F76 --> CFB94FDC: DC 4F B9 CF
[+] CE22A711 --> D242439D: 9D 43 42 D2
[+] 69F3C748 --> CE11BA35: 35 BA 11 CE
[+] A21C7278 --> 30DFCECA: CA CE DF 30
[+] 31F2B605 --> 8DEBF876: 76 F8 EB 8D
[+] A6BAA4A5 --> 6C78695A: 5A 69 78 6C
[+] 61E071F3 --> C6AAEAC3: C3 EA AA C6
[+] 6655AD4B --> FC85A742: 42 A7 85 FC
[+] A04F34BA --> D2AE20B3: B3 20 AE D2
[+] EFE63749 --> B4997809: 09 78 99 B4
[+] 07565758 --> 3801BEB1: B1 BE 01 38
[+] 6313FBB2 --> 9F75D710: 10 D7 75 9F
[+] E30BC2BC --> B2842F47: 47 2F 84 B2
[+] B7F791D2 --> AFCC2894: 94 28 CC AF
[+] 426A761A --> EAD9C320: 20 C3 D9 EA
[+] 092FE8E3 --> B075E503: 03 E5 75 B0
[+] E24F2F31 --> 050BC281: 81 C2 0B 05
[+] EF544491 --> F62B105A: 5A 10 2B F6
[+] 35238CC7 --> 147B3AC2: C2 3A 7B 14
[+] E1F1250D --> 2FE2D230: 30 D2 E2 2F
[+] B7148038 --> DD5DECFA: FA EC 5D DD
[+] 38557CF2 --> 74718730: 30 87 71 74
[+] 11B49B2A --> 2D19C22D: 2D C2 19 2D
[+] 241F63D0 --> CE9B8300: 00 83 9B CE
[+] F3F19028 --> CDE88022: 22 80 E8 CD
[+] 4674C8E7 --> 4EB52335: 35 23 B5 4E
[+] CE66EA02 --> 322591F7: F7 91 25 32
[+] CC71A91B --> F92738E3: E3 38 27 F9
[+] 97B3121B --> 0F2C0FAA: AA 0F 2C 0F
[+] 198B059E --> 75086C7F: 7F 6C 08 75
[+] 831F7304 --> 1A40D606: 06 D6 40 1A
[+] F9DAD7E5 --> 81F5DF1B: 1B DF F5 81
[+] 71F58305 --> 31F2F1A7: A7 F1 F2 31
[+] C259D470 --> 489C2C8F: 8F 2C 9C 48
[+] 7ED4D71F --> 7BD78954: 54 89 D7 7B
[+] C31A776E --> 46FEDB8B: 8B DB FE 46
[+] 34B9CB58 --> C93C7CC0: C0 7C 3C C9
[+] C973811C --> 06FA31BE: BE 31 FA 06
[+] 9A64A9DE --> 8275338A: 8A 33 75 82
[+] E20FFD6E --> 835B2F4A: 4A 2F 5B 83
[+] A3C33DC3 --> AFCBB57B: 7B B5 CB AF
[+] Applying serpent on decrypted DiMap ...
[+] Storing final plaintext into 'flag.zip' ...
[+] Dumping contents of zip file ...
File Name                                             Modified             Size
C/Users/Kevin/Desktop/flag.txt                 1980-00-00 00:00:00           42
[+] Extracting 'C/Users/Kevin/Desktop/flag.txt' ...
[+] Contents: r4d1x_m4l0rum_357_cup1d1745@flare-on.com
[+] Program finished. Bye bye :)
'''
# --------------------------------------------------------------------------------------------------
