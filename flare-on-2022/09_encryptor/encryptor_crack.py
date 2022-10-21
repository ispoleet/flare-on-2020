#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2022: 9 - encryptor
# ----------------------------------------------------------------------------------------
from Crypto.Util import number


# ----------------------------------------------------------------------------------------
# ChaCha20 Encryption/Decryption
def quarter_round(a, b, c, d):
    ROTL = lambda n, c: ((n << c) | (n >> (32 - c))) & 0xFFFFFFFF

    a += b; a &= 0xFFFFFFFF; d ^= a; d = ROTL(d,16); 
    c += d; c &= 0xFFFFFFFF; b ^= c; b = ROTL(b,12);  
    a += b; a &= 0xFFFFFFFF; d ^= a; d = ROTL(d, 8);
    c += d; c &= 0xFFFFFFFF; b ^= c; b = ROTL(b, 7);

    return a, b, c, d

def chacha20_gen_keystream(key):
    dword = lambda n: n[0] | n[1] << 8 | n[2] << 16 | n[3] << 24

    X = [dword(key[i:i+4]) for i in range(0, 64, 4)]
    X_bkp = X[::]

    print(f"[+] Initial: {'-'.join('%08X' % x for x in X)}")
    
    for i in range(10):
        # Mix columns
        X[0], X[4], X[ 8], X[12] = quarter_round(X[0], X[4], X[ 8], X[12])
        X[1], X[5], X[ 9], X[13] = quarter_round(X[1], X[5], X[ 9], X[13])
        X[2], X[6], X[10], X[14] = quarter_round(X[2], X[6], X[10], X[14])
        X[3], X[7], X[11], X[15] = quarter_round(X[3], X[7], X[11], X[15])

        # Mix diagonals
        X[0], X[5], X[10], X[15] = quarter_round(X[0], X[5], X[10], X[15])
        X[1], X[6], X[11], X[12] = quarter_round(X[1], X[6], X[11], X[12])
        X[2], X[7], X[ 8], X[13] = quarter_round(X[2], X[7], X[ 8], X[13])
        X[3], X[4], X[ 9], X[14] = quarter_round(X[3], X[4], X[ 9], X[14])
        
        print(f"[+] Round {i}: {'-'.join('%08X' % x for x in X)}")

    X = list(map(lambda x, y: (x + y) & 0xFFFFFFFF, X, X_bkp))    
    print(f"[+] Final Add: {'-'.join('%08X' % x for x in X)}")

    keystream = []
    for x in X:
        keystream += [x & 0xFF, (x >> 8) & 0xFF, (x >> 16)  & 0xFF, x >>24]

    print(f"[+] Final Key Stream: {'-'.join('%02X' % k for k in keystream)}")
    
    return keystream


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Encryptor crack started.')

    # Ciphertext occupies the first 73 bytes. Then we have the 1024-bit bignums.
    with open('SuspiciousFile.txt.Encrypted', 'rb') as fp:
    # with open('ispo.Encrypted.fixed', 'rb') as fp:
        cipher = fp.read(73)
        # cipher = fp.read(8)

        num_a = fp.read(257).strip().decode('utf-8')  # +1 for newline.
        num_b = fp.read(257).strip().decode('utf-8')
        num_c = fp.read(257).strip().decode('utf-8')
        num_d = fp.read(256).strip().decode('utf-8')

    # num_a and num_c are decoys (not used).    
    n = int(num_b, 16)
    C = int(num_d, 16)

    print('[+] Ciphertext:', '-'.join('%02X' % x for x in cipher))
    print(f'[+] n: 0x{n:X}')
    print(f'[+] C: 0x{C:X}')

    
    # This will take a while (~18 secs), but we're good :)
    key = (C ** 0x10001) % n
    
    print(f'[+] Key: 0x{key:X}')

    # Correct Key:
    #   01 B0 97 A1 2A 39 FC 42  05 24 A2 E7 75 A7 43 C9
    #   28 D5 A5 50 B1 87 9A A8  B4 15 57 1E 38 32 9B 98
    #   00 00 00 00 02 49 FC 0F  C8 33 40 FE 4D 92 8F 95 

    # Reverse array (it's little endian).
    key_arr = list(bytes.fromhex(f'{key:X}')[::-1])

    print('[+] Key array:', '-'.join('%02X' % x for x in key_arr))

    # Build key for Chacha20.
    #
    # Test key:
    #   chacha20_key = (
    #       [ord(a) for a in 'expand 32-byte k'] +
    #       [0x20 + x for x in range(16)] +
    #       [0x30 + x for x in range(16)] +
    #       [0]*4 +
    #       [0x40 + x for x in range(12)]
    #   )        
    chacha20_key = [ord(a) for a in 'expand 32-byte k'] + key_arr

    # Decrypt 64 of them (1 block) (they are enough).
    keystream = chacha20_gen_keystream(chacha20_key)
    
    flag = ''.join(chr(c ^ k) for c, k in zip(cipher, keystream))

    print(f'[+] Decrypted Plaintext:\n{flag}')

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@localhost:~/ctf/flare-on-challenges/flare-on-2022/09_encryptor$ time ./encryptor_crack.py 
[+] Encryptor crack started.
[+] Ciphertext: 7F-8A-FA-63-65-9C-5E-F6-9E-B9-C3-DC-13-E8-B2-31-3A-8F-E3-6D-94-86-34-21-46-2B-6F-E8-AD-30-8D-2A-79-E8-EA-7B-66-09-D8-D0-58-02-3D-97-14-6B-F2-AA-60-85-06-48-4D-97-0E-71-EA-82-06-35-BA-4B-FC-51-8F-06-E4-AD-69-2B-E6-25-5B
[+] n: 0xDC425C720400E05A92EEB68D0313C84A978CBCF47474CBD9635EB353AF864EA46221546A0F4D09AAA0885113E31DB53B565C169C3606A241B569912A9BF95C91AFBC04528431FDCEE6044781FBC8629B06F99A11B99C05836E47638BBD07A232C658129AEB094DDAF4C3AD34563EE926A87123BC669F71EB6097E77C188B9BC9
[+] C: 0x5A04E95CD0E9BF0C8CDDA2CBB0F50E7DB8C89AF791B4E88FD657237C1BE4E6599BC4C80FD81BDB007E43743020A245D5F87DF1C23C4D129B659F90ECE2A5C22DF1B60273741BF3694DD809D2C485030AFDC6268431B2287C597239A8E922EB31174EFCAE47EA47104BC901CEA0ABB2CC9EF974D974F135AB1F4899946428184C
[+] Key: 0x958F924DFE4033C80FFC490200000000989B32381E5715B4A89A87B150A5D528C943A775E7A2240542FC392AA197B001
[1, 176, 151, 161, 42, 57, 252, 66, 5, 36, 162, 231, 117, 167, 67, 201, 40, 213, 165, 80, 177, 135, 154, 168, 180, 21, 87, 30, 56, 50, 155, 152, 0, 0, 0, 0, 2, 73, 252, 15, 200, 51, 64, 254, 77, 146, 143, 149] <class 'list'>
[+] Key array: 01-B0-97-A1-2A-39-FC-42-05-24-A2-E7-75-A7-43-C9-28-D5-A5-50-B1-87-9A-A8-B4-15-57-1E-38-32-9B-98-00-00-00-00-02-49-FC-0F-C8-33-40-FE-4D-92-8F-95
[+] Initial: 61707865-3320646E-79622D32-6B206574-A197B001-42FC392A-E7A22405-C943A775-50A5D528-A89A87B1-1E5715B4-989B3238-00000000-0FFC4902-FE4033C8-958F924D
[+] Round 0: 8B8CEBAE-4C017D62-15FEA7DB-F1252C5A-3AC66152-627109E8-235AD2A4-CDA5F3DC-EE2103BB-28E96FF8-865A3EB2-0A7EE199-C699ED82-5C2BB73E-CDA36A5A-E4E29DBF
[+] Round 1: 24311766-48854B41-C59BBBAB-9EEF2933-375286B9-652DA694-60A4C227-088B1DD5-C6B64A9C-1A4381D5-A1FC7FB2-3CAF78A5-19AF9EDE-0AB9B73F-435000BC-7049C66F
[+] Round 2: B495006E-F4F2AE8E-2CBC030D-DBBFA1BB-F77BCE3D-98ACD26D-12B21B67-3C81AC3D-77915458-FD8F3445-AD573B7D-1DAB72CE-C864156E-116D4B9E-283456D8-EDC2B56B
[+] Round 3: D0A6B847-D31AC43C-6C7C8D4C-D2BBD9D9-FE4BE72C-9A630035-E6F87310-648634C9-75846177-D1F30207-14C794DE-D2E53113-05A14248-94B8D9BE-B7364E73-33F31195
[+] Round 4: 386391AB-AA4F6927-3C824A81-134683E1-551EDE63-CB175FAD-25C52E0D-93BD80C0-6D7245E8-5D599A1A-E4F22D4D-EB3A5DFB-995B3B53-8AE80E39-77C34F10-128CB80F
[+] Round 5: C2B6496E-3871E981-219C6D58-08BC5BD6-3F115576-DFDCF51E-656FB650-87EA9B16-95A23ECC-E2CC486D-60B52488-5C5F032C-DE43D707-852F6EE7-3D2AF65E-F6BA4700
[+] Round 6: 5E77A710-406CE5DF-85C04091-DD9870B6-E0A50689-A34EC65C-C485AC7F-A1DD881C-9EED8285-24178427-B94EE684-41E70E5C-88FDF2C9-15BDFD8A-0CBFC5BD-61D9C6E8
[+] Round 7: 8F8C5A08-D435D7F0-D9966CA7-C597786D-FD77C3EC-27505B65-659A8C5A-5D118779-9E661FEB-FE62AFF0-FFD1302B-950D4BB4-DCDEB7EE-5A332253-AB1D2B6F-90FEC01B
[+] Round 8: 2D81B98D-99E13758-3F86B734-4F382B1F-3BB4BB55-011B7FE5-EDD623CF-6CF1DFFC-D2103818-E5B0BF4F-B67E29AE-CA4DA3C9-894FFB37-96971C89-9F0BDF4D-58B50286
[+] Round 9: AE2676D2-C934589C-8344A498-EBB31F01-B5F93619-C26A5374-F1A95002-7B78B726-FE35E227-F80DB188-81B510B4-34270239-2B68B63F-3682A53D-77287F13-8E0D958F
[+] Final Add: 0F96EF37-FC54BD0A-FCA6D1CA-56D38475-5790E61A-05668C9E-D94B7407-44BC5E9B-4EDBB74F-A0A83939-A00C2668-CCC23471-2B68B63F-467EEE3F-7568B2DB-239D27DC
[+] Final Key Stream: 37-EF-96-0F-0A-BD-54-FC-CA-D1-A6-FC-75-84-D3-56-1A-E6-90-57-9E-8C-66-05-07-74-4B-D9-9B-5E-BC-44-4F-B7-DB-4E-39-39-A8-A0-68-26-0C-A0-71-34-C2-CC-3F-B6-68-2B-3F-EE-7E-46-DB-B2-68-75-DC-27-9D-23
[+] Decrypted Plaintext:
Hello!

The flag is:

R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flar
[+] Program finished! Bye bye :)

real    0m19.978s
user    0m19.890s
'''
# ----------------------------------------------------------------------------------------

