#!/usr/bin/env sage
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 11 - Over the Rainbow
# ----------------------------------------------------------------------------------------
# To get sage running: 
#   wget https://github.com/python/cpython/blob/main/Include/cpython/longintrepr.h
#   sudo cp ~/Downloads/longintrepr.h /usr/include/python3.11/
#   sudo chmod 644 /usr/include/python3.11/longintrepr.h 
# ----------------------------------------------------------------------------------------
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long

pubkey = '''\
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAycMwco9oCHr8YKEz5Jud
PeSfD/mZXF4S5cZcEYl7xxjj5NJy1aWM5GN1WyxjRn8NCfk8Mctn/jGICa9/yLLI
xyGrVHzk22Pb3/9dmwbIV5n97mkPkMR5xtC546P2blXWMCnOWgLvhMaq3F4iQWgw
JMxl11ZCr+C6vnbymmd86xWb5IuzJl69K9UZoq9+A2zC5kAcN1VXYagcPR0opFbD
i5G1WQNb/wE92gQ5BTuelvSyePcZ6Tnmd9BYvG6YAFr/IwgUpJerNLf6kCtmbRgN
6E4k6Q91PXnbC3IXrLXEb00apWvuVz8tR6Qzfd0eK5Z+3HA4/usJDex0ktlNlom7
YQIBAw==
-----END PUBLIC KEY-----
'''

# ----------------------------------------------------------------------------------------
# Code taken from here:
# https://github.com/maximmasiutin/rsa-coppersmith-stereotyped-message/blob/main/rsa-coppersmith-stereotyped-message.sage
def message_recover(prefix, sec_len, suffix, c, n, e):
    ZmodN = Zmod(n)
    P.<x> = PolynomialRing(ZmodN)
    suffix_len = len(suffix)
    a = ZmodN(
        (bytes_to_long(prefix) * (2 ^ ((sec_len + suffix_len) * 8)))
        + bytes_to_long(suffix)
    )
    b = ZmodN(Integer(2 ^ (suffix_len * 8)))
    c = ZmodN(c)
    f = (a + b * x) ^ e - c
    f = f.monic()
    roots = f.small_roots(epsilon=1 / 20)
    rc = len(roots)
    if rc == 0:
        return None
    elif rc == 1:
        message = a + b * (roots[0])
        return long_to_bytes(int(message))
    else:
        print(
            "Don't know how to handle situation when multiple roots are returned:", rc
        )
        sys.exit(1)

def encrypt(m, n, e):
    m = bytes_to_long(m)
    return pow(m, e, n)

def do_coppersmith(
    n=None,
    bits=None,
    e=None,
    c=None,
    prefix=None,
    suffix=None,
    test_secret=None,
    secret_len=None,
):
    if "n" not in locals() or n is None:
        print("Generating public modulus..")
        if "bits" not in locals() or bits is None:
            bits = 4096
        pn = 2 ^ (bits // 2) - 1
        pl = 2 ^ (bits // 2 - 1)
        p = random_prime(pn, False, pl)
        q = random_prime(pn, False, pl)
        n = p * q
        print("n=", n)
    else:
        if not ("bits" not in locals() or bits is None):
            print(
                'Error: if you defined "n"', n, 'you should not specify "bits"!', bits
            )
            sys.exit(1)

    if "e" not in locals() or e is None:
        e = 5
        print("e=", e)

    if "suffix" not in locals() or suffix is None:
        suffix = (
            bytearray([0x0A])
            + "The quick brown fox jumped over ??".encode()
            + bytearray([0x0A])
        )

    if "prefix" not in locals() or prefix is None:
        prefix = "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do once or twice she had peeped into sister was reading, but it had no pictures or conversations in it, and what is the use of a book thought Alice without".encode() + bytearray(
            [0xE8, 0x01]
        )

    if "c" not in locals() or c is None:
        if "test_secret" not in locals() or test_secret is None:
            if "secret_len" not in locals() or secret_len is None:
                secret_len = 51
            test_secret = (bytearray([0xFF])) * int(
                secret_len
            )  # You can alsox[ 0], x[ 4], x[ 8], fill this with pseudorandom bytes rather than fixed bytes
        else:
            secret_len = len(test_secret)

        plaintext = prefix + test_secret + suffix
        c = encrypt(plaintext, n, e)
        print("c=", c)
    else:
        if "secret_len" not in locals() or secret_len is None:
            secret_len = 51

    e = Integer(e)
    n = Integer(n)
    c = Integer(c)
    max_secret_len = max(n.nbits(), c.nbits()) // 8 - len(prefix) - len(suffix)
    if secret_len > max_secret_len:
        print(
            "Error: The secret length of",
            secret_len,
            "byte(s) is larger then the maximum of",
            max_secret_len,
            "bytes(s) for the given prefix, suffix, encrypted message and the public exponent!",
        )
        sys.exit(1)

    print(
        "Will recover the secret with the length of up to a maximum",
        max_secret_len,
        "byte(s).",
    )

    # Attack
    while True:
        print("Trying to recover the message", secret_len, "byte(s) long...")
        message = message_recover(prefix, secret_len, suffix, c, n, e)
        if message is not None:
            # Uncomment the following if you need to write decrypted message on disk
            #            with open("decrypted-message.bin", "wb") as file:
            #                file.write(message)
            #                file.close()
            break
        else:
            if secret_len > max_secret_len:
                print("Could not recover the message, sorry!")
                sys.exit(1)
        secret_len += 1

    # Result
    print("Decrypted message:", message)
    if ("plaintext" in locals()) and (plaintext is not None) and (plaintext != message):
        print("Original message:", plaintext)

    return message


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Over the Rainbow crack started.')

    print('[+] Loading secret message (very_important_file.d3crypt_m3) ...')
    with open('very_important_file.d3crypt_m3', 'rb') as fp:
        contents = fp.read()
        rsa_c = contents[len(contents) - 256:]
        msg  = contents[:len(contents) - 256]
        
    print('[+] Loading ciphertext ...')
    c = '0x' + ''.join('%02X' % x for x in rsa_c)

    print('[+] Loading public key ...')
    public_key = RSA.importKey(pubkey)
    n = public_key.n
    e = public_key.e
    
    print(f'[+] n = {n}')
    print(f'[+] e = {e}')
    print(f'[+] c = {c}')

    plaintext = do_coppersmith(
        prefix=('\x00'*168).encode(),
        suffix='expand 32-byte k'.encode(),
        secret_len=48+24,
        n=n,
        c=c,
        e=3,
    )

    p = int.from_bytes(plaintext, byteorder='big')
    print(f'[+] Plaintext found: 0x{p:X}')


    # rand2 = [
    #     0x06, 0xF7, 0x76, 0x8F, 0xF2, 0xB9, 0x63, 0xF3, 0x56, 0xFC, 0x25, 0xB3,
    #     0x44, 0x3F, 0x7B, 0x72, 0x9F, 0x68, 0xBC, 0xBD, 0xD6, 0x5F, 0x22, 0xDE,
    # ]
    rand2 = list(plaintext[:24])
    print('[+] Recovered rand2:', ' '.join(f'{x:02X}'for x in rand2))

    # rand1 = [
    #     0x68, 0x5C, 0x3C, 0xB5, 0xC8, 0xA2, 0x69, 0x72, 0x24, 0x36, 0x85, 0x30,
    #     0xE2, 0x64, 0xFD, 0x38, 0x8D, 0xC9, 0x62, 0xF5, 0xD7, 0x37, 0xCB, 0x87,
    #     0x3E, 0x24, 0xF3, 0x97, 0x09, 0xD2, 0x94, 0x22, 0x4A, 0x52, 0x68, 0xC3,
    #     0x51, 0x2D, 0xDB, 0x6B, 0x3E, 0x54, 0x41, 0x9B, 0x41, 0xC8, 0x10, 0xCF,
    # ]
    rand1 = list(plaintext[24:24+48])
    print('[+] Recovered rand2:', ' '.join(f'{x:02X}'for x in rand1))

    # Take this directly from IDA no need to implement modified salsa20 :)
    #
    #    .text:000000014007F25D    lea     r8, [rsp+568h+salsa20_blk]
    #    .text:000000014007F265    lea     rdx, [rsp+568h+rand_bytes]
    #    .text:000000014007F26D    mov     rcx, [rsp+568h+var_530]
    #    .text:000000014007F272    call    u_custom_salsa20_encrypt
    #    .text:000000014007F277    mov     rax, 0AAAAAAAAAAAAAAABh  ; <~ Breakpoint here
    salsa20_blk = [
        0x6C, 0xE1, 0xF0, 0xBC, 0x2B, 0x3D, 0xE3, 0x62, 0xAC, 0x1A, 
        0xD8, 0xED, 0x3A, 0xEF, 0x0E, 0x1C, 0xEF, 0xF1, 0x09, 0x0F, 
        0x34, 0xC5, 0xE6, 0x1A, 0x4F, 0xF5, 0x5F, 0xC4, 0x90, 0xE0, 
        0x3A, 0xE8, 0x81, 0x4F, 0x75, 0xEE, 0x1B, 0xB5, 0x01, 0x6B, 
        0x0D, 0xA3, 0xD4, 0x31, 0xBC, 0x0B, 0xE4, 0xC9, 0x15, 0xCC, 
        0xAB, 0xEB, 0x8D, 0x23, 0x70, 0x18, 0xBF, 0xB7, 0xDB, 0xA8, 
        0x17, 0x96, 0xD3, 0xF7
    ]

    # Do the decryption.
    flag = ''.join(chr(m ^^ rand2[i % 24] ^^ salsa20_blk[i]) for i, m in enumerate(msg))
    print(f'[+] Flag is: {flag}')
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/11_over_the_rainbow$ ./over_the_rainbow_crack.sage 
[+] Over the Rainbow crack started.
[+] Loading secret message (very_important_file.d3crypt_m3) ...
[+] Loading ciphertext ...
[+] Loading public key ...
[+] n = 25470150703730072315086034936055649836295236884601534304156993296936285040601301375939610442634162257314189499275100972455566398455602026574433195970815202585090501432569441133857842325042217925159448570072586058996240505604332536419689764920477213974406475165093073579216369638057129512420088827606714396031123135244463251843168817519429473193827165432916372277360150211932008151288302906204095482949720169306181114320172114379252171541724857670073249548632622866650173757036971232388781059615489960396402755953330835572369467647829965472365925514887194394952977362957692659807638830075891677256168792219800752995169
[+] e = 3
[+] c = 0x1336E28042804094B2BF03051257AAAABA7EBA3E3DD6FACFF7E3ABDD571E9D2E2D2C84F512C0143B27207A3EAC0EF965A23F4F4864C7A1CEB913CE1803DBA02FEB1B56CD8EBE16656ABAB222E8EDCA8E9C0DDA17C370FCE72FE7F6909EED1E6B02E92EBF720BA6051FD7F669CF309BA5467C1FB5D7BB2B7AECA07F11A575746C1047EA35CC3CE246AC0861F0778880D18B71FB2A8D7A736A646CF99B3DCEC362D413414BEB9F01815DB7F72F6E081AEE91F191572A28B9576F6C532349F8235B6DAF31B39B5ADD7ADE0CFBD30F704EB83D983C215DE3261F73565843539F6BB46C9457DF16E807449F99F3DABDDDD5764FD63D09BC9C4E6844EC3410DC821AB4
Will recover the secret with the length of up to a maximum 72 byte(s).
Trying to recover the message 72 byte(s) long...
Decrypted message: b'\x06\xf7v\x8f\xf2\xb9c\xf3V\xfc%\xb3D?{r\x9fh\xbc\xbd\xd6_"\xdeh\\<\xb5\xc8\xa2ir$6\x850\xe2d\xfd8\x8d\xc9b\xf5\xd77\xcb\x87>$\xf3\x97\t\xd2\x94"JRh\xc3Q-\xdbk>TA\x9bA\xc8\x10\xcfexpand 32-byte k'
[+] Plaintext found: 0x6F7768FF2B963F356FC25B3443F7B729F68BCBDD65F22DE685C3CB5C8A2697224368530E264FD388DC962F5D737CB873E24F39709D294224A5268C3512DDB6B3E54419B41C810CF657870616E642033322D62797465206B
[+] Recovered rand2: 06 F7 76 8F F2 B9 63 F3 56 FC 25 B3 44 3F 7B 72 9F 68 BC BD D6 5F 22 DE
[+] Recovered rand2: 68 5C 3C B5 C8 A2 69 72 24 36 85 30 E2 64 FD 38 8D C9 62 F5 D7 37 CB 87 3E 24 F3 97 09 D2 94 22 4A 52 68 C3 51 2D DB 6B 3E 54 41 9B 41 C8 10 CF
[+] Flag is: Wa5nt_th1s_Supp0s3d_t0_b3_4_r3vers1nG_ch4l1eng3@flare-on.com

[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
