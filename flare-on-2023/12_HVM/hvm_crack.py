#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 12 - HVM
# ----------------------------------------------------------------------------------------
import base64


glo_xor_key = [
  0x19, 0x76, 0x37, 0x2F, 0x3D, 0x1D, 0x26, 0x3F, 0x7B, 0x06, 
  0x39, 0x58, 0x12, 0x23, 0x25, 0x6B, 0x2A, 0x07, 0x3C, 0x38, 
  0x18, 0x68, 0x16, 0x1C, 0x30, 0x09, 0x34, 0x23, 0x08, 0x5B, 
  0x21, 0x24, 0x36, 0x61, 0x6A, 0x26, 0x6A, 0x0F, 0x44, 0x5D, 
  0x06
]

__ROL4__ = lambda n, c: (((n & 0xFFFFFFFF) << c) | ((n & 0xFFFFFFFF) >> (32 - c))) & 0xFFFFFFFF
__ROR4__ = lambda n, c: (((n & 0xFFFFFFFF) >> c) | ((n & 0xFFFFFFFF) << (32 - c))) & 0xFFFFFFFF

str_2_dword  = lambda a: ord(a[0]) | (ord(a[1]) << 8) | (ord(a[2]) << 16) | (ord(a[3]) << 24)
dword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
qword_2_list = lambda a: [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF,
                          (a >> 32) & 0xFF, (a >> 40) & 0xFF, (a >> 48) & 0xFF, (a >> 56) & 0xFF]
list_2_dword = lambda a: a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24)
list_2_qword = lambda a: (a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24) |
                          (a[4] << 32) | (a[5] << 40) | (a[6] << 48) | (a[7] << 56))


# ----------------------------------------------------------------------------------------
def modified_salsa20():
    buf = [str_2_dword('FLAR') for i in range(16)]
    init = buf[:]

    for i in range(0, 19+1, 2):
        buf[4] ^= __ROL4__(buf[0] + buf[12], 7);
        buf[8] ^= __ROL4__(buf[4] + buf[0], 9);
        buf[12] ^= __ROL4__(buf[8] + buf[4], 13);
        buf[0] ^= __ROR4__(buf[12] + buf[8], 14);
        buf[9] ^= __ROL4__(buf[5] + buf[1], 7);
        buf[13] ^= __ROL4__(buf[9] + buf[5], 9);
        buf[1] ^= __ROL4__(buf[13] + buf[9], 13);
        buf[5] ^= __ROR4__(buf[1] + buf[13], 14);
        buf[14] ^= __ROL4__(buf[10] + buf[6], 7);
        buf[2] ^= __ROL4__(buf[14] + buf[10], 9);
        buf[6] ^= __ROL4__(buf[2] + buf[14], 13);
        buf[10] ^= __ROR4__(buf[6] + buf[2], 14);
        buf[3] ^= __ROL4__(buf[15] + buf[11], 7);
        buf[7] ^= __ROL4__(buf[3] + buf[15], 9);
        buf[11] ^= __ROL4__(buf[7] + buf[3], 13);
        buf[15] ^= __ROR4__(buf[11] + buf[7], 14);
        buf[1] ^= __ROL4__(buf[0] + buf[3], 7);
        buf[2] ^= __ROL4__(buf[1] + buf[0], 9);
        buf[3] ^= __ROL4__(buf[2] + buf[1], 13);
        buf[0] ^= __ROR4__(buf[3] + buf[2], 14);
        buf[6] ^= __ROL4__(buf[5] + buf[4], 7);
        buf[7] ^= __ROL4__(buf[6] + buf[5], 9);
        buf[4] ^= __ROL4__(buf[7] + buf[6], 13);
        buf[5] ^= __ROR4__(buf[4] + buf[7], 14);
        buf[11] ^= __ROL4__(buf[10] + buf[9], 7);
        buf[8] ^= __ROL4__(buf[11] + buf[10], 9);
        buf[9] ^= __ROL4__(buf[8] + buf[11], 13);
        buf[10] ^= __ROR4__(buf[9] + buf[8], 14);
        buf[12] ^= __ROL4__(buf[15] + buf[14], 7);
        buf[13] ^= __ROL4__(buf[12] + buf[15], 9);
        buf[14] ^= __ROL4__(buf[13] + buf[12], 13);
        tmp1 = __ROR4__(buf[14] + buf[13], 14);
        tmp2 = tmp1 ^ (buf[15] & 0xFF)
        buf[15] ^= tmp1;

        print(f'[+] Salsa 20 round {i}', ' '.join('%08X' % a for a in buf))
   
    for i in range(16):
        buf[i] += init[i]
        buf[i] &= 0xFFFFFFFF

    l = []
    for b in buf:
        l += dword_2_list(b)
    
    return l


# ----------------------------------------------------------------------------------------
def verify(argv2):
    b = base64.b64decode(argv2)
    buf = [0]*6
    buf[0] = list_2_qword(b[0:8])
    buf[1] = list_2_qword(b[8:16])
    buf[2] = list_2_qword(b[16:24])
    buf[3] = list_2_qword(b[24:32])
    buf[4] = list_2_qword(b[32:40])
    buf[5] = list_2_qword(b[40:48])

    for i in range(0, decoded_len // 8, 2):
       x = buf[i]
       y = buf[(i + 1)]
       for j in range(7, 0-1, -1):
           tmp = buf[i]
           buf[i] ^= buf[(i + 1)] ^ salsa20_blk[j]
           buf[i + 1] = tmp

           x, y = buf[i], buf[i + 1]

    secret = (qword_2_list(buf[0]) +
              qword_2_list(buf[1]) +
              qword_2_list(buf[2]) +
              qword_2_list(buf[3]) +
              qword_2_list(buf[4]) +
              qword_2_list(buf[5]))
    
    assert(
        ''.join(chr(x) for x in secret) ==
        'FLARE2023FLARE2023FLARE2023FLARE2023\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

  
# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] HVM crack started.')

    blk = modified_salsa20()
    salsa20_blk = [list_2_qword(blk[x:x+8]) for x in range(0, 64, 8)]
    print('[+] Modified Salsa20 key stream', ' '.join(hex(x) for x in salsa20_blk))

    argv1 = b'FLARE2023FLARE2023FLARE2023FLARE2023\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    buf = [0]*6
    buf[0] = list_2_qword(argv1[0:8])
    buf[1] = list_2_qword(argv1[8:16])
    buf[2] = list_2_qword(argv1[16:24])
    buf[3] = list_2_qword(argv1[24:32])
    buf[4] = list_2_qword(argv1[32:40])
    buf[5] = list_2_qword(argv1[40:48])
    
    # We have to run the Feistel Network in reverse.
    # Let's do the forward first.
    #
    #   for i in range(0, decoded_len // 8, 2):
    #       x = buf[i]
    #       y = buf[(i + 1)]
    #       print(f'INIT:  {x:016X} {y:016X}')
    #
    #       for j in range(7, 0-1, -1):
    #           tmp = buf[i]
    #           buf[i] ^= buf[(i + 1)] ^ salsa20_blk[j]
    #           buf[i + 1] = tmp
    #
    #           x, y = buf[i], buf[i + 1]
    #           print(f'RND: {j} {x:016X} {y:016X}')
    #
    print('[+] Running Feistel Network backwards ...')
    
    decoded_len = 48
    for i in range(0, decoded_len // 8, 2):
        x, y = buf[i], buf[i + 1]
    
        print(f'[+] Initial State: {x:016X} {y:016X}')
        for j in range(8):
            tmp = buf[i + 1]
            buf[i + 1] ^= buf[i] ^ salsa20_blk[j]
            buf[i] = tmp

            x, y = buf[i], buf[i + 1]
            print(f'[+] Round {j}: {j} {x:016X} {y:016X}')


    print('[+] Reconstructing secret ...')
    secret = (qword_2_list(buf[0]) +
              qword_2_list(buf[1]) +
              qword_2_list(buf[2]) +
              qword_2_list(buf[3]) +
              qword_2_list(buf[4]) +
              qword_2_list(buf[5]))

    print('[+] Secret:', ' '.join(f'{x:02X}' for x in secret))

    argv2 = base64.b64encode(bytearray(secret))
    print(f'[+] Base64 encoded secret: {argv2}')

    flag = ''.join(chr(k ^ e) for k, e in zip(glo_xor_key, argv2))
    print(f'[+] Flag is: {flag}@flare-on.com')
    print(f'[+] argv[1]: {argv1[:0x24]}')
    print(f'[+] argv[2]: {argv2}')

    verify(argv2)

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/12_HVM$ ./hvm_crack.py 
[+] HVM crack started.
[+] Salsa 20 round 0 C05C66EA 833C7FBD ED7DE97F 5E2A8403 5E2A8403 C05C66EA 833C7FBD ED7DE97F ED7DE97F 5E2A8403 C05C66EA 833C7FBD 833C7FBD ED7DE97F 5E2A8403 C05C66EA
[+] Salsa 20 round 2 3085869B A162D05E 7EB6DFE5 A451B3A1 A451B3A1 3085869B A162D05E 7EB6DFE5 7EB6DFE5 A451B3A1 3085869B A162D05E A162D05E 7EB6DFE5 A451B3A1 3085869B
[+] Salsa 20 round 4 C8114F2F BF78BB0C F9544606 F0589850 F0589850 C8114F2F BF78BB0C F9544606 F9544606 F0589850 C8114F2F BF78BB0C BF78BB0C F9544606 F0589850 C8114F2F
[+] Salsa 20 round 6 441390E5 E85AB320 D65764FE 765E5245 765E5245 441390E5 E85AB320 D65764FE D65764FE 765E5245 441390E5 E85AB320 E85AB320 D65764FE 765E5245 441390E5
[+] Salsa 20 round 8 7EFA1429 C03F7491 D0AE83BF FE7642CE FE7642CE 7EFA1429 C03F7491 D0AE83BF D0AE83BF FE7642CE 7EFA1429 C03F7491 C03F7491 D0AE83BF FE7642CE 7EFA1429
[+] Salsa 20 round 10 84F0C27C 507BB50E 95A91BE3 F8AC2315 F8AC2315 84F0C27C 507BB50E 95A91BE3 95A91BE3 F8AC2315 84F0C27C 507BB50E 507BB50E 95A91BE3 F8AC2315 84F0C27C
[+] Salsa 20 round 12 0B161A5A 0FD189A1 0FF7B2B3 691D6586 691D6586 0B161A5A 0FD189A1 0FF7B2B3 0FF7B2B3 691D6586 0B161A5A 0FD189A1 0FD189A1 0FF7B2B3 691D6586 0B161A5A
[+] Salsa 20 round 14 19C7F0A2 EAF9D86B 3C320DC3 66095CEE 66095CEE 19C7F0A2 EAF9D86B 3C320DC3 3C320DC3 66095CEE 19C7F0A2 EAF9D86B EAF9D86B 3C320DC3 66095CEE 19C7F0A2
[+] Salsa 20 round 16 26CE94AF DB1724F3 D345FB52 A2E56FA7 A2E56FA7 26CE94AF DB1724F3 D345FB52 D345FB52 A2E56FA7 26CE94AF DB1724F3 DB1724F3 D345FB52 A2E56FA7 26CE94AF
[+] Salsa 20 round 18 A2E314BC 25CB3827 50D7AEB4 0CE2D073 0CE2D073 A2E314BC 25CB3827 50D7AEB4 50D7AEB4 0CE2D073 A2E314BC 25CB3827 25CB3827 50D7AEB4 0CE2D073 A2E314BC
[+] Modified Salsa20 key stream 0x780c846df5246102 0x5f241cb9a318fafa 0xf52461025f241cb9 0xa318fafa780c846d 0x5f241cb9a318fafa 0x780c846df5246102 0xa318fafa780c846d 0xf52461025f241cb9
[+] Running Feistel Network backwards ...
[+] Initial State: 3230324552414C46 30324552414C4633
[+] Round 0: 0 30324552414C4633 7A0EF37AE6296B77
[+] Round 1: 1 7A0EF37AE6296B77 1518AA91047DD7BE
[+] Round 2: 2 1518AA91047DD7BE 9A3238E9BD70A070
[+] Round 3: 3 9A3238E9BD70A070 2C326882C101F3A3
[+] Round 4: 4 2C326882C101F3A3 E9244CD2DF69A929
[+] Round 5: 5 E9244CD2DF69A929 BD1AA03DEB4C3B88
[+] Round 6: 6 BD1AA03DEB4C3B88 F72616154C2916CC
[+] Round 7: 7 F72616154C2916CC BF18D72AF84131FD
[+] Initial State: 324552414C463332 4552414C46333230
[+] Round 0: 0 4552414C46333230 0F1B9760FF516000
[+] Round 1: 1 0F1B9760FF516000 156DCA951A7AA8CA
[+] Round 2: 2 156DCA951A7AA8CA EF523CF7BA0FD473
[+] Round 3: 3 EF523CF7BA0FD473 59270C98D879F8D4
[+] Round 4: 4 59270C98D879F8D4 E9512CD6C16ED65D
[+] Round 5: 5 E9512CD6C16ED65D C87AA423EC334F8B
[+] Round 6: 6 C87AA423EC334F8B 8233720F55511DBB
[+] Round 7: 7 8233720F55511DBB BF6DB72EE6464E89
[+] Initial State: 0000000033323032 0000000000000000
[+] Round 0: 0 0000000000000000 780C846DC6165130
[+] Round 1: 1 780C846DC6165130 272898D4650EABCA
[+] Round 2: 2 272898D4650EABCA AA007DBBFC3CE643
[+] Round 3: 3 AA007DBBFC3CE643 2E301F95E13EC9E4
[+] Round 4: 4 2E301F95E13EC9E4 DB147E97BE1AD55D
[+] Round 5: 5 DB147E97BE1AD55D 8D28E56FAA007DBB
[+] Round 6: 6 8D28E56FAA007DBB F52461026C162C8B
[+] Round 7: 7 F52461026C162C8B 8D28E56F99324D89
[+] Reconstructing secret ...
[+] Secret: CC 16 29 4C 15 16 26 F7 FD 31 41 F8 2A D7 18 BF BB 1D 51 55 0F 72 33 82 89 4E 46 E6 2E B7 6D BF 8B 2C 16 6C 02 61 24 F5 89 4D 32 99 6F E5 28 8D
[+] Base64 encoded secret: b'zBYpTBUWJvf9MUH4KtcYv7sdUVUPcjOCiU5G5i63bb+LLBZsAmEk9YlNMplv5SiN'
[+] Flag is: c4n_i_sh1p_a_vm_as_an_exe_ask1ng_4_a_frnd@flare-on.com
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

