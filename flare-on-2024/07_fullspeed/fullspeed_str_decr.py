#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 07 - fullspeed
# ----------------------------------------------------------------------------------------
import binascii

xor = 133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337
# ----------------------------------------------------------------------------------------
def decrypt(s):
    ecx = 0
    res = []
    for b in binascii.unhexlify(s):
        ecx = ((ecx * 13) + 37) & 0xFF
        res.append(ecx ^ b) 

    return bytes(res)

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] fullspeed string deobfuscator started.')

    # Decrypt all strings from the program.
    strings = [
        '4c6815',
        '53630195971b',
        '53630195971b3fde1c17e751ad',
        '143540cbc0512c8f4c4db803f8698447e4c5905b90617c1f1c5d88934879d4d7b4d5e0eb60714cafec6dd8231809246704e5307b30019c3fbc7d28b3e81974f7d4f5008b8011ec4f0c0d78c3b8294407a485501b50213cdfdc1d485308399497',
        '4b731f90',
        '59',
        '4662',
        '4a6d',
        '51691cdc9d0d71df',
        '183b4edc950b6dcb5d43b609',
        '0b',
        '183b4edc970b73dd0e5eb609f4',
        '466707',
        '407e1a88',
        '476717dc920f7b',
        '143f41d2c05427964848a505f9698c43e4c5905b',
        '1e',
        '4975',
        '463f43cdc15079d91c4ab352f862d545b097c05dc765794a4f5a8bc54828de86e7d6b7e4657348a9ef3c89711a5f226502e0627b60079931ba7878b6bb4b22a384f20484811be84e080c73c7e87b4707ad835b1f04236aded81f4c565839c1c4',
        '443644c595002f80181fb900fe6a8445e59592549366771f4f5b8bc24e7dd7d7e182e7ea307747f9ec3ada22195c71670ce43a7b6551cc31ef287ae0ef4921a3dcf052848041eb1904097ec2bd2b4608f482531f5223698ddd4818550a3890c6',
        '1c604acfc8012f8a1c49e950fe3cd442e3c5c258c2312a1c1c58dd901a7fd0d5e3d4ebb861214eabec6b88204f0a74620de4652f60049838b42f2ee2e04c70a6dca501898041e61d585a2ecdec784652f4d7501d57223dd9db191d050c399f90',
        '153e449ec4047a8b1c1bbd50aa3cd540b0c69458c3667f4e1b5c8b9c1a7281d6e183e7ba65244faeea678f22100924670ce0677f630bcd6cbb7b22b3e91e21a2ddf307898344ef4c0c582d92b82e1456a5d35a4d00256adcd81b4f505f33c398',
        '143444c8c3577c89194db804ac3e8243e2c0955fc46a781c1857dec5187b85d1e7d3e0b935241aabed6b8d22480d2e3204ee372e32039738bd7d28e5b84876f9d5a35185d043ef480e5b7bc6ec231352f380071958216cdd881d1954013b9f92',
    ]

    for s in strings:
        ss = s
        if len(s) > 16:
            ss = s[:13] + '...'

        print(f'{ss:16} ~> {decrypt(s)}')

    print()

    # Decrypt the first 4 packets for ECDH key exchange (x1, y1) and (x2, y2)
    x = binascii.unhexlify('0a6c559073da49754e9ad9846a72954745e4f2921213eccda4b1422e2fdd646fc7e28389c7c2e51a591e0147e2ebe7ae')
    y = [a ^ b for a, b, in zip(x, b'\13\37'*24)]
    print('packet #1 ~>',  ''.join(f'{a:02X}' for a in y))

    x = binascii.unhexlify('264022daf8c7676a1b2720917b82999d42cd1878d31bc57b6db17b9705c7ff2404cbbf13cbdb8c096621634045293922')
    y = [a ^ b for a, b, in zip(x, b'\13\37'*24)]
    print('packet #2 ~>',  ''.join(f'{a:02X}' for a in y))

    x = binascii.unhexlify('a0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c31')
    y = [a ^ b for a, b, in zip(x, b'\x13\x37'*24)]
    print('packet #3 ~>',  ''.join(f'{a:02X}' for a in y))

    x = binascii.unhexlify('96a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dcf272d54c31860f')
    y = [a ^ b for a, b, in zip(x, b'\x13\x37'*24)]
    print('packet #4 ~>',  ''.join(f'{a:02X}' for a in y))

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[:(]─[00:00:54]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/07_fullspeed]
└──> ./fullspeed_str_deobf.py 
[+] fullspeed string deobfuscator started.
4c6815           ~> b'inf'
53630195971b     ~> b'verify'
53630195971b3... ~> b'verify failed'
143540cbc0512... ~> b'133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337'
4b731f90         ~> b'null'
59               ~> b'|'
4662             ~> b'cd'
4a6d             ~> b'ok'
51691cdc9d0d71df ~> b'too long'
183b4edc950b6... ~> b'=== dirs ==='
0b               ~> b'.'
183b4edc970b7... ~> b'=== files ==='
466707           ~> b'cat'
407e1a88         ~> b'exit'
476717dc920f7b   ~> b'bad cmd'
143f41d2c0542... ~> b'192.168.56.103;31337'
1e               ~> b';'
4975             ~> b'ls'
463f43cdc1507... ~> b'c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd'
443644c595002... ~> b'a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f'
1c604acfc8012... ~> b'9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380'
153e449ec4047... ~> b'087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8'
143444c8c3577... ~> b'127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182'

packet #1 ~> 01735E8F78C5426A4585D29B616D9E584EFBF98D190CE7D2AFAE493124C26F70CCFD8896CCDDEE0552010A58E9F4ECB1
packet #2 ~> 2D5F29C5F3D86C7510382B8E709D928249D21367D804CE6466AE70880ED8F43B0FD4B40CC0C487166D3E685F4E36323D
packet #3 ~> B3E5F89F04D49834DE312110AE05F0649B3F0BBE2987304FC4EC2F46D6F036F1A897807C4E693E0BB5CD9AC8A8005F06
packet #4 ~> 85944D98396918741316CD0109929CB706AF0CCA1EAF378219C5286BDC21E979210390573E3047645E1969BDBCB667EB
[+] Program finished successfully. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
