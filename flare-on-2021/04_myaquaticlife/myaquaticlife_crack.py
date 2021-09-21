#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 4 - My aquatic life
# ----------------------------------------------------------------------------------------
import tarfile
import os
import json
import zlib
import hashlib
import itertools

floatsam = ['DFWEyEW', 'BGgsuhn', 'PXopvM']
jetsam   = ['newaui',  'HwdwAZ',  'SLdkv']

rand_to_index = {
    'MZZWP': 1,
    'BAJkR': 2,
    'DFWEyEW': 3,
    'PXopvM': 4,
    'LDNCVYU': 5,
    'yXQsGB': 6,
    'newaui': 7,
    'QICMX': 8,
    'rOPFG': 9,
    'HwdwAZ': 10,
    'SLdkv': 11,
    'LSZvYSFHW': 12,
    'BGgsuhn': 13,
    'LSZvYSFHW': 14,
    'RTYXAc': 15,
    'GTXI': 16
}


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] My Aquatic Life crack started.')

    # We just assume that all elements from floatsam and jetsam are used (i.e., len = 3)
    for floatsam_order in list(itertools.permutations(floatsam)):
        for jetsam_order in list(itertools.permutations(jetsam)):
            init = (b'\x96\x25\xA4\xA9\xA3\x96\x9A\x90\x9F\xAF\xE5\x38\xF9\x81\x9E\x16'+
                    b'\xF9\xCB\xE4\xA4\x87\x8F\x8F\xBA\xD2\x9D\xA7\xD1\xFC\xA3\xA8\x00')

            floatsam_str = ''.join(floatsam_order)
            jetsam_str = ''.join(jetsam_order)

            flag = [((init[i] ^ ord(floatsam_str[i % len(floatsam_str)])) -
                                ord(jetsam_str[i % 0x11])) & 0xFF for i in range(31)]
            md5 = hashlib.md5(bytes(flag))

            fish_order = ([rand_to_index[i] for i in floatsam_order] +
                          [rand_to_index[i] for i in jetsam_order])

            print('[+] Fish order: %s, gives MD5 sum: %s' % (
                ', '.join('%d' % x for x in fish_order), md5.hexdigest()))

            if md5.hexdigest() == "6c5215b12a10e936f8de1e42083ba184":
                print('[+] Hash found! Flag is:', bytes(flag))
                exit()

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-2021/04_myaquaticlife$ ./myaquaticlife_crack.py 
    [+] My Aquatic Life crack started.
    [+] Fish order: 3, 13, 4, 7, 10, 11, gives MD5 sum: 0c862f6300200c1183e362f68585fc7b
    [+] Fish order: 3, 13, 4, 7, 11, 10, gives MD5 sum: 6eb4abfb79f0af903c20d48a80a1ed54
    [+] Fish order: 3, 13, 4, 10, 7, 11, gives MD5 sum: 5e63af3c21fbfb81e9a5a8cc7e104ff9
    [+] Fish order: 3, 13, 4, 10, 11, 7, gives MD5 sum: 2c2486ae3215cb9cc22773eb12eccb88
    [+] Fish order: 3, 13, 4, 11, 7, 10, gives MD5 sum: ba95ca2fda51a511ea333483af281d3b
    [+] Fish order: 3, 13, 4, 11, 10, 7, gives MD5 sum: c22719005c12ed83992f27f6b5777200
    [+] Fish order: 3, 4, 13, 7, 10, 11, gives MD5 sum: 1ced06649c92bec8e950779fb5798f9b
    [+] Fish order: 3, 4, 13, 7, 11, 10, gives MD5 sum: ddc23f96a79eaa396a67250e70a890f4
    [+] Fish order: 3, 4, 13, 10, 7, 11, gives MD5 sum: e054517b85d7f2e71388bd861342e927
    [+] Fish order: 3, 4, 13, 10, 11, 7, gives MD5 sum: cc01b26bed53131cd424948e521cbd50
    [+] Fish order: 3, 4, 13, 11, 7, 10, gives MD5 sum: e550eb92b2aad49c09e85772680064a7
    [+] Fish order: 3, 4, 13, 11, 10, 7, gives MD5 sum: c70b64c5f6ae88f1fc6fa054c3ec7e6b
    [+] Fish order: 13, 3, 4, 7, 10, 11, gives MD5 sum: d7df5b228aa4fd7fc68e384964020868
    [+] Fish order: 13, 3, 4, 7, 11, 10, gives MD5 sum: 25cec08b7640f2d95032c8964c828cc1
    [+] Fish order: 13, 3, 4, 10, 7, 11, gives MD5 sum: 94e844df91543cb88ddcf7ad19362984
    [+] Fish order: 13, 3, 4, 10, 11, 7, gives MD5 sum: e159133b08d1d6027ff3597765458c9e
    [+] Fish order: 13, 3, 4, 11, 7, 10, gives MD5 sum: 0cfe5503c3e9c1a345a3687a2e09b525
    [+] Fish order: 13, 3, 4, 11, 10, 7, gives MD5 sum: da308fdf7dc8b1e43e31aec31800ed89
    [+] Fish order: 13, 4, 3, 7, 10, 11, gives MD5 sum: 599037cf4c1da55a64409e1830f665d5
    [+] Fish order: 13, 4, 3, 7, 11, 10, gives MD5 sum: 0837a4e70d33123b30d4d1835772b502
    [+] Fish order: 13, 4, 3, 10, 7, 11, gives MD5 sum: 47abdc8dd7d02b9f73c4fbf3e4b27457
    [+] Fish order: 13, 4, 3, 10, 11, 7, gives MD5 sum: 7bc288f7ef00bdbdb89c5984c0695073
    [+] Fish order: 13, 4, 3, 11, 7, 10, gives MD5 sum: 6e0d1247adcbc8c1ed09317862fffb84
    [+] Fish order: 13, 4, 3, 11, 10, 7, gives MD5 sum: 0e0070f833493063253662d33bed5283
    [+] Fish order: 4, 3, 13, 7, 10, 11, gives MD5 sum: d7190a0db3112d7e1dc804d1f291e840
    [+] Fish order: 4, 3, 13, 7, 11, 10, gives MD5 sum: 40c41e43f3809d0d2e46b465b4e86f14
    [+] Fish order: 4, 3, 13, 10, 7, 11, gives MD5 sum: 33ff768d634e3c47af114c53a3d43440
    [+] Fish order: 4, 3, 13, 10, 11, 7, gives MD5 sum: 77ec26a38a3bf393ba8b1346d00ec6fa
    [+] Fish order: 4, 3, 13, 11, 7, 10, gives MD5 sum: 6c5215b12a10e936f8de1e42083ba184
    [+] Hash found! Flag is: b's1gn_my_gu357_b00k@flare-on.com'
'''
# ----------------------------------------------------------------------------------------

