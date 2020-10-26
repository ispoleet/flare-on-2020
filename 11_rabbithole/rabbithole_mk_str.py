#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 11 - rabbithole
# --------------------------------------------------------------------------------------------------


# --------------------------------------------------------------------------------------------------
def gen_sid_magic(sid):
    sid = sid.split('-')[1:]                        # drop 'S' and split into parts
    sid = [int(s) for s in sid]                     # convert to list
    # print ['%X' % x for x in sid]

    magic = (sid[4] << 32) + (sum(sid[3:6]) )
    magic ^= (0xEDB88320 << 32) | 0xEDB88320
             
    return magic


# --------------------------------------------------------------------------------------------------
def mk_str(arg1, arg2, sid_magic):
    words = ('old new current version process thread id identity task disk keyboard monitor class '
         'archive drive message link template logic protocol console magic system software '
         'word byte timer window scale info char calc map print list section name lib access '
         'code guid build warning save load region column row language date day false true '
         'screen net info web server client search storage icon desktop mode project media '
         'spell work security explorer cache theme solution').split()

    magic_const = 0x2545F4914F6CDD1D
    string = ''

    for i in range(4):
        A = (sid_magic + ((arg1 + 2*i) & 0xFF)) & 0xFFFFFFFFFFFFFFFF
        B = (A ^ (A >> 0x0C)) & 0xFFFFFFFFFFFFFFFF
        C = (B ^ (B << 0x19)) & 0xFFFFFFFFFFFFFFFF
        D = (C ^ (C >> 0x1B)) & 0xFFFFFFFFFFFFFFFF

        idx = ((D * magic_const) & 0xFFFF) % len(words)
        word = words[idx]

        rcx = ((D * magic_const) >> 32) & 0xFFFFFFFFFFFFFFFF
        if rcx & 1 == 0: word_len = len(word)
        else:            word_len = ((rcx & 0xFFFF) % (len(word) - 1)) + 2
        
        sw = 0x20 if arg2 & (1 << i) else 0
       
        string += chr(ord(words[idx][0]) - sw) + words[idx][1:word_len]

        arg1 >>= 8
        if arg1 == 0: break

    return string


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Rabbithole make string script started.'

    sid = "S-1-5-21-3823548243-3100178540-2044283163-513"
    magic = gen_sid_magic(sid)

    print '[+] SID: %s' % sid
    print '[+] SID magic number: %X' % magic


    # Various string pairs I encountered during my analysis.
    string_pairs = [
        (0x707, 3),
        (0x808, 3),
        (0xB0B, 1),
        (0xC0C, 3),
        (0xF0F, 1),
        (0x1010, 1),
        (0x1111, 3),
        (0x1B1B, 3),
        (0x7F7F, 3),
        (0x8576b0d0, 5),
        (0xd6306e08, 5)
    ]

    for a, b in string_pairs:
        print '[+] Generating string for (0x%-8X, %d) --> %s' % (a, b, mk_str(a, b, magic))

    print '[+] Program finished. Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare_on/11_rabbithole$ ./rabbithole_mk_str.py 
[+] Rabbithole make string script started.
[+] SID: S-1-5-21-3823548243-3100178540-2044283163-513
[+] SID magic number: 55707B4EFB307BFA
[+] Generating string for (0x707     , 3) --> SolutionDat
[+] Generating string for (0x808     , 3) --> WordTimer
[+] Generating string for (0xB0B     , 1) --> Newfalse
[+] Generating string for (0xC0C     , 3) --> VersionSoftware
[+] Generating string for (0xF0F     , 1) --> Languagetheme
[+] Generating string for (0x1010    , 1) --> Columncurrent
[+] Generating string for (0x1111    , 3) --> ThemeDay
[+] Generating string for (0x1B1B    , 3) --> CalTimer
[+] Generating string for (0x7F7F    , 3) --> DiMap
[+] Generating string for (0x8576B0D0, 5) --> WebsoftwareProcesstemplate
[+] Generating string for (0xD6306E08, 5) --> WordlibSystemser
[+] Program finished. Bye bye :)
'''
# --------------------------------------------------------------------------------------------------
