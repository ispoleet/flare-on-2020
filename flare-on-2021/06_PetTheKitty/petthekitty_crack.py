#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 6 - Pet The Kitty
#
# Code is based on: 
# https://github.com/ritsec/RITSEC-CTF-2019/blob/master/Misc/patch-tuesday/delta_patch.py
# ---------------------------------------------------------------------------------------- 
import struct
import hashlib
from ctypes import (windll, wintypes, c_uint64, cast, POINTER, Union, c_ubyte,
                    LittleEndianStructure, byref, c_size_t)

DELTA_FLAG_TYPE = c_uint64
DELTA_FLAG_NONE = 0x00000000

class DELTA_INPUT(LittleEndianStructure):
    class U1(Union):
        _fields_ = [('lpcStart', wintypes.LPVOID), ('lpStart', wintypes.LPVOID)]

    _anonymous_ = ('u1',)
    _fields_ = [('u1', U1), ('uSize', c_size_t), ('Editable', wintypes.BOOL)]

class DELTA_OUTPUT(LittleEndianStructure):
    _fields_ = [('lpStart', wintypes.LPVOID), ('uSize', c_size_t)]

ApplyDeltaB = windll.msdelta.ApplyDeltaB
ApplyDeltaB.argtypes = [DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT, POINTER(DELTA_OUTPUT)]
ApplyDeltaB.rettype = wintypes.BOOL
DeltaFree = windll.msdelta.DeltaFree
DeltaFree.argtypes = [wintypes.LPVOID]
DeltaFree.rettype = wintypes.BOOL


# ----------------------------------------------------------------------------------------
def apply_patchfile_to_buffer(buf, buflen, patch_contents):
    dd = DELTA_INPUT()
    ds = DELTA_INPUT()
    dout = DELTA_OUTPUT()

    ds.lpcStart = buf
    ds.uSize = buflen
    ds.Editable = False

    dd.lpcStart = cast(patch_contents, wintypes.LPVOID)
    dd.uSize = len(patch_contents)
    dd.Editable = False

    status = ApplyDeltaB(DELTA_FLAG_NONE, ds, dd, byref(dout))
    if status == 0:
        raise Exception("Patch {} failed".format(patchpath))

    return (dout.lpStart, dout.uSize)


# ----------------------------------------------------------------------------------------
def crack_chunk(data):
    source_buf = open('file_1.png', 'rb').read()
    source_buf_lpvoid = cast(source_buf, wintypes.LPVOID)
    n = len(source_buf)    
    to_free = []
    buf, n = apply_patchfile_to_buffer(source_buf_lpvoid, n, data)
    to_free.append(buf)
    bufout = bytes((c_ubyte*n).from_address(buf))

    for buf in to_free: DeltaFree(buf)

    print('Patch applied Successfully:', (hashlib.sha256(bufout).hexdigest()))
    
    return bufout
    

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Pet The Kitty crack started.')

    alt = 0
    i  = 0
    with open('tcp_stream_2.raw', 'rb') as fp:
        # Crack all chunks one by one.
        while True:
            magic = fp.read(4)
            if not magic: break

            assert(magic == b'ME0W')    
            patched_size = struct.unpack('<L', fp.read(4))[0]
            size = struct.unpack('<L', fp.read(4))[0]
            data = fp.read(size)
            
            print('[+] Reading chunk #%-2d: %s ~> 0x%X' % (i, 'client' if alt == 0 else 'server', patched_size))

            # We only get the first `patched_size` bytes.
            bufout = crack_chunk(data)[:patched_size]
            
            # Decrypt.
            cmd = [chr((d) ^ ord('meoow'[i % 5])) for i,d  in enumerate(bufout)]
            print(''.join(cmd))
            
            alt ^= 1            
            if alt == 0: 
                print('='*80)    
                i+=1

# ----------------------------------------------------------------------------------------
'''
C:\Users\ispol\Desktop\reversing\06_PetTheKitty>python petthekitty_crack.py
[+] Pet The Kitty crack started.
[+] Reading chunk #0 : client ~> 0x8B
Patch applied Successfully: 5a0cdbb7ee5e954c8bc356fe4241ae25e5f5a9719ef2ebbb1d0445c23457faff
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\user\Desktop\SuperSecret>
[+] Reading chunk #0 : server ~> 0x9
Patch applied Successfully: 14ede9a87f911654a2de3c9785991ac1281151e89572e1dc8ec906a772fcccd7
whoami

================================================================================
[+] Reading chunk #1 : client ~> 0x3A
Patch applied Successfully: 8d87f0df6dbff5c4f7bf57c440d3cfb827cd9c2d552b7b74ccc7e1666f110135
whoami
user-pc\user

C:\Users\user\Desktop\SuperSecret>
[+] Reading chunk #1 : server ~> 0xB
Patch applied Successfully: 3e4513ea36a82fb783d814a971ac4fdd2f5be298cb5800e2b07a368025cf937a
net user

================================================================================
[+] Reading chunk #2 : client ~> 0x114
Patch applied Successfully: 088e14a3b1b3ccbbb2f910f89badbaf4e5535ec1540ffeb88a5c98a6fa9c7a33
net user

User accounts for \\USER-PC

-------------------------------------------------------------------------------
Administrator            Guest                    user
The command completed successfully.


C:\Users\user\Desktop\SuperSecret>
[+] Reading chunk #2 : server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #3 : client ~> 0x201
Patch applied Successfully: f3684110ec761b668748269b10c0ff8d4b522600834176a579532b90d35783a5
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret

09/02/2021  11:51 PM    <DIR>          .
09/02/2021  11:51 PM    <DIR>          ..
07/23/2021  03:32 PM    <DIR>          2021_FlareOn
09/02/2021  11:51 PM         1,438,208 PetTheKitty.jpg
09/02/2021  11:34 PM           205,312 PurrMachine.exe
               2 File(s)      1,643,520 bytes
               3 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret>
[+] Reading chunk #3 : server ~> 0x12
Patch applied Successfully: ad83d9849892a5ef98b8f7426f943347ac63c848b3ca523fc3d231e1e6402398
cd 2021_FlareOn

================================================================================
[+] Reading chunk #4 : client ~> 0x42
Patch applied Successfully: b12aca7b871f1bd268abb89c863ff333b38c486052b0107052a52214b1fa6ca9
cd 2021_FlareOn

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #4 : server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #5 : client ~> 0x324
Patch applied Successfully: 0dee48cb5eef6006e1ce9d6e0ecfac4ecfa07e99b41120fbc9afb56a9e93fbe0
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn

07/23/2021  03:32 PM    <DIR>          .
07/23/2021  03:32 PM    <DIR>          ..
09/02/2021  11:44 PM    <DIR>          Cat_Memes
09/02/2021  11:47 PM    <DIR>          Great_Ideas
07/23/2021  03:18 PM    <DIR>          Never
09/02/2021  11:44 PM    <DIR>          No_Flags_Here
09/02/2021  11:45 PM    <DIR>          NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS
09/02/2021  11:47 PM    <DIR>          Okay_Ideas
09/02/2021  11:47 PM    <DIR>          Swag
09/02/2021  11:47 PM    <DIR>          The_BEST_Ideas
               0 File(s)              0 bytes
              10 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #5 : server ~> 0xF
Patch applied Successfully: 6b712c161ec574db0c371d92c6d3e6337a99f3430f21ead70c104b4887df4142
cd Cat_Memes

================================================================================
[+] Reading chunk #6 : client ~> 0x49
Patch applied Successfully: 44fcc3f0fc1bde03647bcbaa974e83c061eb554e07c0c41b995dfed49255702e
cd Cat_Memes

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes>
[+] Reading chunk #6 : server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #7 : client ~> 0x1BB
Patch applied Successfully: 6df7735870011a48ee035aa7748078d3961516a5855010f7938642e209d1de66
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes

09/02/2021  11:44 PM    <DIR>          .
09/02/2021  11:44 PM    <DIR>          ..
09/02/2021  11:44 PM                64 (eow.txt
               1 File(s)             64 bytes
               2 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes>
[+] Reading chunk #7 : server ~> 0x10
Patch applied Successfully: 21a7287ffd3f40b0f7cc066eee15c05c6f156ef5a119fff902752fd43ccb9954
type (eow.txt

================================================================================
[+] Reading chunk #8 : client ~> 0x8A
Patch applied Successfully: ffd72012a0ac0793add4652eebd9d835539d7db45fdbc9355f80e194b9d3c370
type (eow.txt
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes>
[+] Reading chunk #8 : server ~> 0x8
Patch applied Successfully: a1976b39d5e170e0877dbc3c763cf58feac64179b1626e7344847bc7b21f444f
cd ..

================================================================================
[+] Reading chunk #9 : client ~> 0x38
Patch applied Successfully: 48e1288073685631a644f01a57a17c2338296844d5fd5a5d6d7fa443b8721def
cd ..

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #9 : server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #10: client ~> 0x324
Patch applied Successfully: 0dee48cb5eef6006e1ce9d6e0ecfac4ecfa07e99b41120fbc9afb56a9e93fbe0
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn

07/23/2021  03:32 PM    <DIR>          .
07/23/2021  03:32 PM    <DIR>          ..
09/02/2021  11:44 PM    <DIR>          Cat_Memes
09/02/2021  11:47 PM    <DIR>          Great_Ideas
07/23/2021  03:18 PM    <DIR>          Never
09/02/2021  11:44 PM    <DIR>          No_Flags_Here
09/02/2021  11:45 PM    <DIR>          NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS
09/02/2021  11:47 PM    <DIR>          Okay_Ideas
09/02/2021  11:47 PM    <DIR>          Swag
09/02/2021  11:47 PM    <DIR>          The_BEST_Ideas
               0 File(s)              0 bytes
              10 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #10: server ~> 0x13
Patch applied Successfully: 8791f5e8146ce7f6b56a83ecf5b449c02b66149cc1c44045909eb93898f5f929
cd No_Flags_Here

================================================================================
[+] Reading chunk #11: client ~> 0x51
Patch applied Successfully: f0b965d813855175fb3d406da9b86b2e0ab0e5cfaa39397a3078a0318a88f049
cd No_Flags_Here

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here>
[+] Reading chunk #11: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #12: client ~> 0x203
Patch applied Successfully: 7603a8dea1703d6349d7cd8d05d13206c1c1d700954079180b26f78284e993f6
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here

09/02/2021  11:44 PM    <DIR>          .
09/02/2021  11:44 PM    <DIR>          ..
09/02/2021  11:44 PM                64 meow.txt
07/23/2021  03:26 PM             1,658 what_did_you_expect.txt
               2 File(s)          1,722 bytes
               2 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here>
[+] Reading chunk #12: server ~> 0x1F
Patch applied Successfully: 81eba7a5102ce0d142e51654ed0a1d33739114b5778c65399120a071564f15ea
type what_did_you_expect.txt

================================================================================
[+] Reading chunk #13: client ~> 0x6D7
Patch applied Successfully: ead8df2996a5c4a53e1bf3c37ac55f4b4944bacb52685c988b0bcf2703d8bbd0
type what_did_you_expect.txt
                          oooo$$$$$$$$$$$$oooo
                      oo$$$$$$$$$$$$$$$$$$$$$$$$o
                   oo$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o         o$   $$ o$
   o $ oo        o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o       $$ $$ $$o$
oo $ $ "$      o$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$o       $$$o$$o$
"$$$$$$o$     o$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$o    $$$$$$$$
  $$$$$$$    $$$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$$$$$$$$$$$$$$
  $$$$$$$$$$$$$$$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$$$$$$  """$$$
   "$$$""""$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     "$$$
    $$$   o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     "$$$o
   o$$"   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$       $$$o
   $$$    $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" "$$$$$$ooooo$$$$o
  o$$$oooo$$$$$  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$   o$$$$$$$$$$$$$$$$$
  $$$$$$$$"$$$$   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     $$$$""""""""
 """"       $$$$    "$$$$$$$$$$$$$$$$$$$$$$$$$$$$"      o$$$
            "$$$o     """$$$$$$$$$$$$$$$$$$"$$"         $$$
              $$$o          "$$""$$$$$$""""           o$$$
               $$$$o                 oo             o$$$"
                "$$$$o      o$$$$$$o"$$$$o        o$$$$
                  "$$$$$oo     ""$$$$o$$$$$o   o$$$$""
                     ""$$$$$oooo  "$$$o$$$$$$$$$"""
                        ""$$$$$$$oo $$$$$$$$$$
                                """"$$$$$$$$$$$
                                    $$$$$$$$$$$$
                                     $$$$$$$$$$"
                                      "$$$""""

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here>
[+] Reading chunk #13: server ~> 0x10
Patch applied Successfully: 21a7287ffd3f40b0f7cc066eee15c05c6f156ef5a119fff902752fd43ccb9954
type (eow.txt

================================================================================
[+] Reading chunk #14: client ~> 0x8E
Patch applied Successfully: e4b4dd4acd1792632b78cbb6ac37bafff18d41f66ee38d1c42fc2fe42a256744
type (eow.txt
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here>
[+] Reading chunk #14: server ~> 0x8
Patch applied Successfully: a1976b39d5e170e0877dbc3c763cf58feac64179b1626e7344847bc7b21f444f
cd ..

================================================================================
[+] Reading chunk #15: client ~> 0x38
Patch applied Successfully: 48e1288073685631a644f01a57a17c2338296844d5fd5a5d6d7fa443b8721def
cd ..

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #15: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #16: client ~> 0x324
Patch applied Successfully: 0dee48cb5eef6006e1ce9d6e0ecfac4ecfa07e99b41120fbc9afb56a9e93fbe0
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn

07/23/2021  03:32 PM    <DIR>          .
07/23/2021  03:32 PM    <DIR>          ..
09/02/2021  11:44 PM    <DIR>          Cat_Memes
09/02/2021  11:47 PM    <DIR>          Great_Ideas
07/23/2021  03:18 PM    <DIR>          Never
09/02/2021  11:44 PM    <DIR>          No_Flags_Here
09/02/2021  11:45 PM    <DIR>          NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS
09/02/2021  11:47 PM    <DIR>          Okay_Ideas
09/02/2021  11:47 PM    <DIR>          Swag
09/02/2021  11:47 PM    <DIR>          The_BEST_Ideas
               0 File(s)              0 bytes
              10 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #16: server ~> 0x2A
Patch applied Successfully: aed315518d94bdca51a66cd5ce48bf025f7b6d2154063e7af062bf653b7fcd69
cd NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS

================================================================================
[+] Reading chunk #17: client ~> 0x7F
Patch applied Successfully: 4f6fd1f31bd06c5496845d565816fd625b0b52da45282d58bf66a24f2da6b0c1
cd NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS>
[+] Reading chunk #17: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #18: client ~> 0x1F1
Patch applied Successfully: d626d357ab9d12ec024b3c4be29dbf5af279d8c34d42b8cf91d46e3ba70509ef
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS

09/02/2021  11:45 PM    <DIR>          .
09/02/2021  11:45 PM    <DIR>          ..
09/02/2021  11:44 PM                64 meow.txt
               1 File(s)             64 bytes
               2 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS>
[+] Reading chunk #18: server ~> 0x10
Patch applied Successfully: 21a7287ffd3f40b0f7cc066eee15c05c6f156ef5a119fff902752fd43ccb9954
type (eow.txt

================================================================================
[+] Reading chunk #19: client ~> 0xA5
Patch applied Successfully: 8c1d9a5f7b5cc4ba613ffb38c2720964f613a858f77260e8323cc402ae9a83ad
type (eow.txt
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS>
[+] Reading chunk #19: server ~> 0x8
Patch applied Successfully: a1976b39d5e170e0877dbc3c763cf58feac64179b1626e7344847bc7b21f444f
cd ..

================================================================================
[+] Reading chunk #20: client ~> 0x38
Patch applied Successfully: 48e1288073685631a644f01a57a17c2338296844d5fd5a5d6d7fa443b8721def
cd ..

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #20: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #21: client ~> 0x324
Patch applied Successfully: 0dee48cb5eef6006e1ce9d6e0ecfac4ecfa07e99b41120fbc9afb56a9e93fbe0
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn

07/23/2021  03:32 PM    <DIR>          .
07/23/2021  03:32 PM    <DIR>          ..
09/02/2021  11:44 PM    <DIR>          Cat_Memes
09/02/2021  11:47 PM    <DIR>          Great_Ideas
07/23/2021  03:18 PM    <DIR>          Never
09/02/2021  11:44 PM    <DIR>          No_Flags_Here
09/02/2021  11:45 PM    <DIR>          NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS
09/02/2021  11:47 PM    <DIR>          Okay_Ideas
09/02/2021  11:47 PM    <DIR>          Swag
09/02/2021  11:47 PM    <DIR>          The_BEST_Ideas
               0 File(s)              0 bytes
              10 Dir(s)  32,587,169,792 bytes free

C:\Users\user\Desktop\SuperSecret\2021_FlareOn>
[+] Reading chunk #21: server ~> 0x3B
Patch applied Successfully: 2c0128d401848ff23f080e9a35eaa487983d8d2f641554a963431ef0e2eb5762
@echo off & for /f %a in ('dir /s /b') do echo %~fa %~za

================================================================================
[+] Reading chunk #22: client ~> 0x84E
Patch applied Successfully: 55b80487310d0cf59763c1cce8570df900cc8ec897a4dd3da6da8fabdab69864
@echo off & for /f %a in ('dir /s /b') do echo %~fa %~za
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Great_Ideas 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Okay_Ideas 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Swag 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\The_BEST_Ideas 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Cat_Memes\(eow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Great_Ideas\meow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\FlagPit 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\Gotcha.txt 1806
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\(eow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\The_Real_Challenge 0
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\FlagPit\(e0000000w.txt 812
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\The_Real_Challenge\Mugatuware.exe 1532928
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\The_Real_Challenge\mydude.exe 650105
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here\meow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\No_Flags_Here\what_did_you_expect.txt 1658
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\NO_SERIOUSLY_EVEN_MORE_BESTEST_IDEAS\meow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Okay_Ideas\meow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Swag\meow.txt 64
C:\Users\user\Desktop\SuperSecret\2021_FlareOn\The_BEST_Ideas\meow.txt 64

[+] Reading chunk #22: server ~> 0x1D
Patch applied Successfully: aeefd99d633cb7b60fa0f12d6361f8e4537c1509bc0fcc1c7a72174bdd250cdf
cd Never\Gonna\Give\You\Up

================================================================================
[+] Reading chunk #23: client ~> 0x1C
Patch applied Successfully: 1bec9a352261ddb70f5fd9b3732e7c0666fe18f19e2019490b1426b15e61a818
cd Never\Gonna\Give\You\Up

[+] Reading chunk #23: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #24: client ~> 0x22C
Patch applied Successfully: f581a90ee0e3e556c7efe5baca2a7e3ea0c513f3a499654d370e954d3686f77b
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up

09/02/2021  11:48 PM    <DIR>          .
09/02/2021  11:48 PM    <DIR>          ..
09/02/2021  11:49 PM    <DIR>          FlagPit
07/23/2021  03:19 PM             1,806 Gotcha.txt
09/02/2021  11:44 PM                64 meow.txt
09/02/2021  11:49 PM    <DIR>          The_Real_Challenge
               2 File(s)          1,870 bytes
               4 Dir(s)  32,587,169,792 bytes free

[+] Reading chunk #24: server ~> 0x12
Patch applied Successfully: d782ddd84ae56f7d39d6c0c2bc8f7dca3f51eb8d99752319c76df78e9f840c0b
type Gotcha.txt

================================================================================
[+] Reading chunk #25: client ~> 0x71F
Patch applied Successfully: 1a0a404e4055c4d2ba75ef801af5fbb63df2cc48f08d70b9e15e24518587fe46
type Gotcha.txt
We're no strangers to love
You know the rules and so do I
A full commitment's what I'm thinking of
You wouldn't get this from any other guy
I just wanna tell you how I'm feeling
Gotta make you understand
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
We've known each other for so long
Your heart's been aching but you're too shy to say it
Inside we both know what's been going on
We know the game and we're gonna play it
And if you ask me how I'm feeling
Don't tell me you're too blind to see
1m_H3rE_Liv3_1m_n0t_a_C4t@flare-on.com
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
We've known each other for so long
Your heart's been aching but you're too shy to say it
Inside we both know what's been going on
We know the game and we're gonna play it
I just wanna tell you how I'm feeling
Gotta make you understand
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
Never gonna give you up, never gonna let you down
Never gonna run around and desert you
Never gonna make you cry, never gonna say goodbye
Never gonna tell a lie and hurt you
[+] Reading chunk #25: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #26: client ~> 0x22C
Patch applied Successfully: f581a90ee0e3e556c7efe5baca2a7e3ea0c513f3a499654d370e954d3686f77b
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up

09/02/2021  11:48 PM    <DIR>          .
09/02/2021  11:48 PM    <DIR>          ..
09/02/2021  11:49 PM    <DIR>          FlagPit
07/23/2021  03:19 PM             1,806 Gotcha.txt
09/02/2021  11:44 PM                64 meow.txt
09/02/2021  11:49 PM    <DIR>          The_Real_Challenge
               2 File(s)          1,870 bytes
               4 Dir(s)  32,587,169,792 bytes free

[+] Reading chunk #26: server ~> 0xD
Patch applied Successfully: 6e25f31e5af99a757fbf873602f0fe3b3544ee6b9ddd7354f41d13e5a75f677f
cd FlagPit

================================================================================
[+] Reading chunk #27: client ~> 0xC
Patch applied Successfully: bdec324364e6046ed0c98650a7ab02602f704a10efb0f3b1afe4a7dfdf6a76d6
cd FlagPit

[+] Reading chunk #27: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #28: client ~> 0x19C
Patch applied Successfully: 5e9a7d0de9be05bf8de54d6eb88b3c5c4ab977ff07915074c04fd3bc55d6e4c7
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\FlagPit

09/02/2021  11:49 PM    <DIR>          .
09/02/2021  11:49 PM    <DIR>          ..
09/02/2021  11:50 PM               812 me0000000w.txt
               1 File(s)            812 bytes
               2 Dir(s)  32,587,169,792 bytes free

[+] Reading chunk #28: server ~> 0x16
Patch applied Successfully: ff220ede7dcab239758718fbcce1a6fda916f74e186f9e57ecfe85861a6f50a4
type me0000000w.txt

================================================================================
[+] Reading chunk #29: client ~> 0x341
Patch applied Successfully: c2cc200b5d9a720f73e673a7c4625b707fadd189c349e7626a1bf03234688e22
type me0000000w.txt
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
[+] Reading chunk #29: server ~> 0x8
Patch applied Successfully: a1976b39d5e170e0877dbc3c763cf58feac64179b1626e7344847bc7b21f444f
cd ..

================================================================================
[+] Reading chunk #30: client ~> 0x7
Patch applied Successfully: 484015429b86a1556dab7a1c46654d340644a062d3dde9784fae10541fd1fa15
cd ..

[+] Reading chunk #30: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #31: client ~> 0x22C
Patch applied Successfully: f581a90ee0e3e556c7efe5baca2a7e3ea0c513f3a499654d370e954d3686f77b
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up

09/02/2021  11:48 PM    <DIR>          .
09/02/2021  11:48 PM    <DIR>          ..
09/02/2021  11:49 PM    <DIR>          FlagPit
07/23/2021  03:19 PM             1,806 Gotcha.txt
09/02/2021  11:44 PM                64 meow.txt
09/02/2021  11:49 PM    <DIR>          The_Real_Challenge
               2 File(s)          1,870 bytes
               4 Dir(s)  32,587,169,792 bytes free

[+] Reading chunk #31: server ~> 0x18
Patch applied Successfully: f2d279bff789e1b4075a0bc84c3c024bb3c5c5fe2b0e0fa2779bb5794b2d4b1f
cd The_Real_Challenge

================================================================================
[+] Reading chunk #32: client ~> 0x17
Patch applied Successfully: 4e6d25a36893eb3f314de86f977759af6f8756e1f01e60e6387fa53f1074c0b5
cd The_Real_Challenge

[+] Reading chunk #32: server ~> 0x6
Patch applied Successfully: 0a285ef8a2cd1d2386bdf0eb3d30c6e86e685c4153aebbbf1ec7a65be7182212
dir

================================================================================
[+] Reading chunk #33: client ~> 0x1DA
Patch applied Successfully: c7941edabd38124476cd2ba689983f2ee14334e1dd7f8110d23bd810939194b5
dir
 Volume in drive C has no label.
 Volume Serial Number is 9C63-6ACB

 Directory of C:\Users\user\Desktop\SuperSecret\2021_FlareOn\Never\Gonna\Give\You\Up\The_Real_Challenge

09/02/2021  11:49 PM    <DIR>          .
09/02/2021  11:49 PM    <DIR>          ..
05/01/2019  02:18 PM         1,532,928 Mugatuware.exe
07/27/2020  05:37 PM           650,105 mydude.exe
               2 File(s)      2,183,033 bytes
               2 Dir(s)  32,587,169,792 bytes free

[+] Reading chunk #33: server ~> 0x8
Patch applied Successfully: a1976b39d5e170e0877dbc3c763cf58feac64179b1626e7344847bc7b21f444f
cd ..

================================================================================
[+] Reading chunk #34: client ~> 0x7
Patch applied Successfully: 484015429b86a1556dab7a1c46654d340644a062d3dde9784fae10541fd1fa15
cd ..

[+] Reading chunk #34: server ~> 0x10
Patch applied Successfully: 21a7287ffd3f40b0f7cc066eee15c05c6f156ef5a119fff902752fd43ccb9954
type (eow.txt

================================================================================
[+] Reading chunk #35: client ~> 0x4F
Patch applied Successfully: b9b874fa25cf9412d12e915da391329e353bb245e56944792b77d6ad3748b3ae
type (eow.txt
         ~me0w~
  /\_/\
 ( ^.^ )
 (")_(")_/
[+] Reading chunk #35: server ~> 0x2A
Patch applied Successfully: 81853a1520d079ff483a2d4cad64cbe4ea6df54a083bd64139575a469d3d608b
rundll32.exe user32.dll,LockWorkStation

================================================================================
[+] Reading chunk #36: client ~> 0x29
Patch applied Successfully: 168f47753ce269fae990141b68bfb79240f86c973d35cb0c7b3500051bc55238
rundll32.exe user32.dll,LockWorkStation

[+] Reading chunk #36: server ~> 0x7
Patch applied Successfully: 005b531130e866d418c85c8f3804c97a7582f58d7fe6d2aa4695991739be2131
exit

================================================================================
'''
# ----------------------------------------------------------------------------------------

