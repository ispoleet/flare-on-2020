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
    print('[+] Pet The Kitty unpack started.')

    alt = 0
    i  = 0
    with open('file_2.patch', 'rb') as fp:
        bufin = fp.read()

    bufout = crack_chunk(bufin)

    with open('stage_1.dll', 'wb') as fp:
        fp.write(bufout)

# ----------------------------------------------------------------------------------------
'''
C:\Users\ispol\Desktop\reversing\06_PetTheKitty>python petthekitty_unpack.py
[+] Pet The Kitty unpack started.
Patch applied Successfully: 3ac740320e922781059f1ebd47934916ad93a03e2eb68bdfc2bcc1695c66b2c9
'''
# ----------------------------------------------------------------------------------------

