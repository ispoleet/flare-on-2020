## Flare-On 2020 - #2 garbage
___

### Description: 

*One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted. We would fix it but we are too busy solving today's most important information security threats affecting our global economy. You should be able to get it working again, reverse engineer it, and acquire the flag.*

`*7zip password: flare`

___


### Solution:

A quick look at the binary shows that it's packed with UPX. However we cannot unpack it:
```
ispo@ispo-glaptop:~/ctf/flare_on/2_garbage/garbage$ upx -d garbage.exe 
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: garbage.exe: OverlayException: invalid overlay size; file is possibly corrupt

Unpacked 1 file: 0 ok, 1 error.
```

Altering the UPX header to thwart the unpacking process, is a common trick used in malware.
Our goal is to "fix" the header. First of all we look into the PE header to figure out what
was corrupted:
```
https://manalyzer.org/report/cb85617125124f3fc945c7f375349de3
```

There are 3 sections: `UPX0`, `UPX1` and `.rsrc`. The problem is with the last section
which is located at the end of the file: It has a `SizeOfRawData = 0x400` but not all
bytes are present:
```
ispo@ispo-glaptop:~/ctf/flare_on/2_garbage$ hexdump -C garbage.exe | tail -n 20
00009e00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 01 00  |................|
00009e10  18 00 00 00 18 00 00 80  00 00 00 00 00 00 00 00  |................|
00009e20  00 00 00 00 00 00 01 00  01 00 00 00 30 00 00 80  |............0...|
00009e30  00 00 00 00 00 00 00 00  00 00 00 00 00 00 01 00  |................|
00009e40  09 04 00 00 48 00 00 00  5c 90 01 00 7d 01 00 00  |....H...\...}...|
00009e50  00 00 00 00 00 00 00 00  60 50 01 00 3c 3f 78 6d  |........`P..<?xm|
00009e60  6c 20 76 65 72 73 69 6f  6e 3d 27 31 2e 30 27 20  |l version='1.0' |
00009e70  65 6e 63 6f 64 69 6e 67  3d 27 55 54 46 2d 38 27  |encoding='UTF-8'|
00009e80  20 73 74 61 6e 64 61 6c  6f 6e 65 3d 27 79 65 73  | standalone='yes|
00009e90  27 3f 3e 0d 0a 3c 61 73  73 65 6d 62 6c 79 20 78  |'?>..<assembly x|
00009ea0  6d 6c 6e 73 3d 27 75 72  6e 3a 73 63 68 65 6d 61  |mlns='urn:schema|
00009eb0  73 2d 6d 69 63 72 6f 73  6f 66 74 2d 63 6f 6d 3a  |s-microsoft-com:|
00009ec0  61 73 6d 2e 76 31 27 20  6d 61 6e 69 66 65 73 74  |asm.v1' manifest|
00009ed0  56 65 72 73 69 6f 6e 3d  27 31 2e 30 27 3e 0d 0a  |Version='1.0'>..|
00009ee0  20 20 3c 74 72 75 73 74  49 6e 66 6f 20 78 6d 6c  |  <trustInfo xml|
00009ef0  6e 73 3d 22 75 72 6e 3a  73 63 68 65 6d 61 73 2d  |ns="urn:schemas-|
00009f00  6d 69 63 72 6f 73 6f 66  74 2d 63 6f 6d 3a 61 73  |microsoft-com:as|
00009f10  6d 2e 76 33 22 3e 0d 0a  20 20 20 20 3c 73 65 63  |m.v3">..    <sec|
00009f20  75 72 69 74                                       |urit|
``` 

This justifies the `invalid overlay size` exception that UPX throws.
There are a few ways to fix this. One approach is to fix the size of `.rsrc`
section, but we'll do a simpler approach: *We will keep appending bytes at
the end of the file, until unpacking is successfull*.

```bash
for ((i=1; i<1024; i++))
do 
    echo "================ $i =================="
    cp garbage.exe garbage_tmp.exe
    echo -ne "$(seq -sa $i |tr -d '[:digit:]')\0" >> garbage_tmp.exe
    upx -d garbage_tmp.exe
    if [ $? -eq 0 ]
    then
        echo 'Found!'
        break
    fi
done
```

The only caveat here is that the section **must** end with a NULL byte. We run the script 
and after a while we hit the right value (`732`):
```
================ 731 ==================
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: garbage_tmp.exe: OverlayException: invalid overlay size; file is possibly corrupt

Unpacked 1 file: 0 ok, 1 error.
================ 732 ==================
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     79360 <-     41472   52.26%    win32/pe     garbage_tmp.exe

Unpacked 1 file.
Found!
```

Then we load the unpacked file into IDA. Decompiled code is quite and after some
renaming we can easily follow what is happening:
```C
int __cdecl main(int argc, const char **argv, const char **envp) {
  key_2[0] = 0x2C332323;
  key_2[1] = 0x49643F0E;
  strcpy(
    cipher_2,
    "nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw ");
  key_2[2] = 0x40A1E0A;
  key_2[3] = 0x1A021623;
  key_2[4] = 0x24086644;
  strcpy(
    cipher_1,
    "KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDH ");
  key_2[5] = 0x2C741132;
  key_2[6] = 0xF422D2A;
  key_2[7] = 0xD64503E;
  key_2[8] = 0x171B045D;
  key_2[9] = 0x5033616;
  key_2[10] = 0x8092034;
  key_2[11] = 0xE242163;
  key_2[12] = 0x58341415;
  key_2[13] = 0x3A79291A;
  key_2[14] = 0x58560000;
  v13 = 0x54;
  key_1[0] = 0x3B020E38;
  key_1[1] = 0x341B3B19;
  key_1[2] = 0x3E230C1B;
  key_1[3] = 0x42110833;
  key_1[4] = 0x731E1239;
  stream_cipher_1_401000(lpFileName, (int)key_1, 20, (int)cipher_1, 0);
  v3 = CreateFileA(lpFileName[0], 0x40000000u, 2u, 0, 2u, 0x80u, 0);
  stream_cipher_2_401045(lpFileName);
  if ( v3 != (HANDLE)-1 )
  {
    NumberOfBytesWritten = 0;
    stream_cipher_1_401000(lpFileName, (int)key_2, 61, (int)cipher_2, v4);
    WriteFile(v3, lpFileName[0], 0x3Du, &NumberOfBytesWritten, 0);
    stream_cipher_2_401045(lpFileName);
    CloseHandle(v3);
    stream_cipher_1_401000(lpFileName, (int)key_1, 20, (int)cipher_1, v5);
    ShellExecuteA(0, 0, lpFileName[0], 0, 0, 0);
    stream_cipher_2_401045(lpFileName);
  }
  v6 = GetCurrentProcess();
  TerminateProcess(v6, 0xFFFFFFFF);
  return 0;
}
```

Functions `stream_cipher_1_401000` and `stream_cipher_2_401045` are just stream
ciphers that XOR the ciphertext and the key:
```C
_DWORD *__thiscall sub_401000(_DWORD *this, int a2, int a3, int a4, int a5) {
  v5 = 0;
  *this = a2;
  this[1] = a3;
  this[2] = a4;
  for ( this[3] = 102; v5 < this[1]; ++v5 )
    *(_BYTE *)(*this + v5) ^= *(_BYTE *)(v5 % this[3] + this[2]);
  return this;
}

char __thiscall stream_cipher_2_401045(_DWORD *this) {
  for ( i = 0; i < this[1]; ++i ) {
    result = *(_BYTE *)(i % this[3] + this[2]);
    *(_BYTE *)(*this + i) ^= result;
  }
  return result;
}
```

All we have to do is to XOR the ciphertexts with the keys:
```python
cipher_1 = "KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDH"
cipher_2 = "nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw"

key_1 = [0x38, 0x0E, 0x02, 0x3B, 0x19, 0x3B, 0x1B, 0x34, 0x1B, 0x0C, 0x23, 0x3E, 0x33, 0x08, 0x11, 0x42,
         0x39, 0x12, 0x1E, 0x73]
key_2 = [0x23, 0x23, 0x33, 0x2C, 0x0E, 0x3F, 0x64, 0x49, 0x0A, 0x1E, 0x0A, 0x04, 0x23, 0x16, 0x02, 0x1A,
         0x44, 0x66, 0x08, 0x24, 0x32, 0x11, 0x74, 0x2C, 0x2A, 0x2D, 0x42, 0x0F, 0x3E, 0x50, 0x64, 0x0D,
         0x5D, 0x04, 0x1B, 0x17, 0x16, 0x36, 0x03, 0x05, 0x34, 0x20, 0x09, 0x08, 0x63, 0x21, 0x24, 0x0E,
         0x15, 0x14, 0x34, 0x58, 0x1A, 0x29, 0x79, 0x3A, 0x00, 0x00, 0x56, 0x58, 0x54]

plain_1 = ''.join(chr(ord(cipher_1[i]) ^ key_1[i % len(key_1)]) for i in xrange(len(cipher_1)))
plain_2 = ''.join(chr(ord(cipher_2[i]) ^ key_2[i % len(key_2)]) for i in xrange(len(cipher_2)))
```

Which gives us the following plaintexts:
```
In [6]: plain_1
Out[6]: 'sink_the_tanker.vbs\x00\\BF~IvIcyAgDD`U\x05vko2SXOioUYQRgSdz`W8WeH\nThhIrJkFY\\bZc}p+o}H\x06__CW`tJeotap@\\u\x12cuZ;'

In [7]: plain_2
Out[7]: 'MsgBox("Congrats! Your key is: C0rruptGarbag3@flare-on.com")\x00eREn]t\x00\x1cGsimR]Q]\x1e\x07gWeR\'CpA!FR)5}\x12sptWQt'
```

Which give us the flag: `C0rruptGarbag3@flare-on.com`

___

