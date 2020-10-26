## Flare-On 2020 - #11 rabbithole
___

### Description: 

*One of our endpoints was infected with a very dangerous, yet unknown malware strain that operates in a fileless manner. The malware is - without doubt - an APT that is the ingenious work of the Cyber Army of the Republic of Kazohinia.*

*One of our experts said that it looks like they took an existing banking malware family, and modified it in a way that it can be used to collect and exfiltrate files from the hard drive.*

*The malware started destroying the disk, but our forensic investigators were able to salvage ones of the files. Your task is to find out as much as you can about the behavior of this malware, and try to find out what was the data that it tried to steal before it started wiping all evidence from the computer.*

*Good luck!*

`7zip password: flare`
___

### Solution:


For the final challenge we are given `NTUSER.DAT`:
```
NTUSER.DAT: MS Windows registry file, NT/2000 or above
```

To parse this file we use [Registry Explorer](https://ericzimmerman.github.io/#!index.md). After some searching
we found a PowerShell script under `HKEY_CURRENT_USER\SOFTWARE\Timerpro` key:
```powershell
[HKEY_CURRENT_USER\SOFTWARE\Timerpro]
;Last write timestamp 2020-07-17T11:15:08.4290564Z
"D"="$jjw=\"kcsukccudy\";

function fromBase64{[System.Convert]::FromBase64String($args[0]);};
[byte[]]$rpl=fromBase64(\"6feZAAA0BgBuMWFe34CyvFBFtRPwA[... LONG BASE64 STRING ...]AAAAAAAAAA\");

function geapmkxsiw{$kjurpkot=fromBase64($args[0]);[System.Text.Encoding]::ASCII.GetString($kjurpkot);};

$cqltd="
[DllImport(`"kernel32`")]`npublic static extern IntPtr GetCurrentThreadId();`n
[DllImport(`"kernel32`")]`npublic static extern IntPtr OpenThread(uint nopeyllax,uint itqxlvpc,IntPtr weo);`n
[DllImport(`"kernel32`")]`npublic static extern uint QueueUserAPC(IntPtr lxqi,IntPtr qlr,IntPtr tgomwjla);`n
[DllImport(`"kernel32`")]`npublic static extern void SleepEx(uint wnhtiygvc,uint igyv);";

$tselcfxhwo=Add-Type -memberDefinition $cqltd -Name 'alw' -namespace eluedve -passthru;

$dryjmnpqj="ffcx";$nayw="
[DllImport(`"kernel32`")]`npublic static extern IntPtr GetCurrentProcess();`n
[DllImport(`"kernel32`")]`npublic static extern IntPtr VirtualAllocEx(IntPtr wasmhqfy,IntPtr htdgqhgpwai,uint uxn,uint mepgcpdbpc,uint xdjp);";

$ywqphsrw=Add-Type -memberDefinition $nayw -Name 'pqnvohlggf' -namespace rmb -passthru;

$jky="epnc";

$kwhk=$tselcfxhwo::OpenThread(16,0,$tselcfxhwo::GetCurrentThreadId());
if($yhibbqw=$ywqphsrw::VirtualAllocEx($ywqphsrw::GetCurrentProcess(),0,$rpl.Length,12288,64))
{
 [System.Runtime.InteropServices.Marshal]::Copy($rpl,0,$yhibbqw,$rpl.length);
 if($tselcfxhwo::QueueUserAPC($yhibbqw,$kwhk,$yhibbqw))
 {
  $tselcfxhwo::SleepEx(5,3);
 }
}
```

With some renaming and cleanup we make the code more readable:
```
"D"="$jjw=\"kcsukccudy\";

function fromBase64{
    [System.Convert]::FromBase64String($args[0]);
};

function str_decode{
    $raw_bytes=fromBase64($args[0]);
    [System.Text.Encoding]::ASCII.GetString($raw_bytes);
};


[byte[]]$shellcode=fromBase64(\"6feZAAA0BgBuMWFe34CyvFBFtRPwA[... LONG BASE64 STRING ...]AAAAAAAAAA\");

$str1="
[DllImport(`"kernel32`")]
public static extern IntPtr GetCurrentThreadId();

[DllImport(`"kernel32`")]
public static extern IntPtr OpenThread(uint dwDesiredAccess, uint bInheritHandle,
                     IntPtr dwThreadId);

[DllImport(`"kernel32`")]
public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

[DllImport(`"kernel32`")]
public static extern void SleepEx(uint dwMilliseconds, uint bAlertable);
";

$class1=Add-Type -memberDefinition $str1 -Name 'alw' -namespace eluedve -passthru;

$dryjmnpqj="ffcx";
$str2="
[DllImport(`"kernel32`")]
public static extern IntPtr GetCurrentProcess();

[DllImport(`"kernel32`")]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize,
                         uint flAllocationType, int flProtect);
";

$class2=Add-Type -memberDefinition $str2 -Name 'pqnvohlggf' -namespace rmb -passthru;

$jky="epnc";

$handle=$class1::OpenThread(16, 0, $class1::GetCurrentThreadId());
if($ptr=$class2::VirtualAllocEx($class2::GetCurrentProcess(),
                       0,
                       $shellcode.Length,
                       12288,
                       PAGE_EXECUTE_READWRITE)) {
    [System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $ptr, $payload.length);
    if($class1::QueueUserAPC($ptr, $handle, $ptr)) {
        $class1::SleepEx(5,3);
    }
}
```

The above code loads and executes some shellcode in memory.


#### Reversing the Shellcode

After some analysis on the shellcode, we found a weird set of words:
```
old new current version process thread id identity task disk keyboard monitor class archive drive
message link template logic protocol console magic system software word byte timer window scale
info char calc map print list section name lib access code guid build warning save load region
column row language date day false true screen net info web server client search storage icon
desktop mode project media spell work security explorer cache theme solution
```

We search for a subset of these words, and we found [this log](https://www.vmray.com/analyses/f812425af9fd/logs/flog.txt)
from 2018. This is quite interesting, as it reveals that we're talking for a known malware
(the sequence that function addresses from `ntdll` are resolved is also the same with the shellcode).
After some more searching we found this shellcode is actually the [Gozi](https://fidelissecurity.com/threatgeek/threat-intelligence/gozi-v3-technical-update)
malware, where its [source code](https://github.com/t3rabyt3-zz/Gozi) is leaked.


**Note:** Shellcode is huge. We will only focus on the important parts that are required to
obtain the flag.

During startup, shellcode uses functions `LdrLoadDll` and `LdrGetProcedureAddress` to
import various Windows functions. Then, it invokes `NtOpenProcessToken` to obtain user SID
and generates a 64-bit value from it as follows:
```assembly
.data:000000013F848B0A         mov     rdx, cs:glo_B_13FA3D580
.data:000000013F848B11         movzx   eax, al
.data:000000013F848B14         xor     r8d, r8d
.data:000000013F848B17         mov     ecx, [rsp+rax*4+78h+var_4C]
.data:000000013F848B1B         mov     [rdx+7Ch], ecx
.data:000000013F848B1E         movzx   eax, [rsp+78h+var_47]
.data:000000013F848B23         sub     eax, 2
.data:000000013F848B26         test    eax, eax
.data:000000013F848B28         jle     short loc_13F848B4A
.data:000000013F848B2A         lea     rcx, [rsp+78h+var_3C]
.data:000000013F848B2F
.data:000000013F848B2F BUILD_HASH_13F7F8B2F:          ; CODE XREF: build_sid_13F528928+220↓j
.data:000000013F848B2F         mov     eax, [rcx]
.data:000000013F848B31         add     r8d, 1
.data:000000013F848B35         add     rcx, 4
.data:000000013F848B39         add     [rdx+78h], rax
.data:000000013F848B3D         movzx   eax, [rsp+78h+var_47]
.data:000000013F848B42         sub     eax, 2
.data:000000013F848B45         cmp     r8d, eax
.data:000000013F848B48         jl      short BUILD_HASH_13F7F8B2F
.data:000000013F848B4A
.data:000000013F848B4A loc_13F848B4A:                 ; CODE XREF: build_sid_13F528928+1E0↑j
.data:000000013F848B4A                       ; build_sid_13F528928+200↑j
.data:000000013F848B4A         mov     eax, 0EDB88320h
.data:000000013F848B4F         lea     rcx, [rdx+80h]          ; lpSystemTimeAsFileTime
.data:000000013F848B56         xor     [rdx+7Ch], eax
.data:000000013F848B59         xor     [rdx+78h], eax
```

We decompile it:
```python
    sid = "S-1-5-21-3823548243-3100178540-2044283163-513"
    sid = sid.split('-')[1:]               # drop 'S' and split into parts
    sid = [int(s) for s in sid]            # convert to list

    magic = (sid[4] << 32) + (sum(sid[3:6]) )
    magic ^= (0xEDB88320 << 32) | 0xEDB88320
```

Obviously, program requires the correct SID to operate. We search on `NTUSER.dat` and
we found the correct (and only) SID:
```
S-1-5-21-3823548243-3100178540-2044283163-513
```

#### Name Generator

Malware uses a name generator, to generate pseudo-random names that are based on the word list
shown above. A pair of integers is used to generate a string. For instance:
```C
regkey_name_1 = j__decode_string_13F8F921C(0xF0Fu, 1u);     // generate --> Languagetheme
```

Pair `(0xF0F, 1)` generates string `Languagetheme` and pair `(0x1010, 1)` generates
string `Columncurrent`. The interesting part is that names are based on the magic value
derived from SID:
```C
__int64 __fastcall j__decode_string_13F8F921C(unsigned int a1, unsigned int a2) {
  v3 = *(glo_B_13FA3D580 + 0x128i64);           // hash derived from SID
  result = 0i64;
  if ( v3 ) result = decode_string_13F8F6B0C(v3, a1, a2);
  return result;
}
```

Function `decode_string_13F8F6B0C` is where generation takes place:
```assembly
.data:000000013F846B0C decode_string_13F8F6B0C proc near       ; CODE XREF: j__decode_string_13F8F921C+22↓p
.....
.data:000000013F846B3C LOOP_13F536B3C:                ; CODE XREF: decode_string_13F8F6B0C+C6↓j
.data:000000013F846B3C         lea     eax, [r11+rbx]          ; eax = arg2 + i
.data:000000013F846B40         movzx   edx, al        ; edx = (arg2 + i) & 0xFF
.data:000000013F846B43         add     rdx, [r10+8]            ; rdx = 0x55707B4EFB307BFA + (arg2  + i) & 0xFF = A
.data:000000013F846B47         mov     rax, rdx
.data:000000013F846B4A         shr     rax, 0Ch                ; rax = A >> 12
.data:000000013F846B4E         xor     rdx, rax                ; rdx = A ^ (A >> 12) = B
.data:000000013F846B51         mov     rax, rdx
.data:000000013F846B54         shl     rax, 19h                ; rax = B << 0x19
.data:000000013F846B58         xor     rdx, rax                ; rdx = B ^ (B << 0x19) = C
.data:000000013F846B5B         mov     rax, 2545F4914F6CDD1Dh
.data:000000013F846B65         mov     rcx, rdx
.data:000000013F846B68         shr     rcx, 1Bh                ; rcx = C >> 0x1B
.data:000000013F846B6C         xor     rcx, rdx                ; rcx = C ^ (C >> 0x1B) = D
.data:000000013F846B6F         xor     edx, edx                ; edx = 0
.data:000000013F846B71         imul    rcx, rax                ; rcx = D * MAGIC
.data:000000013F846B75         movzx   eax, cx
.data:000000013F846B78         shr     rcx, 20h                ; rcx = D * MAGIC >> 32
.data:000000013F846B7C         div     dword ptr [r10+10h]     ; (D * MAGIC) & 0xFFFF % len(words) => (r10+0x10 = len(words))
.data:000000013F846B80         mov     esi, edx
.data:000000013F846B82         add     rsi, rsi                ; rsi = idx * 2
.data:000000013F846B85         test    cl, 1
.data:000000013F846B88         jz      short loc_13F846BA0
.data:000000013F846B8A         movzx   r8d, word ptr [r10+rsi*8+18h] ; read word size
.data:000000013F846B90         movzx   eax, cx        ; eax = (D * MAGIC >> 32) & 0xFFFF
.data:000000013F846B93         sub     r8d, 1
.data:000000013F846B97         cdq
.data:000000013F846B98         idiv    r8d            ; (D * MAGIC >> 32) & 0xFFFF / (len(word) - 1)
.data:000000013F846B9B         add     edx, 2         ; edx = (D * MAGIC >> 32) & 0xFFFF % (len(word) - 1) + 2
.data:000000013F846B9E         jmp     short loc_13F846BA6
.data:000000013F846BA0
.data:000000013F846BA0 loc_13F846BA0:                 ; CODE XREF: decode_string_13F8F6B0C+7C↑j
.data:000000013F846BA0         movzx   edx, word ptr [r10+rsi*8+18h]
.data:000000013F846BA6
.data:000000013F846BA6 loc_13F846BA6:                 ; CODE XREF: decode_string_13F8F6B0C+92↑j
.data:000000013F846BA6         test    r9, r9
.data:000000013F846BA9         jz      short loc_13F846BAE     ; r13 += len(word)
.data:000000013F846BAB         mov     [r9], edx
.data:000000013F846BAE
.data:000000013F846BAE loc_13F846BAE:                 ; CODE XREF: decode_string_13F8F6B0C+9D↑j
.data:000000013F846BAE         add     r13d, [r9]              ; r13 += len(word)
.data:000000013F846BB1         mov     rax, [r10+rsi*8+20h]    ; read word
.data:000000013F846BB6         add     r14d, 1        ; ++j
.data:000000013F846BBA         mov     [rdi], rax              ; add pointer to word
.data:000000013F846BBD         add     r11d, 2        ; i += 2
.data:000000013F846BC1         add     r9, 4
.data:000000013F846BC5         add     rdi, 8         ; next index
.data:000000013F846BC9         shr     ebx, 8         ; arg2 >>= 8
.data:000000013F846BCC         jz      short AFTER_LOOP_13FD46BD8 ; if !arg2 break
.data:000000013F846BCE         cmp     r11d, 8
.data:000000013F846BD2         jb      LOOP_13F536B3C          ; eax = arg2 + i
.data:000000013F846BD8
.data:000000013F846BD8 AFTER_LOOP_13FD46BD8:          ; CODE XREF: decode_string_13F8F6B0C+C0↑j
.....
.data:000000013F846C17 loc_13F846C17:                 ; CODE XREF: decode_string_13F8F6B0C+13B↓j
.data:000000013F846C17         mov     r15d, [rbp+0]
.data:000000013F846C1B         mov     rdx, [r12]              ; _QWORD
.data:000000013F846C1F         mov     rcx, rbx                ; _QWORD
.data:000000013F846C22         mov     r8, r15        ; _QWORD
.data:000000013F846C25         call    cs:mbstowcs
.data:000000013F846C2B         bt      edi, esi                ; check i-th bit
.data:000000013F846C2E         jnb     short NOT_UPPER_13F536C35 ; ++i
.data:000000013F846C30         add     word ptr [rbx], 0FFE0h  ; make 1st character uppercase (-0x20)
.data:000000013F846C35
.data:000000013F846C35 NOT_UPPER_13F536C35:           ; CODE XREF: decode_string_13F8F6B0C+122↑j
.data:000000013F846C35         add     esi, 1         ; ++i
.....
```

The first number is parsed into bytes. Each byte determines which word to select from the word list and how
many characters to select from this word (it selects the first K characters, or all). The second number
determines capitalization of the first letter of each word. For more details on how names are generated,
please take a look at [rabbithole_mk_str.py](./rabbithole_mk_str.py) script.


#### Decrypting Registry Entries

After initialization, program reads and decrypts the following entries from registry:
```
\REGISTRY\USER\S-1-5-21-3823548243-3100178540-2044283163-513\Software\Timerpro\Languagetheme\WebsoftwareProcesstemplate
\REGISTRY\USER\S-1-5-21-3823548243-3100178540-2044283163-513\Software\Timerpro\Columncurrent\WebsoftwareProcesstemplate
```

**Note:** To make our shellcode read and write values from registry, where we can inspect them, we set 
a breakpoint at `0x13FA7EEEF`:
```Assembly
.data:000000013FA7EEB9         mov     rcx, cs:glo_B_13FA3D580
.data:000000013FA7EEC0         mov     [rcx+0F0h], rax
.data:000000013FA7EEC7         mov     [rcx+0E0h], rdi
.data:000000013FA7EECE         mov     [rcx+0E8h], rdi
.data:000000013FA7EED5         lea     r9, [rcx+0D8h]
.data:000000013FA7EEDC         xor     r8d, r8d
.data:000000013FA7EEDF         mov     r13d, 0C0000000h
.data:000000013FA7EEE5         mov     edx, r13d
.data:000000013FA7EEE8         mov     rcx, [rcx+170h]
.data:000000013FA7EEEF         call    create_reg_key_13FA18C94 ; patch SID
.data:000000013FA7EEF4         cmp     eax, edi
.data:000000013FA7EEF6         jge     short loc_13FA7EF02
```

And then we patch it (from IDAPython command line) with the SID of the current machine:
```C
reg_entry = '\\REGISTRY\\USER\\S-1-5-21-335012620-259892110-3672055497-1000\\Software\\Timerpro\x00'
for i in range(len(reg_entry)): idaapi.patch_byte(idaapi.get_reg_val('rcx')+2*i, ord(reg_entry[i]))
```

If decryption is successful, program executes one of these two entries. To find out how decryption works, we look
at the Gozi [source code](https://github.com/t3rabyt3-zz/Gozi). Decryption is actually the
[DsUnsign](https://github.com/t3rabyt3-zz/Gozi/blob/494e9f1bc1b57e1f3aee0e3682134ee6483e9ff3/crypto/sign.c#L118) function.
However DsUnsign requires a public key to operate. Therefore, to decrypt a registry entry, it shellcode first decrypts
the RSA public key using [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher)) algorithm (function
[RC6EncryptDecryptBuffer](https://github.com/t3rabyt3-zz/Gozi/blob/494e9f1bc1b57e1f3aee0e3682134ee6483e9ff3/crypto/cryptstr.c#L52)
from the source). Decryption key is `90982d21090ef347`:
```C
__int64 __fastcall decrypt_13F8F9828(__int64 a1, unsigned int a2, _QWORD *a3, _DWORD *a4) {
    /* ... */
    xor_serpent_key_1_13F536524(a5_pRC6Key);
    xor_serpent_key_2_13F532CC0(v20);
    v10 = RC6EncryptDecryptBuffer_13F535D44(v9, *(v8 + 0x1A8), &v18, &a4_pOutSize, a5_pRC6Key, 0);// decrypt RSA key
```

RSA key is 1024-bits and its structure is defined as follows:
```C
/* RSA public and private key.
 */
typedef struct {
  unsigned int bits;                  /* length in bits of modulus */
  unsigned char modulus[MAX_RSA_MODULUS_LEN];           /* modulus */
  unsigned char exponent[MAX_RSA_MODULUS_LEN];           /* public exponent */
} R_RSA_PUBLIC_KEY;
```

The RSA public key pair `(n, e)` is:
```
00 04 00 00                                         <--- 1024

C3 DA 26 3D F1 72 29 33 73 B0 43 1E E0 0B AC 4C     <--- n
3D B7 23 BE E2 D9 CC C0 A7 EF 8D 03 68 C3 3C 57
7D F7 E6 4F 09 50 34 37 E9 17 85 33 C9 F3 B4 D4
EE BD 7F E1 07 5E 2E 55 39 39 D4 3C 25 EB 8A 89
A5 FD 7A D5 F8 A5 2C 20 71 3A E8 78 CF 2B 1F 32
2A CF E8 B7 C5 5D AD 60 B3 52 06 14 19 FA 71 3C
90 3D 9E FC 36 BA F9 51 85 88 0D 03 EC 16 5A 51
18 6C F1 C3 23 BC 58 C4 0B 85 FC BC 7F A1 62 AD

00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     <--- e
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 01
```

Once the RSA public key is obtained, decryption takes place. First, function decrypts the last `128`
bytes from the registry using the RSA public key and obtains a [DS_HEADER](https://github.com/t3rabyt3-zz/Gozi/blob/494e9f1bc1b57e1f3aee0e3682134ee6483e9ff3/crypto/sign.c#L20):
```C
// File digital signature header structure.
typedef union   _DS_HEADER
{
    struct 
    {
        MD5     Md5;    // MD5 hash of the signed data buffer
        RC6_KEY Key;    // RC6 key used to encrypt the buffer
        ULONG   Size;   // Size of the buffer in bytes
        ULONG   Salt;   // Random value
    };
    CHAR    Padding[RSA_BLOCK_LENGTH / 2];
} DS_HEADER, *PDS_HEADER;
```

This structure contains the MD5 hash of the plaintext and and Serpent key to decrypt the ciphertext
(Note that this pattern is common: A slow, public-key encryption algorithm is used to encrypt a
symmetric key from a fast, symmetric key block cipher). The program uses this key to decrypt the
registry data. After decryption, program compares the MD5 hashes to verify that decryption was
successful.

If decryption is successful, program decompresses the plaintext (using aplib) and transforms the
(decompressed) plaintext into PE format. Fortunately, there is a [converter](https://github.com/hasherezade/funky_malware_formats)
so we do not have to write any code for it. At this point we know everything in order to write
a decryptor for all registry entries under `Timerpro`.
We create [rabbithole_decrypt_regval.py](./rabbithole_decrypt_regval.py) script that decrypts any value from registry.


#### Reversing Registry DLLs

At this point, we successfully decrypted the 2 DLLs from `WebsoftwareProcesstemplate` keys. We apply
the same decryption scheme for the remaining registry keys. Most of the entries (at least those which
are at least 128 bytes) can be decrypted successfully, so end up with a large set of decrypted DLLs
(see [Timerpro_dlls.7z](./Timerpro_dlls.7z). Each DLL comes in `32` and `64` bit flavors. We ignore
the `32` bit ones.

We suspect that the flag is one of the entries that we could not decrypt. The only entrie (with a
reasonable size) that we could not decrypt are:
* `Timerpro/DiMap`
* `Timerpro/WordTimer/MAIN`
* `Timerpro/Languagetheme/MonitornewWarningmap`


We start from `MonitornewWarningmap`. Although we can use our
[rabbithole_decrypt_regval.py](./rabbithole_decrypt_regval.py) script to decrypt it,
the result is not a PE file. Instead we get some random data:
```
00000000  17 00 00 00 00 00 00 00  5a 84 92 b8 01 00 00 00  |........Z.......|
00000010  28 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |(...............|
00000020  70 6c 47 72 01 00 00 00  2b 02 00 00 00 00 00 00  |plGr....+.......|
00000030  00 00 00 00 00 00 00 00  5e 94 58 2e 01 00 00 00  |........^.X.....|
00000040  15 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000050  8f ed 6a 55 01 00 00 00  0a 02 00 00 00 00 00 00  |..jU............|
00000060  00 00 00 00 00 00 00 00  3e 69 a8 4f 01 00 00 00  |........>i.O....|
00000070  f5 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000080  7f 1c 27 11 01 00 00 00  ee 01 00 00 00 00 00 00  |..'.............|
00000090  00 00 00 00 00 00 00 00  d5 7b 27 31 01 00 00 00  |.........{'1....|
000000a0  da 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000b0  c9 03 a0 d7 01 00 00 00  c6 01 00 00 00 00 00 00  |................|
000000c0  00 00 00 00 00 00 00 00  46 ee 30 7d 01 00 00 00  |........F.0}....|
000000d0  b2 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000e0  a6 79 58 95 01 00 00 00  9e 01 00 00 00 00 00 00  |.yX.............|
000000f0  00 00 00 00 00 00 00 00  8a 79 6b 65 01 00 00 00  |.........yke....|
00000100  8a 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000110  1e 81 ff de 01 00 00 00  77 01 00 00 00 00 00 00  |........w.......|
00000120  00 00 00 00 00 00 00 00  25 59 4e 58 01 00 00 00  |........%YNX....|
00000130  62 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |b...............|
00000140  91 75 95 09 01 00 00 00  4d 01 00 00 00 00 00 00  |.u......M.......|
00000150  00 00 00 00 00 00 00 00  b6 1c 45 6c 01 00 00 00  |..........El....|
00000160  38 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |8...............|
00000170  76 3c 4c 75 01 00 00 00  22 01 00 00 00 00 00 00  |v<Lu....".......|
00000180  00 00 00 00 00 00 00 00  cb 9e 28 e3 01 00 00 00  |..........(.....|
00000190  0c 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001a0  a5 46 59 ea 01 00 00 00  f6 00 00 00 00 00 00 00  |.FY.............|
000001b0  00 00 00 00 00 00 00 00  de 04 da 97 01 00 00 00  |................|
000001c0  02 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000001d0  0d 2b e9 8d 01 00 00 00  f1 00 00 00 00 00 00 00  |.+..............|
000001e0  00 00 00 00 00 00 00 00  fc c2 c4 c6 01 00 00 00  |................|
000001f0  e8 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000200  ff a0 71 95 01 00 00 00  d4 00 00 00 00 00 00 00  |..q.............|
00000210  00 00 00 00 00 00 00 00  51 f5 80 db 01 00 00 00  |........Q.......|
00000220  c0 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000230  68 74 74 70 73 3a 2f 2f  67 6c 6f 72 79 2e 74 6f  |https://glory.to|
00000240  2e 6b 61 7a 6f 68 69 6e  69 61 00 30 00 63 75 72  |.kazohinia.0.cur|
00000250  6c 6d 79 69 70 2e 6e 65  74 00 31 32 00 47 53 50  |lmyip.net.12.GSP|
00000260  79 72 76 33 43 37 39 5a  62 52 30 6b 31 00 33 30  |yrv3C79ZbR0k1.30|
00000270  30 00 33 30 30 00 33 30  30 00 33 30 30 00 33 30  |0.300.300.300.30|
00000280  30 00 31 30 30 30 00 36  30 00 36 30 00 31 30 00  |0.1000.60.60.10.|
00000290  30 00 30 00 31 00 6e 6f  2d 63 61 63 68 65 2c 20  |0.0.1.no-cache, |
000002a0  6e 6f 2d 73 74 6f 72 65  2c 20 6d 75 73 74 2d 72  |no-store, must-r|
000002b0  65 76 61 6c 69 64 61 74  65 00 33 30 30 30 30 30  |evalidate.300000|
000002c0  00 33 30 2c 20 38 2c 20  6e 6f 74 69 70 64 61 00  |.30, 8, notipda.|
000002d0  34 38 30 00 32 34 30 00  32 34 30 00              |480.240.240.|
000002dc
```

There are some interesting strings here like `https://glory.tokazohinia`, `curlmyip.net`, `GSPyrv3C79ZbR0k1`
and `no-cache, no-store, must-revalidate`. Let's keep `GSPyrv3C79ZbR0k1` in mind.

The next step is to decrypt `DiMap`. We need to find in which DLL is being accessed. After a lot of searching
we find that there is an interesting function at `0x180004BB3` in `WebmodeThemearchive` DLL:
```assembly
seg001:0000000180004BB3 Get_DiMap_value_180004BB3 proc near     ; CODE XREF: DECRYPT_FLAG_180001000+189↑p
seg001:0000000180004BB3        push    rax
seg001:0000000180004BB4        sub     rsp, 20h
seg001:0000000180004BB8        mov     rdi, [r12+18h]
seg001:0000000180004BBD        mov     ebx, [r12+28h]
seg001:0000000180004BC2        xor     r9, r9          ; _QWORD
seg001:0000000180004BC5        mov     rax, cs:glo_B_180006070
seg001:0000000180004BCC        mov     r8d, [eax+78h]  ; _QWORD
seg001:0000000180004BD1        mov     rdx, rbx        ; _QWORD
seg001:0000000180004BD4        mov     rcx, rdi        ; _QWORD
seg001:0000000180004BD7        mov     rax, cs:__imp_d6306e08_57
seg001:0000000180004BDE        sub     ax, 454h
seg001:0000000180004BE2        call    rax ; dword_180004E84
seg001:0000000180004BE4        mov     r9, rbx         ; arg4 = *(r12 + 0x28)
seg001:0000000180004BE7        mov     r8, rdi         ; arg3 = *(r12 + 0x18)
seg001:0000000180004BEA        mov     dl, 3           ; arg2 = 3
seg001:0000000180004BEC        mov     cl, 7Fh
seg001:0000000180004BEE        mov     ch, cl          ; arg1 = 0x7f7f
seg001:0000000180004BF0        call    _8576b0d0_79
seg001:0000000180004BF5        mov     edi, 24924925h
seg001:0000000180004BFA        add     rsp, 20h
seg001:0000000180004BFE        pop     rax
seg001:0000000180004BFF        retn
seg001:0000000180004BFF Get_DiMap_value_180004BB3 endp
```

```C
void __fastcall Get_DiMap_value_180004BB3()
{
  __int64 v0; // r12
  __int64 v1; // rdi
  __int64 v2; // rbx
  __int64 (__fastcall *v3)(_QWORD); // rax
  __int64 v4; // rdx
  __int64 v5; // rcx

  v1 = *(v0 + 0x18);                            // serpent out buf
  v2 = *(v0 + 0x28);                            // serpent out size
  v3 = d6306e08_57;
  LOWORD(v3) = d6306e08_57 - 0x454;             // d6306e08:43
  (v3)(v1, v2, *(glo_B_180006070 + 0x78), 0i64);// offset 0x78: 4 LSB of SID magic
  LOBYTE(v4) = 3;
  LOWORD(v5) = 0x7F7F;
  8576b0d0_79(v5, v4, v1, v2);                  // Read DiMap value
}
```

(Note that `glo_B_180006070 + 0x78` corresponds to the 4 low bytes of the SID magic; 
we derive this from the main shellcode as offset `0x78` is used to hold the same value).


```assembly
seg001:0000000180001BEC
seg001:0000000180001BEC _8576b0d0_79    proc near               ; CODE XREF: sub_180002798+A4↓p
seg001:0000000180001BEC                       ; _17+86↓p ...
seg001:0000000180001BEC        jmp     cs:__imp__8576b0d0_79
seg001:0000000180001BEC _8576b0d0_79    endp
```

Let's also take a look at the (only) XREF to for `Get_DiMap_value_180004BB3`:
```C
    // arg1: inbuf
    // arg2: insize
    // arg3: r12 + 0x18: OutBuf
    // arg4: r12 + 0x28: OutSize
    v15 = 8576b0d0_27(v22, a4, a5 + 0x18, a5 + 0x28, *a1, 1);// RC6EncryptDecryptBuffer
    _InterlockedAdd(a1 + 56, 0xFFFFFFFF);
    if ( !v15 )
    {
        *(a5 + 44) = 1;
        v10 = 8576b0d0_10_HeapAlloc(0x77i64);
        if ( v10 )
        {
            v16 = 8576b0d0_7();
            Get_DiMap_value_180004BB3();

            /* ... */
```

The reason that `Get_DiMap_value_180004BB3` is interesting is because function `_8576b0d0_79` is
invoked as `_8576b0d0_79(0x7f7f, 3, ...)`. If we supply the pair `(0x7F7F, 3)` into our name generator
we will get the string `DiMap` as output.


The next step is to find where functions `cs:__imp_d6306e08_57` and `cs:__imp__8576b0d0_79` are imported.
To do this we check again our name generator and our [rabbithole_mk_str.py](./rabbithole_mk_str.py) script.
Number `d6306e08` generates name `WordlibSystemser` and number `8576b0d0` generates `WebsoftwareProcesstemplate`
(we ignore the second number of the pair as it only affects the capitalization).
The `_57` and `_79` numbers are the ordinals. Let's see the `_79` function:
```C
__int64 __fastcall _79_decrypt_and_set_regval(__int64 a1, unsigned int a2, __int64 a3, int a4) {
  decr_str = _60_decode_string(a1, 3i64);       // Read Registry Name String
  decr_str2 = (void *)decr_str;
  if ( !decr_str )
    return 8;
  v9 = set_reg_value(0i64, decr_str, a2, a3, a4);
  HeapFree(hHeap, 0, decr_str2);
  return v9;
}
```

Function `_60_decode_string` is the name generator described above (it generates a pseudo-random
name from a pair of numbers) and is used to generate the registry key name. Then `set_reg_value`
sets the value of that registry key. Therefore, `cs:__imp__8576b0d0_79` is used to set the value of
`DiMap` key.

Regarding ordinal `_57`, It is important to observer that the constant `0x454` is subtracted from the
address of `__imp_d6306e08_57`, so the actual function that we invoke is `__imp_d6306e08_43`:
```C
seg001:000000018000542C ; void __fastcall 43_0(__int64 a1_buf, unsigned int a2_size, int a3, int a4)
seg001:000000018000542C _43_0   proc near                            ; CODE XREF: _43↑j
seg001:000000018000542C                                              ; DATA XREF: seg007:00000001800113CC↓o
seg001:000000018000542C
seg001:000000018000542C arg_0   = qword ptr  8
seg001:000000018000542C
seg001:000000018000542C         mov     [rsp+arg_0], rbx
seg001:0000000180005431         xor     r10d, r10d
seg001:0000000180005434         xor     r11d, r11d                   ; A = 0
seg001:0000000180005437         shr     edx, 2                       ; arg2 >> 2
seg001:000000018000543A         mov     ebx, r8d
seg001:000000018000543D         jz      short RETURN_180005487
seg001:000000018000543F         lea     rax, [rcx+8]                 ; rax = arg1 + 8
seg001:0000000180005443
seg001:0000000180005443 LOOP_180005443:                              ; CODE XREF: _43_0+59↓j
seg001:0000000180005443         test    r9d, r9d
seg001:0000000180005446         mov     r8d, [rax-8]                 ; r8 = arg1[i] (DWORD)
seg001:000000018000544A         jz      short SKIP_180005467         ; ecx = A
seg001:000000018000544C         test    r8d, r8d
seg001:000000018000544F         jnz     short SKIP_180005467         ; ecx = A
seg001:0000000180005451         cmp     edx, 3
seg001:0000000180005454         jbe     short SKIP_180005467         ; ecx = A
seg001:0000000180005456         cmp     [rax-4], r8d
seg001:000000018000545A         jnz     short SKIP_180005467         ; ecx = A
seg001:000000018000545C         cmp     [rax], r8d
seg001:000000018000545F         jnz     short SKIP_180005467         ; ecx = A
seg001:0000000180005461         cmp     [rax+4], r8d
seg001:0000000180005465         jz      short RETURN_180005487
seg001:0000000180005467
seg001:0000000180005467 SKIP_180005467:                              ; CODE XREF: _43_0+1E↑j
seg001:0000000180005467                                              ; _43_0+23↑j ...
seg001:0000000180005467         mov     ecx, r11d                    ; ecx = A
seg001:000000018000546A         add     rax, 4                       ; rax += 4
seg001:000000018000546E         xor     r11d, 1                      ; A ^= 1
seg001:0000000180005472         shl     ecx, 2                       ; A << 2
seg001:0000000180005475         ror     r8d, cl                      ; r8 = ROR(arg1[i], A << 2)
seg001:0000000180005478         xor     r10d, r8d
seg001:000000018000547B         xor     r10d, ebx                    ; r10 ^= arg3 ^ ROR(arg1[i], A << 2)
seg001:000000018000547E         add     edx, 0FFFFFFFFh              ; --arg2
seg001:0000000180005481         mov     [rax-0Ch], r10d
seg001:0000000180005485         jnz     short LOOP_180005443
seg001:0000000180005487
seg001:0000000180005487 RETURN_180005487:                            ; CODE XREF: _43_0+11↑j
seg001:0000000180005487                                              ; _43_0+39↑j
seg001:0000000180005487         mov     rbx, [rsp+arg_0]
seg001:000000018000548C         retn
seg001:000000018000548C _43_0   endp
```

This function implements a custom encryption using XOR and ROR. Let's decompile it:
```python
def custom_encrypt(sid_magic):
    numA = 0
    Ci = 0

    for i in range(0, len(DiMap_decr), 4):
        val = DiMap_decr[i] | (DiMap_decr[i+1] << 8) | (DiMap_decr[i+2] << 16) | (DiMap_decr[i+3] << 24)       
        Ci = Ci ^ (sid_magic & 0xFFFFFFFF) ^ ror(val, 4 * numA);
        numA ^= 1
```


#### Cracking the Flag

At this point we know that the flag is stored in `DiMap` registry key. We also know
that the flag is encrypted using Serpent algorithm and then encrypted again using `43_0`
function. After some guessing we find that the serpent key is `GSPyrv3C79ZbR0k1`, 
the one we found in `MonitornewWarningmap`.
In order to decrypt the flag, we first apply the inverse algorithm of `43_0` and then we do a
Serpent decryption (note that the order is reversed). The inversed algorithm of custom
encryption is shown below:
```Python
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
```

Once we apply the decryption, we get a zip archive with 1 file: `C/Users/Kevin/Desktop/flag.txt`.
Inside this file is the flag.

The full script that breaks the flag is here: [rabbithole_crack.py](./rabbithole_crack.py)

The final flag is `r4d1x_m4l0rum_357_cup1d1745@flare-on.com`.

___
