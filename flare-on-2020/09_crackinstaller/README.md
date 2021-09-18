
## Flare-On 2020 - #9 crackinstaller
___

### Description: 

*What kind of crackme doesn't even ask for the password? We need to work on our COMmunication skills.*

*Bug Notice: Avoid a possible blue-screen by debugging this on a single core VM*

`*7zip password: flare`
___

### Solution:

As stated in the description, this challenge has multiple components that communicate with each
other. An overview of their communication diagram is shown below:
```
Dropper (TLS callback) ---> cfs.dll ---> Dropper (2nd callback) ------\
                                                                      |
  /--- Capcom.sys (DriverEntry) <--- Capcom.sys (DriverBootstrap) <---/
  |
  \---> Dropper (main) ---> credHelper.dll (DllRegisterServer) ---\
                                                                  |
                               /---- (Registry gets modified) <---/
                               |
                               \--------------------------------------------------\
                                                                                  |
          credHelper.dll (decrypt_flag) <--- credHelper.dll (verify_password) <---/
```


#### Dropper (crackstaller.exe)

`crackstaller.exe` contains a TLS callback which initializes the environment. First, it uses
`LoadLibrary` and `GetProcAddress` to load functions `CreateServiceW`, `OpenServiceW`,
`CloseServiceHandle`, `StartServiceW`, `ControlService`, `DeleteService`, `OpenSCManagerW`
and `CreateFileW`. Note that all strings are XOR encrypted with `<g~{<it"` as a repeating key.
We can deobfuscate strings from the binary using 2 lines in python:
```python
def decode_string(buf):
    buf = buf.replace(" ", "").decode('hex')
    return ''.join(chr(ord(buf[i]) ^ ord('<g~{<it'[i % 7])) for i in xrange(len(buf)))
```

Then program decrypts `2` executables and drops them on the disk. These executables
are encrypted with [salsa20](https://en.wikipedia.org/wiki/Salsa20) stream cipher and
`SHA256("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")` as the encryption
key:
```Assembly
.text:000000013FCF2563         mov     edx, 1F85h
.text:000000013FCF2568         lea     rcx, encrypted_exe1_13F4063B0
.text:000000013FCF256F         mov     r8d, 2950h
.text:000000013FCF2575         call    decrypt_salsa20_13F292370
.text:000000013FCF257A         mov     r14, rax
.text:000000013FCF257D         test    rax, rax
.text:000000013FCF2580         jz      MOVE_ON_13F8E26C7
.text:000000013FCF2586         mov     edx, 22B2h
.text:000000013FCF258B         lea     rcx, encrypted_exe2_13FF84080
.text:000000013FCF2592         mov     r8d, 5800h
.text:000000013FCF2598         call    decrypt_salsa20_13F292370
.text:000000013FCF259D         mov     rsi, rax
.text:000000013FCF25A0         test    rax, rax
.text:000000013FCF25A3         jz      MOVE_ON_13F8E26C7
.text:000000013FCF25A9         xor     r8d, r8d
.text:000000013FCF25AC         lea     edx, [rbx+1Ch]
.text:000000013FCF25AF         lea     rcx, unk_13FD09988
.text:000000013FCF25B6         call    decode_string_unicode_13F291C34  ; C:\Windows\System32\cfs.dll
.text:000000013FCF25BB         mov     rcx, rax                         ; arg1: C:\Windows\System32\cfs.dll
.text:000000013FCF25BE         mov     rdx, r14                         ; arg2: exe1
.text:000000013FCF25C1         call    save_dll_to_disk_13F8E2ED8
```

We set breakpoints at `0x13FCF257A` and `0x13FCF259D` and we let IDA to decrypt the executables.
Then we write them to disk using the following code snippet (addresses will be different, just see the value
of `rax` and adjust them):
```python
import idaapi

buf = bytes((idaapi.get_byte(0x1241d0 + it)) for it in range(0x2950))
with open('exe_1.exe', 'wb') as fp:
    fp.write(buf)


buf2 = bytes((idaapi.get_byte(0x128e40 + it)) for it in range(0x5800))
with open('exe_2.exe', 'wb') as fp:
    fp.write(buf2)
```

The first executable is stored under `C:\Windows\System32\cfs.dll`. Then, program starts a service
called `cfs` and opens file `\\.\Htsysm72FB` to get a handle to the device. Then it does some magic:
```C
dword_13FAA634B = v22;
*(_QWORD *)((char *)&xmmword_13FAA6338 + 3) = a2_exe2;
*(_DWORD *)((char *)&xmmword_13FAA6338 + 13) = 22528;

v23 = (char *)VirtualAlloc(0i64, 0x2Dui64, 0x3000u, 0x40u); // _IRP object
if ( v23 )
{
    *(_QWORD *)v23 = v23 + 8;
    *(_OWORD *)(v23 + 8) = xmmword_13FAA6338;
    *(_OWORD *)(v23 + 24) = *(_OWORD *)&byte_13FAA6348;
    *((_DWORD *)v23 + 10) = *(_DWORD *)((char *)&callback_1_13FAA6355 + 3);
    v23[44] = HIBYTE(callback_1_13FAA6355);     // SystemBuffer offset
    InBuffer = v23 + 8;

    if (DeviceIoControl(hObject, 0xAA013044, &InBuffer, 8u, &OutBuffer, 4u, &BytesReturned, 0i64))
        v5 = 1;
}
```

Here, `InBuffer` is a pointer to an `_IRP` struct. `SystemBuffer` contains address of function
`callback_1_13FAA6355`, which is invoked as callback through the `cfs` driver (described in
the next section). After that, program stops the service and deletes the file from the disk.

`callback_1_13FAA6355` holds a function pointer to `second_stage_callback_13FCF2A10`, which takes a
pointer to `MmGetSystemRoutineAddress` as the first argument and a pointer to the second decrypted executable
(we call it **Capcom.sys**):
```C
__int64 __fastcall second_stage_callback_13FCF2A10(__int64 (__fastcall *a1)(_QWORD), const void *a2, unsigned int a3, int a4) {  
  size_v2 = a3;
  retval = 0xC0000001;
  MmGetSystemRoutineAddress_13FD295A8 = a1;
  init_loaded_module_13FCF2768();
  v22 = 0i64;
  v23 = 0i64;
  v25 = 0i64;
  v21 = 48;
  v24 = 512;
  ExAllocatePoolWithTag = (__int64 (__fastcall *)(_QWORD, __int64, _QWORD))load_function_13F952964(0x490A231A);
  if ( ExAllocatePoolWithTag )
  {
    ExFreePoolWithTag = (void (__fastcall *)(char *, _QWORD))load_function_13F952964(0x34262863);
    if ( ExFreePoolWithTag )
    {
      IoCreateDriver = load_function_13F952964(0x1128974);
      if ( IoCreateDriver )
      {
        RtlImageNtHeader = load_function_13F952964(0xE2A9259B);
        if ( RtlImageNtHeader )
        {
          RtlImageDirectoryEntryToData = load_function_13F952964(0xCF424038);
          if ( RtlImageDirectoryEntryToData )
          {
            RtlQueryModuleInformation = load_function_13F952964(0xCE968D51);
            if ( RtlQueryModuleInformation )
            {
              PsCreateSystemThread = (__int64 (__fastcall *)(__int64 *, __int64, int *, _QWORD, _QWORD, char *, __int64))load_function_13F952964(0xB40D00D9);
              if ( PsCreateSystemThread )
              {
                ZwClose = (void (__fastcall *)(__int64))load_function_13F952964(0xA95BE347);
                if ( ZwClose )
                {
                  size = a3;
                  pool = (char *)ExAllocatePoolWithTag(0i64, a3, 'RALF');
                  if ( pool )
                  {
                    v13 = ExAllocatePoolWithTag(0i64, 0x44i64, 'RALF');
                    v14 = v13;
                    if ( v13 )
                    {
                      *(_QWORD *)v13 = ExAllocatePoolWithTag;
                      *(_DWORD *)(v13 + 0x38) = size_v2;
                      *(_QWORD *)(v13 + 8) = ExFreePoolWithTag;
                      *(_QWORD *)(v13 + 0x28) = IoCreateDriver;
                      *(_QWORD *)(v13 + 0x30) = pool;
                      *(_QWORD *)(v13 + 0x18) = RtlImageDirectoryEntryToData;
                      *(_QWORD *)(v13 + 0x20) = RtlQueryModuleInformation;
                      v16 = pool;
                      *(_QWORD *)(v14 + 0x10) = RtlImageNtHeader;
                      qmemcpy(pool, a2, 8 * (size >> 3));
                      v17 = &pool[size_v2 - 8];
                      if ( pool < v17 )
                      {
                        do
                        {
                          if ( *(_QWORD *)v16 == 0xDC16F3C3B57323i64 )
                            strcpy(v16, "BBACABA");
                          ++v16;
                        }
                        while ( v16 < v17 );
                      }
                      retval = PsCreateSystemThread(&handle, 0x10000000i64, &v21, 0i64, 0i64, &pool[a4], v14);
                      if ( retval >= 0 )
                      {
                        ZwClose(handle);
                        return (unsigned int)retval;
                      }
                    }
                    else
                    {
                      retval = 0xC0000017;
                    }
                    ExFreePoolWithTag(pool, 'RALF');
                    if ( v14 )
                      ExFreePoolWithTag((char *)v14, 'RALF');
                  }
                  else
                  {
                    retval = 0xC0000017;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return (unsigned int)retval;
}
```

Before we analyze this function, it is worht to take a look at `init_loaded_module_13FCF2768` that searches for a
loaded driver whose custom checksum is `C036346A`. The driver we are looking for is `ntoskrnl.exe`:
```C
unsigned int *init_loaded_module_13FCF2768() {
  str_decode_13FCF1CA8((__int64)&ZwQuerySystemInformation_13FD09950, 0x19u, (__int64)v11);
  ZwQuerySystemInformation = (int (__fastcall *)(__int64, unsigned int *, _QWORD, int *))MmGetSystemRoutineAddress_13FD295A8(v11);
  str_decode_13FCF1CA8((__int64)&ExAllocatePoolWithTag_13FD099A8, 0x16u, (__int64)v12);
  ExAllocatePoolWithTag = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))MmGetSystemRoutineAddress_13FD295A8(v12);
  str_decode_13FCF1CA8((__int64)&ExFreePoolWithTag_13FD09A00, 0x12u, (__int64)v13);
  ExFreePoolWithTag = (void (__fastcall *)(unsigned int *, _QWORD))MmGetSystemRoutineAddress_13FD295A8(v13);
  ModuleInfo = 0;
  ZwQuerySystemInformation(0xBi64, (unsigned int *)&ModuleInfo, 0i64, &ModuleInfo);// SystemModuleInformation
  if ( !ModuleInfo )
    return 0i64;
  result = (unsigned int *)ExAllocatePoolWithTag(0i64, (unsigned int)(2 * ModuleInfo), 'RALF');
  pool = result;
  if ( result )
  {
    memset(result, 0, (unsigned int)(2 * ModuleInfo));
    if ( ZwQuerySystemInformation(0xBi64, pool, (unsigned int)(2 * ModuleInfo), &ModuleInfo) >= 0 )
    {
      for ( i = 0; i < *pool; ++i )
      {
        memset(v14, 0, sizeof(v14));
        v6 = (char *)&pool[74 * i] + HIWORD(pool[74 * i + 11]);// use image name only (no full path)
        for ( j = 0i64; v6[j + 48]; j = (unsigned int)(j + 1) )
          v14[j] = tolower(v6[j + 48]);
        v8 = 0;
        for ( k = v14; ; ++k )
        {
          v10 = __ROR4__(v8, 14);
          if ( !*k )
            break;
          v8 = v10 + *k;
        }
        if ( v10 == 0xC036346A )
        {
          v0 = *(unsigned int **)&pool[74 * i + 6];
          target_module_13FD295A0 = (__int64)v0;
          break;
        }
      }
    }
    if ( pool )
      ExFreePoolWithTag(pool, 'RALF');
    result = v0;
  }
  return result;
}
```

To make it more clear, you can take a look at the following usage example:
```C
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
 
int main()
{
    NTSTATUS status;
    ULONG i;
 
    PRTL_PROCESS_MODULES ModuleInfo;
 
    ModuleInfo=(PRTL_PROCESS_MODULES)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); // Allocate memory for the module list
 
    if(!ModuleInfo)
    {
        printf("\nUnable to allocate memory for module list (%d)\n",GetLastError());
        return -1;
    }
 
    if(!NT_SUCCESS(status=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,ModuleInfo,1024*1024,NULL))) // 11 = SystemModuleInformation
    {
        printf("\nError: Unable to query module list (%#x)\n",status);
 
        VirtualFree(ModuleInfo,0,MEM_RELEASE);
        return -1;
    }
 
    for(i=0;i<ModuleInfo->NumberOfModules;i++)
    {
        printf("\n*****************************************************\n");
        printf("\nImage base: %#x\n",ModuleInfo->Modules[i].ImageBase);
        printf("\nImage name: %s\n",ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        printf("\nImage full path: %s\n",ModuleInfo->Modules[i].FullPathName);
        printf("\nImage size: %d\n",ModuleInfo->Modules[i].ImageSize);
        printf("\n*****************************************************\n");
    }
 
    VirtualFree(ModuleInfo,0,MEM_RELEASE);
    return 0;
}
```

The second function that is worth to mention is `load_function_13F952964`, which is quite similar and
it searches for an exported function from `ntoskrnl.exe` (the windows kernel), based on the its checksum:
```C
__int64 __fastcall load_function_13F952964(int a1) {
  if ( *(_WORD *)target_module_13FD295A0 != 0x5A4D )
    return 0i64;
  v2 = *(int *)(target_module_13FD295A0 + 60);
  if ( *(_DWORD *)(v2 + target_module_13FD295A0) != 0x4550 )
    return 0i64;
  v3 = *(unsigned int *)(v2 + target_module_13FD295A0 + 136);
  if ( !(_DWORD)v3 )
    return 0i64;
  v4 = *(unsigned int *)(v3 + target_module_13FD295A0 + 28);
  v5 = 0i64;
  v6 = (_DWORD *)(target_module_13FD295A0 + *(unsigned int *)(v3 + target_module_13FD295A0 + 32));
  v7 = target_module_13FD295A0 + *(unsigned int *)(v3 + target_module_13FD295A0 + 36);
  if ( !(_DWORD)v4 )
    return 0i64;
  while ( 1 )
  {
    if ( *v6 )
    {
      v8 = 0;
      for ( i = (_BYTE *)(target_module_13FD295A0 + (unsigned int)*v6); ; ++i )
      {
        v10 = __ROR4__(v8, 14);
        if ( !*i )
          break;
        v8 = (char)*i + v10;
      }
      if ( a1 == v10 )
        break;
    }
    v5 = (unsigned int)(v5 + 1);
    ++v6;
    if ( (unsigned int)v5 >= (unsigned int)v4 )
      return 0i64;
  }
  return target_module_13FD295A0
       + *(unsigned int *)(target_module_13FD295A0 + v4 + 4i64 * *(unsigned __int16 *)(v7 + 2 * v5));
}
```

To break those hashes, we keep a list of all exported functions from `ntoskrnl.exe` and we
try them one by one until we find a match (forward search):
```
    490A231A --> ExAllocatePoolWithTag
    34262863 --> ExFreePoolWithTag
    01128974 --> IoCreateDriver
    E2A9259B --> RtlImageNtHeader
    CF424038 --> RtlImageDirectoryEntryToData
    CE968D51 --> RtlQueryModuleInformation
    B40D00D9 --> PsCreateSystemThread
    A95BE347 --> ZwClose
```

Function iterates through the **Capcom.sys** module in memory, searches for byte sequence
`23 73 B5 C3 F3 16 DC` and replaces it with string `BBACABA`.
```C
do {
    if ( *(_QWORD *)v16 == 0xDC16F3C3B57323i64 )
        strcpy(v16, "BBACABA");
        ++v16;
    }
while ( v16 < v17 );
```

Finally, it creates a new thread that invokes `DriverBootstrap` functions from **Capcom.sys**:
```C
retval = PsCreateSystemThread(&handle, 0x10000000i64, &v21, 0i64, 0i64, &pool[a4], v14);
if ( retval >= 0 ) {
    ZwClose(handle);
    return (unsigned int)retval;
}
```

The script that deobfuscates all the strings is here: [deobfuscate_strings.py](./deobfuscate_strings.py)

After that, the TLS callback returns and the main function if `crackstaller.exe` is called.
This function decrypts a new executable, `credHelper.dll` (stored under `C:\Users\vm\AppData\Local\Microsoft\Credentials\credHelper.dll`)
and invokes function `DllRegisterServer` from it:
```Assembly
.text:000000013FCF231F         test    ebx, ebx
.text:000000013FCF2321         jz      short RETURN_13F8E2357
.text:000000013FCF2323         lea     rcx, [rbp+780h+LibFileName]      ; lpLibFileName
.text:000000013FCF232A         call    cs:LoadLibraryW
.text:000000013FCF2330         mov     rbx, rax
.text:000000013FCF2333         test    rax, rax
.text:000000013FCF2336         jz      short RETURN_13F8E2357
.text:000000013FCF2338         mov     edx, 12h
.text:000000013FCF233D         lea     rcx, unk_13FD09970
.text:000000013FCF2344         call    xor_140001BC8                    ; "DllRegisterServer"
.text:000000013FCF2349         mov     rdx, rax                         ; lpProcName
.text:000000013FCF234C         mov     rcx, rbx                         ; hModule
.text:000000013FCF234F         call    cs:GetProcAddress
.text:000000013FCF2355         call    rax                              ; call DllRegisterServer
```

After that, `crackstaller.exe` terminates.


#### Driver #1 (cfs.dll)

The first interesting part of [cfs.dll](./cfs.dll) os the string decoding function at `0x103AC`:
```Assembly
.text:00000000000103AC string_decode_103AC proc near                      ; CODE XREF: DriverUnload_1047C+38↓p
.....
.text:00000000000103D2         mov     r9w, 5555h                         ; r9 = 0x5555
.text:00000000000103D7         cmp     [rsp+48h+buf], di                  ; buf[2*i] == NULL?
.text:00000000000103DB         jz      short MOVE_ON_1044F                ; if so, stop
.text:00000000000103DD
.text:00000000000103DD LOOP_103DD:                                        ; CODE XREF: string_decode_103AC+A1↓j
.text:00000000000103DD         movzx   ecx, word ptr [rdx]                ; ecx = buf[i] (HALFWORD)
.text:00000000000103E0         shl     r9w, 2
.text:00000000000103E5         mov     r10d, ecx
.text:00000000000103E8         add     r9w, di                            ; r9 = ((r9 << 2) + i) & 0xFFFF = A
.text:00000000000103EC         shr     r10d, 6                            ; r10 = buf[i] >> 6 = B
.text:00000000000103F0         lea     eax, [r10-1]
.text:00000000000103F4         cmp     eax, 2                             ; if (buf[i] >> 6) > 3
.text:00000000000103F7         ja      short MOVE_ON_1044F                ; then break
.text:00000000000103F9         xor     cl, r9b                            ; cl = (buf[i] ^ A) & 0xFF
.text:00000000000103FC         xor     ax, ax
.text:00000000000103FF         sub     cl, dil
.text:0000000000010402         sub     cl, r10b
.text:0000000000010405         and     cx, 3Fh                            ; cl = (((buf[i] ^ A) & 0xFF) - i - B) & 0x3F = C
.text:0000000000010409         cmp     cx, 0Ah
.text:000000000001040D         jnb     short NOT_DIGIT_10414              ; if C < 10 then C += 0x30 (to digit)
.text:000000000001040F         lea     eax, [rcx+30h]
.text:0000000000010412         jmp     short loc_1041D
.text:0000000000010414 ; ---------------------------------------------------------------------------
.text:0000000000010414
.text:0000000000010414 NOT_DIGIT_10414:                                   ; CODE XREF: string_decode_103AC+61↑j
.text:0000000000010414         cmp     cx, 24h ; '$'
.text:0000000000010418         jnb     short ABOVE_24h_10423              ; if C < 0x24 then C += 0x37
.text:000000000001041A         lea     eax, [rcx+37h]
.text:000000000001041D
.text:000000000001041D loc_1041D:                                         ; CODE XREF: string_decode_103AC+66↑j
.text:000000000001041D         cmp     cx, 24h ; '$'
.text:0000000000010421         jb      short LOOP_END_1042C
.text:0000000000010423
.text:0000000000010423 ABOVE_24h_10423:                                   ; CODE XREF: string_decode_103AC+6C↑j
.text:0000000000010423         cmp     cx, 3Eh ; '>'
.text:0000000000010427         jnb     short LOOP_END_1042C               ; if C < 0x3E then C += 0x3D
.text:0000000000010429         lea     eax, [rcx+3Dh]
.text:000000000001042C
.text:000000000001042C LOOP_END_1042C:                                    ; CODE XREF: string_decode_103AC+75↑j
.text:000000000001042C                                                    ; string_decode_103AC+7B↑j
.text:000000000001042C         cmp     cx, 3Eh ; '>'
.text:0000000000010430         mov     r10d, 2Eh ; '.'
.text:0000000000010436         cmovz   ax, r10w                           ; if C == 0x3E then C = 0x2E
.text:000000000001043B         test    ax, ax
.text:000000000001043E         jz      short MOVE_ON_1044F                ; if ax == 0 then break
.text:0000000000010440         mov     [rdx], ax                          ; buf[2*i] = C
.text:0000000000010443         add     rdx, 2
.text:0000000000010447         inc     edi                                ; edi = iterator = ++i
.text:0000000000010449         cmp     word ptr [rdx], 0                  ; if buf[2*i + 2] == 0 the break
.text:000000000001044D         jnz     short LOOP_103DD                   ; ecx = buf[i] (HALFWORD)
.text:000000000001044F MOVE_ON_1044F:                                     ; CODE XREF: string_decode_103AC+2F↑j
.text:000000000001044F                                                    ; string_decode_103AC+4B↑j ...
.text:000000000001044F         xor     eax, eax
.text:0000000000010451         mov     rdi, r8                            ; rdi = arg1
.text:0000000000010454         lea     rdx, [rsp+48h+buf]                 ; rdx = buf
.text:0000000000010458         lea     rcx, [rax-1]                       ; rcx = -1
.text:000000000001045C         repne scasw                                ; search for null in arg1
.text:000000000001045F         xor     ecx, ecx
.text:0000000000010461
.text:0000000000010461 STRCAT_10461:                                      ; CODE XREF: string_decode_103AC+C5↓j
.text:0000000000010461         movzx   eax, word ptr [rdx+rcx]            ; eax = buf[2*i]
.text:0000000000010465         add     rcx, 2
.text:0000000000010469         test    ax, ax
.text:000000000001046C         mov     [rdi+rcx-4], ax                    ; arg1[strlen(arg1)+2*i - 4] = buf[2*i]
.text:0000000000010471         jnz     short STRCAT_10461                 ; eax = buf[2*i]
.text:0000000000010473         mov     rax, r8
.text:0000000000010476         add     rsp, 40h
.text:000000000001047A         pop     rdi
.text:000000000001047B         retn
```

Which decompiles to the following code:
```python
def string_decode(buf):
    A = 0x5555
    plain = ''

    for i in range(0, len(buf) >> 1):
        A = ((A << 2) + i) & 0xFFFF
        B = buf[2*i] >> 6        

        if B < 1: break
        
        C = (((buf[2*i] ^ A) & 0xFF) - i - B) & 0x3F       
        D = 0

        if C >= 0xA:
            if C >= 0x24:
                if C < 0x3E:
                    D = C + 0x3D      
            else:
                D = C + 0x37
        else:
            D = C + 0x30

        if C == 0x3E: D = 0x2E

        if not D: break
        plain += chr(D)

    return plain
```

This function is invoked `3` times in the code with different encoded buffers:
```python
buf_1 = [
    0x87, 0x00, 0xEA, 0x00, 0xFD, 0x00, 0x9A, 0x00, 0x4B, 0x00, 0x73, 0x00,
    0x54, 0x00, 0xA4, 0x00, 0x5C, 0x00, 0x8F, 0x00,
    0x00, 0x00
]

buf_2 = [  
    0x59, 0x00, 0x77, 0x00, 0xB1, 0x00, 0xF7, 0x00, 0x88, 0x00, 0x73, 0x00,
    0x00, 0x00,
]

buf_3 = [
    0x59, 0x00, 0xB6, 0x00, 0xFE, 0x00, 0xF7, 0x00, 0xC9, 0x00, 0xB2, 0x00,
    0xDD, 0x00, 0x90, 0x00, 0xC3, 0x00, 0xDB, 0x00,
    0x00, 0x00
]

print '[+] String #1:', string_decode(buf_1)
print '[+] String #2:', string_decode(buf_2)
print '[+] String #3:', string_decode(buf_3)
```

Running the code reveals the following constant strings:
```
String #1: Htsysm72FB
String #2: Capcom
String #3: Capcom.sys
```

```C
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    // Initialize: dev_name_10880 = "\Device\"
    string_decode_103AC(dev_name_10880, cipher_10980);  // dev_name_10880 = "\Device\Htsysm72FB"
    RtlInitUnicodeString(&DestinationString, v5);
    if (IoCreateDevice(DriverObject, 0, &DestinationString, 0xAA01u, 0, 0, &DeviceObject) >= 0) {

    // Initialize: dev_name_10880 = "\DosDevices\Htsysm72FB"
    string_decode_103AC(dos_name_10840, cipher_10980);
    RtlInitUnicodeString(&SymbolicLinkName, v9);    
    if (IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString) >= 0) {
        DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)DispatchOpenClose_104E4;// IRP_MJ_CLOSE
        DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)DispatchOpenClose_104E4;// IRP_MJ_OPEN
        DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)DispatchDeviceControl_10590;// IRP_MJ_DEVICE_CONTROL
        DriverObject->DriverUnload = (PDRIVER_UNLOAD)DriverUnload_1047C;    
    } else {
      IoDeleteDevice(DeviceObject);
    }
}
```

Initialization routine creates device `\Device\Htsysm72FB` and a symbolic link (`\DosDevices\Htsysm72FB`)
to it. The it sets the driver dispatcher routines. The only important part, is on function
`DispatchDeviceControl_10590`, which invokes a function, stored in the `SystemBuffer`:
```C
__int64 __fastcall DispatchDeviceControl_10590(__int64 a1, IRP *a2) {
  v2 = a2->Tail.Overlay.CurrentStackLocation;
  v3 = a2->AssociatedIrp.SystemBuffer;   // AssociatedIrp is a union)

  if (v2->MajorFunction == 0xE) {  // IRP_MJ_DEVICE_CONTROL
    /* ... */
    if (v2->Parameters.Read.ByteOffset.LowPart == 0xAA012044) {
        v11 = (void (__fastcall *)(_QWORD))*(unsigned int *)&v3;
    } else if (v2->Parameters.Read.ByteOffset.LowPart == 0xAA013044) {
        v11 = *(void (__fastcall **)(_QWORD))&v3;
    }

    *(_DWORD *)&v3 = invoke_func_10524(v11);
    a2->IoStatus.Information = iostat_inf;
  }

  a2->IoStatus.Status = 0xC0000002;
  IofCompleteRequest(a2, 0);
  return (unsigned int)a2->IoStatus.Status;
}
```

Note that `AssociatedIrp` is actually a union:
```C
typedef struct _IRP {
    CSHORT                    Type;
    USHORT                    Size;
    PMDL                      MdlAddress;
    ULONG                     Flags;
    union {
        struct _IRP     *MasterIrp;
        __volatile LONG IrpCount;
        PVOID           SystemBuffer;
    } AssociatedIrp;
    /* ... */
}
```

Therefore, function `invoke_func_10524` invokes function stored at `v11` with the address of
`MmGetSystemRoutineAddress` as a parameter:
```C
__int64 __fastcall invoke_func_10524(void (__fastcall *a1)(_QWORD)) {
    /* ... */
    func = (void (__fastcall *)(PVOID (__stdcall *)(PUNICODE_STRING)))a1;
    func(MmGetSystemRoutineAddress);
}
```

Overall, `cfs.dll` driver, is used to invoke other functions.


#### Driver #2 (Capcom.sys)

**Note: Driver may not be called "Capcom.sys". I just named it from cfs.dll. But it doesn't matter**

The second driver (which is the ony who actually checks the password) is the one that receives control
from dropper and execution is transfered to `DriverBootstrap`:
```C
__int64 __fastcall DriverBootstrap(__int64 a1)
{
  __int64 v1; // r8
  unsigned int i; // [rsp+20h] [rbp-78h]
  int v4; // [rsp+24h] [rbp-74h]
  char *pool; // [rsp+30h] [rbp-68h]
  __int64 image_hdr; // [rsp+38h] [rbp-60h]
  __int64 v7; // [rsp+40h] [rbp-58h]
  __int64 v8[6]; // [rsp+48h] [rbp-50h] BYREF
  char *v9; // [rsp+78h] [rbp-20h]

  memset(v8, 0, sizeof(v8));
  v4 = 0xC0000001;
  v8[0] = *(_QWORD *)a1;                        // ExAllocatePoolWithTag
  if ( v8[0] )
  {
    v8[1] = *(_QWORD *)(a1 + 8);                // ExFreePoolWithTag
    if ( v8[1] )
    {
      v8[2] = *(_QWORD *)(a1 + 0x28);           // IoCreateDriver
      if ( v8[2] )
      {
        v8[3] = *(_QWORD *)(a1 + 0x10);         // RtlImageNtHeader
        if ( v8[3] )
        {
          v8[5] = *(_QWORD *)(a1 + 0x20);       // RtlQueryModuleInformation
          if ( v8[5] )
          {
            v8[4] = *(_QWORD *)(a1 + 0x18);     // RtlImageDirectoryEntryToData
            if ( v8[4] )
            {
              image_hdr = ((__int64 (__fastcall *)(_QWORD))v8[3])(*(_QWORD *)(a1 + 48));
              pool = (char *)((__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))v8[0])(
                               0i64,
                               *(unsigned int *)(image_hdr + 80),
                               'RALF');
              if ( pool )
              {
                v7 = image_hdr + *(unsigned __int16 *)(image_hdr + 20) + 24;
                qmemcpy(pool, *(const void **)(a1 + 0x30), 8 * (*(unsigned int *)(image_hdr + 0x54) / 8ui64));
                for ( i = 0; i < *(unsigned __int16 *)(image_hdr + 6); ++i )
                  qmemcpy(
                    &pool[*(unsigned int *)(v7 + 40i64 * i + 12)],
                    (const void *)(*(_QWORD *)(a1 + 48) + *(unsigned int *)(v7 + 40i64 * i + 0x14)),
                    8 * (*(unsigned int *)(v7 + 40i64 * i + 16) / 8ui64));
                if ( (int)func_search_maybe_140003B80((__int64)v8, (__int64)pool) >= 0
                  && (int)sub_140003FE0((__int64)v8, (__int64)pool, v1) >= 0 )
                {
                  v9 = &pool[*(unsigned int *)(image_hdr + 40)];
                  if ( v9 )
                    v4 = ((__int64 (__fastcall *)(_QWORD, char *))v8[2])(0i64, v9);// IoCreateDriver
                  else
                    v4 = 0xC0000001;
                }
                if ( v4 < 0 )
                  ((void (__fastcall *)(char *, _QWORD))v8[1])(pool, 'RALF');
              }
              else
              {
                v4 = 0xC0000017;
              }
            }
          }
        }
      }
    }
  }
  return (unsigned int)v4;
}
```

This routine extracts the function addresses (as filled up by `crackstaller.exe`) and loads
a new driver (itself), so after that execution is tranfered to `DriverEntry` from the same module!
All that `DriverEntry` does is to install a registry hook:
```C
__int64 __fastcall driver_entry_140009000(struct _DRIVER_OBJECT *a1) {  
  DeviceObject = 0i64;
  memset(&Altitude, 0, sizeof(Altitude));
  memset(v6, 0, 0x100ui64);
  Altitude.Buffer = (PWSTR)v6;
  xor_very_outer_140004D60((__int64)&c_360000_140006070, 7u, (__int64)&Altitude);
  a1->DriverUnload = (PDRIVER_UNLOAD)DriverUnload_140004420;
  v2 = IoCreateDevice(a1, 0x60u, 0i64, 0x22u, 0x100u, 0, &DeviceObject);
  if ( v2 >= 0 )
  {
    v3 = (char *)DeviceObject->DeviceExtension;
    initialize_event_140004510(v3 + 8);
    KeInitializeEvent((PRKEVENT)(v3 + 64), NotificationEvent, 0);
    *(_DWORD *)v3 = 0;
    v3[88] = 0;
    v2 = CmRegisterCallbackEx((PEX_CALLBACK_FUNCTION)registry_callback_Function, &Altitude, a1, a1, &Cookie, 0i64);
  }
  if ( v2 < 0 && DeviceObject )
    IoDeleteDevice(DeviceObject);
  return (unsigned int)v2;
}
```

`CmRegisterCallbackEx` registers a hook, so every time a registry event occurs (i.e., a key is 
deleted, see `RegNtPostDeleteKey`), our `registry_callback_Function` is invoked:
```C
__int64 __fastcall registry_callback_Function(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {  
  DestinationString = 0i64;
  Str = 0i64;
  v6 = 0i64;
  memset(&Class, 0, sizeof(Class));
  v7 = 0;
  memset(v29, 0, 0x100ui64);
  Class.Buffer = (PWSTR)&v28;
  if ( Argument1 && Argument2 && CallbackContext && (_DWORD)Argument1 == 0x1A )// RegNtPostDeleteKey
  {
    v6 = *(_QWORD *)(*((_QWORD *)CallbackContext + 1) + 0x40i64);
    ExAcquireFastMutex((PFAST_MUTEX)(v6 + 8));
    if ( *(_BYTE *)(v6 + 88) )
    {
      ExReleaseFastMutex((PFAST_MUTEX)(v6 + 8));
      goto LABEL_27;
    }
    ++*(_DWORD *)(v6 + 4);
    ExReleaseFastMutex((PFAST_MUTEX)(v6 + 8));
    if ( **(_WORD **)Argument2 && **(_WORD **)(*(_QWORD *)Argument2 + 8i64) != 0x5C )
    {
      if ( !*((_QWORD *)Argument2 + 1) )
        goto LABEL_27;
      v7 = CmCallbackGetKeyObjectID(&Cookie, *((PVOID *)Argument2 + 1), 0i64, &ObjectName);
      if ( v7 >= 0 )
      {
        v5 = **(_WORD **)Argument2 + ObjectName->Length + 2;
        DestinationString = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, (unsigned int)v5 + 16, 'RALF');
        if ( DestinationString )
        {
          DestinationString->Length = 0;
          DestinationString->MaximumLength = v5;
          DestinationString->Buffer = &DestinationString[1].Length;
          RtlCopyUnicodeString(DestinationString, ObjectName);
          RtlAppendUnicodeToString(DestinationString, &Source);
          RtlAppendUnicodeStringToString(DestinationString, *(PCUNICODE_STRING *)Argument2);
        }
      }
    }
    if ( DestinationString )
      v15 = DestinationString;
    else
      v15 = *(PCUNICODE_STRING *)Argument2;
    v12 = (_UNICODE_STRING *)v15;
    Str = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, v15->Length + 2i64, 'RALF');
    if ( Str )
    {
      v18 = v12->Length + 2i64;
      memset(Str, 0, v18);
      qmemcpy(Str, v12->Buffer, v12->Length);
      guid_config_name = (const wchar_t *)xor_outer_140004DC0((__int64)&c_GUID_Config_140006040, 0x2Eu, (__int64)v29);// "{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config"
      if ( wcsstr(Str, guid_config_name) )
      {
        memset(sha256_ctx, 0, sizeof(sha256_ctx));
        memset(sha256_hashval, 0, 0x20ui64);
        memset(salsa20_ctx, 0, 0x88ui64);
        memset(ivbits, 0, sizeof(ivbits));
        memset(plaintext, 0, sizeof(plaintext));
        sha256_init_1400034F0((__int64)sha256_ctx);
        sha256_update_140003AD0((__int64)sha256_ctx, (__int64)&key_1_14000608C, 7ui64);
        sha256_final_140003120((__int64)sha256_ctx, (__int64)sha256_hashval);
        salsa20_custom_keysetup_140002760((__int64)salsa20_ctx, sha256_hashval, 0x20ui64, ivbits);
        decrypt_140002490(
          (__int64)salsa20_ctx,
          (__int64)&cipher_140006078,
          (__int64)plaintext,
          (unsigned int)cipher_len_140006088);
        Class.Length = 2 * cipher_len_140006088;
        Class.MaximumLength = 2 * (cipher_len_140006088 + 1);
        for ( i = 0; i < cipher_len_140006088; ++i )
          Class.Buffer[i] = (unsigned __int8)plaintext[i];
        v24.Length = 48;
        v24.RootDirectory = 0i64;
        v24.Attributes = 512;
        v24.ObjectName = 0i64;
        v24.SecurityDescriptor = 0i64;
        v24.SecurityQualityOfService = 0i64;
        ObjectAttributes.Length = 48;
        ObjectAttributes.RootDirectory = 0i64;
        ObjectAttributes.Attributes = 576;
        ObjectAttributes.ObjectName = v12;
        ObjectAttributes.SecurityDescriptor = 0i64;
        ObjectAttributes.SecurityQualityOfService = 0i64;
        ZwCreateKey(&KeyHandle, 0xF003Fu, &ObjectAttributes, 0, &Class, 0, *((PULONG *)Argument2 + 8));
        ObReferenceObjectByHandle(
          KeyHandle,
          *((_DWORD *)Argument2 + 14),
          *((POBJECT_TYPE *)Argument2 + 2),
          0,
          &Object,
          0i64);
        ZwClose(KeyHandle);
        *((_DWORD *)Argument2 + 15) = *((_DWORD *)Argument2 + 14);
        *((_QWORD *)Argument2 + 9) = Object;
        v7 = 0xC0000503;
        ExAcquireFastMutex((PFAST_MUTEX)(v6 + 8));
        if ( ++*(_DWORD *)v6 == 1 )
        {
          *(_BYTE *)(v6 + 88) = 1;
          v7 = PsCreateSystemThread(
                 &ThreadHandle,
                 0x10000000u,
                 &v24,
                 0i64,
                 0i64,
                 *((PKSTART_ROUTINE *)CallbackContext + 0xD),
                 CallbackContext);              // CallbackContext = _DRIVER_OBJECT
          if ( v7 >= 0 )
            ZwClose(ThreadHandle);
        }
        ExReleaseFastMutex((PFAST_MUTEX)(v6 + 8));
      }
    }
  }
LABEL_27:
  if ( Str )
    ExFreePoolWithTag(Str, 0);
  if ( DestinationString )
    ExFreePoolWithTag(DestinationString, 0);
  if ( v6 )
  {
    ExAcquireFastMutex((PFAST_MUTEX)(v6 + 8));
    if ( !--*(_DWORD *)(v6 + 4) && *(_BYTE *)(v6 + 88) )
      KeSetEvent((PRKEVENT)(v6 + 64), 0, 0);
    ExReleaseFastMutex((PFAST_MUTEX)(v6 + 8));
  }
  return (unsigned int)v7;
}
```

So what's going here? When a key is deleted from `{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config` key,
then function calculates the SHA256 checksum of `key_1_14000608C` which is constant and has the
`23 73 B5 C3 F3 16 DC` value. However recall the check from `crackstaller.exe`:
```C
    if ( *(_QWORD *)v16 == 0xDC16F3C3B57323i64 )
        strcpy(v16, "BBACABA");
```

That is this value is actually a placeholder, and gets replaced at runtime, so our key is
actually `BBACABA`. Then it uses a custom [salsa20](https://en.wikipedia.org/wiki/Salsa20)
implementation (we can infer that from `expand 32-byte k` magic constant), but the
matrix is initialized in a different way:
```
    c[0], c[1], c[2], c[3], 
    k[0], k[1], k[2], k[3],
    k[4], k[5], k[6], k[7], 
    0,    0,    0,    0
```

Then it performs `10` rounds of encryption (instead of `20`) and XORs it with our
ciphertext `cipher_140006078`:
```
    10 31 F0 8B 89 4E 73 B5 30 47 AD 6E 18 A9 5E
```

After decryption, hook updates the `Password` entry in registry.

Recovering the password is straight forward here. We just xor the ciphertext with
the key stream: `H@n $h0t FiRst!` The full crack script here: [crackstaller_crack.py](./crackstaller_crack.py)



#### DLL (credHelper.dll)

The last step of `crackstaller.exe` is to transfer execution to `DllRegisterServer` of 
`credHelper.dll`. This function create some interesting registry keys:
```C
HRESULT __stdcall DllRegisterServer() {
  memset_180003220(Filename, 0i64, 512i64);
  memset_180003220(sz, 0i64, 258i64);
  memset_180003220(v17, 0i64, 498i64);

  StringFromGUID2(&rguid, sz, 129);             // {CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}
  *(_QWORD *)SubKey = 0x490053004C0043i64;      // CLSID/
 
  v5 = RegCreateKeyExW(HKEY_CLASSES_ROOT, SubKey, 0, 0i64, 0, 0xF003Fu, 0i64, &hKey, 0i64);
  if ( v5
    || (v5 = RegSetValueExW(hKey, 0i64, 0, 1u, Data, 0x16u)) != 0
    || (v5 = RegCreateKeyExW(hKey, L"InProcServer32", 0, 0i64, 0, 0xF003Fu, 0i64, &phkResult, 0i64)) != 0
    || (v5 = RegCreateKeyExW(hKey, L"Config", 0, 0i64, 0, 0xF003Fu, 0i64, &v22, 0i64)) != 0
    || (v5 = RegSetValueExW(phkResult, 0i64, 0, 1u, (const BYTE *)Filename, v1)) != 0
    || (v5 = RegSetValueExW(phkResult, L"ThreadingModel", 0, 1u, v10, 0x14u)) != 0 )
  {
    result = (unsigned __int16)v5 | 0x80070000;
    if ( v5 <= 0 )
      result = v5;
  }
  else
  {
    RegSetValueExW(v22, L"Password", 0, 1u, (const BYTE *)&v19, 2u);
    RegSetValueExW(v22, L"Flag", 0, 1u, (const BYTE *)&v19, 2u);
    result = 0;
  }
  return result;
}
```

Similarly, the `DllUnregisterServer` cleans up all keys:
```C
HRESULT __stdcall DllUnregisterServer() {  
  memset_180003220(sz, 0, 0x102ui64);
  memset_180003220(v3, 0, 0x200ui64);
  memset_180003220(SubKey, 0, sizeof(SubKey));
  StringFromGUID2(&rguid, sz, 129);
  wsprintfW(v3, L"CLSID\\%s", sz);
  wsprintfW(SubKey, L"\\Software\\Classes\\CLSID\\%s", sz);
  RegDeleteTreeW(HKEY_LOCAL_MACHINE, SubKey);
  RegDeleteTreeW(HKEY_CURRENT_USER, SubKey);
  RegDeleteTreeW(HKEY_CLASSES_ROOT, v3);
}
```

Apart from that, there is no other execution flow. 

However there are two interesting functions (`verify_password_18000153C` and
`set_flag_1800016D8`) that have no XREFs to (which means that they are invoked
from a kernel driver). The first function reads the password from registry and
initializes an RC4 keystream:

```C
__int64 __fastcall verify_password_18000153C(__int64 a1, _WORD *a2) {
  memset_180003220(pvData, 0, sizeof(pvData));
  memset_180003220(SubKey, 0, sizeof(SubKey));
  memset_180003220(sz, 0, 0x102ui64);
  StringFromGUID2(&rguid, sz, 129);
  wsprintfW(SubKey, L"%s\\%s\\%s", L"CLSID", sz, L"Config");
  v3 = 0;
  if ( RegGetValueW(HKEY_CLASSES_ROOT, SubKey, L"Password", 2u, 0i64, pvData, &pcbData) )
    return 0x80004005;
  if ( pcbData <= 2 )
    return 0x80004005;
  unicode_to_ascii_180005A2C((__int64)key, (__int64)pvData, 260i64);
  if ( v4 == 260 || v4 == -1 )
    return 0x80004005;
  
  v5 = (char *)(a2 + 1);
  *a2 = 0;
  S = a2 + 1;
  LOBYTE(v7) = 0;
  v8 = 0;
  it = 0;
  iterator = 256i64;
  do
  {
    *(_BYTE *)S = it++;
    S = (_WORD *)((char *)S + 1);
  }
  while ( it < 256 );
  v11 = v4;
  i = 0i64;
  v13 = v5;
  do                                            // RC4!
  {
    v14 = *v13;
    i_2 = i + 1;
    v16 = key[i];
    i = 0i64;
    v7 = (unsigned __int8)(v7 + *v13 + v16);
    *v13++ = v5[v7];
    v5[v7] = v14;
    v17 = v8 + 1;
    v8 = 0;
    if ( i_2 < v11 )
      v8 = v17;
    if ( i_2 < v11 )
      i = i_2;
    --iterator;
  }
  while ( iterator );
  return v3;
}
```

The second function XORs the flag with a keystream that comes from the second parameter (`a2`)
and updates the registry value:
```C
void __fastcall set_flag_1800016D8(__int64 a1, unsigned __int8 *a2)
{
  unsigned __int8 v3; // r10
  __int64 v4; // r9
  unsigned __int8 v5; // r11
  unsigned __int8 v6; // r8
  unsigned __int8 v7; // cl
  int v8; // eax
  int v9; // edi
  char Source[16]; // [rsp+30h] [rbp-D0h] BYREF
  __int128 v11; // [rsp+40h] [rbp-C0h]
  __int64 v12; // [rsp+50h] [rbp-B0h]
  int v13; // [rsp+58h] [rbp-A8h]
  char v14; // [rsp+5Ch] [rbp-A4h]
  wchar_t Data[96]; // [rsp+60h] [rbp-A0h] BYREF
  OLECHAR sz[136]; // [rsp+120h] [rbp+20h] BYREF
  WCHAR SubKey[256]; // [rsp+230h] [rbp+130h] BYREF
  HKEY hKey; // [rsp+448h] [rbp+348h] BYREF

  memset_180003220(SubKey, 0, sizeof(SubKey));
  memset_180003220(sz, 0, 0x102ui64);
  v12 = 0i64;
  v13 = 0;
  v14 = 0;
  *(_OWORD *)Source = 0i64;
  v11 = 0i64;
  memset_180003220(Data, 0, 0xB4ui64);
  v3 = *a2;
  v4 = 0i64;
  v5 = a2[1];
  do
  {
    v6 = a2[++v3 + 2];
    v5 += v6;
    v7 = a2[v5 + 2];
    a2[v3 + 2] = v7;                            // RC4 swap?
    a2[v5 + 2] = v6;
    Source[v4] = keystream_18001A9F0[v4] ^ a2[(unsigned __int8)(v6 + v7) + 2];
    ++v4;
  }
  while ( v4 < 44 );
  *a2 = v3;
  a2[1] = v5;
  v8 = mbstowcs(Data, Source, 0x2Dui64);
  v9 = v8;
  if ( v8 != -1 && v8 != 0x2D )
  {
    StringFromGUID2(&rguid, sz, 129);
    wsprintfW(SubKey, L"%s\\%s\\%s", L"CLSID", sz, L"Config");
    if ( !RegOpenKeyExW(HKEY_CLASSES_ROOT, SubKey, 0, 0x20006u, &hKey) )
      RegSetValueExW(hKey, L"Flag", 0, 1u, (const BYTE *)Data, 2 * v9);
  }
}
```

We can easily infer that these functions are related: `verify_password_18000153C`
reads the password and generates an RC4 keystream from the password and then
`set_flag_1800016D8` uses this keystream to decrypt the flag. The encrypted
flag is shown below:
```
16 56 BC 86 9E E1 D1 02  65 C1 69 9F 10 0A AC C1
F6 E9 FD B4 CD 22 4A 35  9C 12 73 BD 2B 10 54 B9
43 D2 13 9A 84 65 AD B0  BF 5A 81 10
```

Knowing that the password is `H@n $h0t FiRst!`, we can do a vanilla RC4 to the
above cipher text and get the flag.

For more details please take a look at the crack file: [crackstaller_crack.py](./crackstaller_crack.py)

The password is: `H@n $h0t FiRst!`

The flag is: `S0_m@ny_cl@sse$_in_th3_Reg1stry@flare-on.com`

___
