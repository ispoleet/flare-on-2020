## Flare-On 2021 - #7: Spel
___

### Description: 

*Pro-tip: start disassembling this one then take a nice long break, you've earned it kid.*

`7-zip password: flare`

___

### Solution:


The challenge binary (`spel.exe`) performs some spell checking using dictionaries (which is
irrelevant to the challenge). If we want to enable the buttons and play with the program, 
we can patch the following code and set `dl` to `1`:
```Assembly
.text:000000013F22A9BF         mov     rcx, rax                ; this
.text:000000013F22A9C2         mov     dl, 0                   ; a2
.text:000000013F22A9C4         call    ?EnableWindow@CWnd@@QEAAHH@Z ; CWnd::EnableWindow(int)
.text:000000013F22A9C9         mov     edx, 3F6h               ; int
.text:000000013F22A9CE         mov     rcx, rdi                ; this
.text:000000013F22A9D1         call    ?GetDlgItem@CWnd@@QEBAPEAV1@H@Z ; CWnd::GetDlgItem(int)
.text:000000013F22A9D6         mov     rcx, rax                ; this
.text:000000013F22A9D9         mov     dl, 0                   ; a2
.text:000000013F22A9DB         call    ?EnableWindow@CWnd@@QEAAHH@Z ; CWnd::EnableWindow(int)
```

If we scroll down to the functions, it is easy to see that there is a huge function
`u_GIANT_SHELLCODE`, located at `13F0B2CB0h`, which is **1534665** bytes long. This function
initializes a huge shellcode and then invokes it:
```assembly
.text:000000013F0B2D55         lea     rdx, aVirtualallocex    ; "VirtualAllocExNuma"
.text:000000013F0B2D5C         mov     rcx, [rsp+2F038h+var_2EFF0]
.text:000000013F0B2D61         call    cs:GetProcAddress
.text:000000013F0B2D67         mov     [rsp+2F038h+var_2EFE8], rax
.text:000000013F0B2D6C         call    cs:GetCurrentProcess
.text:000000013F0B2D72         mov     [rsp+2F038h+var_2EFE0], rax
.text:000000013F0B2D77         mov     [rsp+2F038h+var_2ED48], 0E8h ; 'è'
.text:000000013F0B2D7F         mov     [rsp+2F038h+var_2ED47], 0
.text:000000013F0B2D87         mov     [rsp+2F038h+var_2ED46], 0
.text:000000013F0B2D8F         mov     [rsp+2F038h+var_2ED45], 0
.text:000000013F0B2D97         mov     [rsp+2F038h+var_2ED44], 0
.text:000000013F0B2D9F         mov     [rsp+2F038h+var_2ED43], 59h ; 'Y'
.text:000000013F0B2DA7         mov     [rsp+2F038h+var_2ED42], 49h ; 'I'
.text:000000013F0B2DAF         mov     [rsp+2F038h+var_2ED41], 89h ; '‰'

[..... TRUNCATED FOR BREVITY .....]

.text:000000013F2296AF         mov     byte ptr [rsp+2F017h], 0
.text:000000013F2296B7         mov     byte ptr [rsp+2F018h], 66h ; 'f'
.text:000000013F2296BF         mov     byte ptr [rsp+2F019h], 6Ch ; 'l'
.text:000000013F2296C7         mov     byte ptr [rsp+2F01Ah], 61h ; 'a'
.text:000000013F2296CF         mov     byte ptr [rsp+2F01Bh], 72h ; 'r'
.text:000000013F2296D7         mov     byte ptr [rsp+2F01Ch], 65h ; 'e'
.text:000000013F2296DF         mov     dword ptr [rsp+38h], 2ED2Dh
.text:000000013F2296E7         mov     eax, [rsp+38h]
.text:000000013F2296EB         mov     dword ptr [rsp+28h], 0
.text:000000013F2296F3         mov     dword ptr [rsp+20h], 40h ; '@'
.text:000000013F2296FB         mov     r9d, 3000h
.text:000000013F229701         mov     r8d, eax
.text:000000013F229704         xor     edx, edx
.text:000000013F229706         mov     rcx, [rsp+58h]
.text:000000013F22970B         call    cs:VirtualAllocExNuma
.text:000000013F229711         mov     [rsp+60h], rax
.text:000000013F229716         mov     eax, [rsp+38h]
.text:000000013F22971A         mov     r8d, eax
.text:000000013F22971D         lea     rdx, [rsp+2F0h]
.text:000000013F229725         mov     rcx, [rsp+60h]
.text:000000013F22972A         call    memmove

.text:000000013F22972F         call    qword ptr [rsp+60h]     ; invoke the shellcode

.text:000000013F229733         mov     dword ptr [rsp+3Ch], 0
.text:000000013F22973B         lea     rcx, [rsp+70h]
.text:000000013F229740         call    sub_13F0B2BD0
.text:000000013F229745         mov     eax, [rsp+3Ch]
```

We set a breakpoint at `memmove` and we dump the shellcode into a `shellcode` array. To make
reversing easier, we create a new program, [shellcode.c](./shellcode.c) that invokes this shellcode:
```c
int main() {
    HANDLE hproc = GetCurrentProcess();
    DWORD oldprot = 0;

    if (!VirtualProtectEx(hproc,
                          (LPVOID)((QWORD)&shellcode & 0xFFFFF000),
                          sizeof(shellcode) + 0x1000,
                          PAGE_EXECUTE_READWRITE,
                          &oldprot)) {
        return -1;
    }


  (*(int(*)()) shellcode)();

  return 0;
}
```

### Reversing Shellcode (Stage #1)

The first function that is invoked in the shellcode is `qword ptr [rsp+60h]`:
```c
void __fastcall shellcode() {
  u_main_shellcode(&glo_stage2_dll, 0x45A75CAA, 0x431D48, 5, 0);
}
```

The first task of `u_main_shellcode`, is to initialize the environment and perform all relocations
that the required for the code to run. Function `u_lookup_func_from_hash` is used to find a Windows
API function address using the ordinal number.
```c
// local variable allocation has failed, the output may be wrong!
void __fastcall u_main_shellcode(char *a1_stage2_dll, int a2_const1, int a3_const2, int a4_5, int a5_0) {
  v90[1] = 0x6E0072;
  v90[2] = 0x6C0065;
  v90[3] = 0x320033;
  v90[4] = 0x64002E;
  v90[5] = 0x6C006C;
  qmemcpy(v80, "Sleep", 5);
  qmemcpy(v82, "LoadLibraryA", 12);
  qmemcpy(v81, "VirtualAlloc", 12);
  qmemcpy(v83, "VirtualProtect", 14);
  qmemcpy(v86, "FlushInstructionCache", 21);
  qmemcpy(v84, "GetNativeSystemInfo", 19);
  qmemcpy(v85, "RtlAddFunctionTable", 19);
  LdrLoadDll = u_lookup_func_from_hash(0xBDBF9C13);
  LdrGetProcedureAddress_ = u_lookup_func_from_hash(0x5ED941B5);
  LdrGetProcedureAddress = LdrGetProcedureAddress_;
  v97[0] = 0x180018;
  v98 = v90;
  (LdrLoadDll)(0i64, 0i64, v97, &kernel32_base);// load kernel32.dll
  v78 = v81;
  ordinal = 0xC000C;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &VirtualAlloc);
  v78 = v83;
  ordinal = 0xE000E;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &VirtualProtect);
  ordinal = 0x150015;
  v78 = v86;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &FlushInstructionCache);
  v78 = v84;
  ordinal = 0x130013;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &GetNativeSystemInfo);
  v78 = v80;
  ordinal = 0x50005;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &Sleep);
  v78 = v85;
  ordinal = 0x130013;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &RtlAddFunctionTable);
  v78 = v82;
  ordinal = 786444;
  LdrGetProcedureAddress_(kernel32_base, &ordinal, 0i64, &LoadLibraryA);

  /* ..... TRUNCATED FOR BREVITY ..... */

  /* Allocate some memory and copy the stage 2 payload. */
  GetNativeSystemInfo(&system_info);
  v14 = -system_info.dwPageSize & (*(v8 + 20) + system_info.dwPageSize - 1);
  if ( v14 == (~(system_info.dwPageSize - 1i64) & (v9 + system_info.dwPageSize - 1i64)) ) {
    alloc_mem = VirtualAlloc(
                  *(v8 + 6),
                  -system_info.dwPageSize & (*(v8 + 20) + system_info.dwPageSize - 1),
                  0x3000i64,
                  4i64);
    if ( !alloc_mem )
      alloc_mem = VirtualAlloc(0i64, v14, 0x3000i64, 4i64);
    if ( (a5_0 & 1) != 0 ) {
      *(alloc_mem + 15) = *(a1_stage2_dll + 15);
      i = *(a1_stage2_dll + 15);
      while ( i < *(v8 + 21) ) {
        v18 = i;
        i = (i + 1);
        alloc_mem[v18] = a1_stage2_dll[v18];
      }
    }
    else {                               // copy MZ file (dll) - Header only
      for ( i = 0i64; i < *(v8 + 21); alloc_mem[i_3] = a1_stage2_dll[i_3] ) {
        i_3 = i;
        i = (i + 1);
      }
    }

    v20 = 0;
    v21 = &alloc_mem[*(alloc_mem + 15)];
    v99 = v21;
    if ( *(v21 + 3) ) {
      v22 = &v21[*(v21 + 10) + 40];
      do {                           // copy more code
        for ( j = 0i64; j < *v22; alloc_mem[v23 + *(v22 - 1)] = a1_stage2_dll[i] ) {
          v23 = j;
          j = (j + 1);
          i = v23 + *(v22 + 1);
        }
        ++v20;
        v22 += 40;
      } while ( v20 < *(v21 + 3) );
    }

    /* ..... TRUNCATED FOR BREVITY ..... */

    /* Load kernel32.dll and other DLLs and resolve all functions from IAT */
    if ( v41 ) {
      v42 = v87;
      do {
        kernel32_base = LoadLibraryA(&alloc_mem[v41], i, v24, j);// load: "KERNEL32.dll"
        kernel32_base_ = kernel32_base;
        v44 = &alloc_mem[*v40];
        kernel32_IAT = &alloc_mem[*(v40 + 4)];
        v46 = *v44;
        if ( *v44 ) {              // resolve all function addresses from kernel32.dll
          while ( 1 ) {
            if ( v46 >= 0 ) {
              i_1 = 0;
              v50 = &alloc_mem[v46 + 2];
              if ( *v50 ) {
                func_name_ptr = &alloc_mem[v46 + 2];
                do {
                  ++func_name_ptr;
                  ++i_1;
                } while ( *func_name_ptr );
              }
              v78 = v50;
              v47 = 0i64;
              p_ordinal = &ordinal;
              LOWORD(ordinal) = i_1;
              HIWORD(ordinal) = i_1;
            }
            else {
              v47 = *v44;
              p_ordinal = 0i64;
            }
            LdrGetProcedureAddress(kernel32_base_, p_ordinal, v47, kernel32_IAT);
            v44 += 8;
            kernel32_IAT += 8;
            v46 = *v44;
            if ( !*v44 )
              break;
            kernel32_base_ = kernel32_base;
          }
        }
        if ( v42 && v32 > 1 ) Sleep(1000 * v35);
        v41 = *(v40 + 8);
        v40 += 20;
      } while ( v41 );
      v21 = v99;
    }
    LdrGetProcedureAddress_ = LdrGetProcedureAddress;
  }

  /* Use VirtualProtect to adjust all segment permissions */


PERMISSIONS_OKAY:
  FlushInstructionCache(-1i64, 0i64, 0i64, j);
  if ( *(v21 + 53) ) {
    for ( ii = *&alloc_mem[*(v21 + 0x34) + 24]; *ii; ++ii )
      (*ii)(alloc_mem, 1i64, 0i64);
  }
  if ( RtlAddFunctionTable ) {
    v67 = *(v21 + 41);
    if ( v67 )
      RtlAddFunctionTable(&alloc_mem[*(v21 + 0x28)], v67 / 0xC - 1, alloc_mem);
  }
  
  // invoke DllEntryPoint from stage_2.dll
  (&alloc_mem[*(v21 + 0xA)])(alloc_mem, 1i64, 1i64); // !!!!
  
  
  /* Tear down */
```

This function does nothring more than preparing the envirnoment for the stage 2 payload. We let code
to run and then we use the following IDA python line to dump the new payload into a new file:
```python
open('stage_2.dll', 'wb').write(bytes([ida_bytes.get_byte(0x180000000+i) for i in range(0x33000)]))
```

### Reversing stage_2.dll

Stage #2 payload ([stage_2.dll](./stage_2.dll)) is quite smaller (**208896** bytes) and its main
purpose is to load the Stage #3 payload, so it is not much interesting.

To make analysis simpler, we first run then program and we let it to resolve all the function
imports. Then we dump the imported function names and we use them to rename the global symbols:
```python
func_names = [
    'ExitProcess', 'VirtualProtect', 'HeapFree', 'SetLastError', 'VirtualFree', 'VirtualAlloc',
    'LoadLibraryA', 'GetNativeSystemInfo', 'HeapAlloc', 'GetProcAddress', 'GetProcessHeap',
    'FreeLibrary', 'IsBadReadPtr', 'RtlCaptureContext', 'RtlLookupFunctionEntry',
    'RtlVirtualUnwind', 'UnhandledExceptionFilter', 'SetUnhandledExceptionFilter',
    'GetCurrentProcess', 'TerminateProcess', 'IsProcessorFeaturePresent',
    'QueryPerformanceCounter', 'GetCurrentProcessId', 'GetCurrentThreadId',
    'GetSystemTimeAsFileTime', 'InitializeSListHead', 'IsDebuggerPresent', 'GetStartupInfoW',
    'GetModuleHandleW', 'RtlUnwindEx', 'InterlockedFlushSList', 'GetLastError',
    'EnterCriticalSection', 'LeaveCriticalSection', 'DeleteCriticalSection',
    'InitializeCriticalSectionAndSpinCount', 'TlsAlloc', 'TlsGetValue', 'TlsSetValue', 'TlsFree',
    'LoadLibraryExW', 'GetModuleHandleExW', 'GetModuleFileNameA', 'MultiByteToWideChar',
    'WideCharToMultiByte', 'GetStringTypeW', 'GetACP', 'HeapReAlloc', 'LCMapStringW',
    'FindClose', 'FindFirstFileExA', 'FindNextFileA', 'IsValidCodePage', 'GetOEMCP', 'GetCPInfo',
    'GetCommandLineA', 'GetCommandLineW', 'GetEnvironmentStringsW', 'FreeEnvironmentStringsW',
    'GetStdHandle', 'GetFileType', 'HeapSize', 'SetStdHandle', 'WriteFile', 'FlushFileBuffers',
    'GetConsoleCP', 'GetConsoleMode', 'SetFilePointerEx', 'CloseHandle', 'WriteConsoleW',
    'CreateFileW', 'RaiseException']

for i, name in enumerate(func_names):
  set_name(0x18000D000 + i*8, 'glo_%s' % name)
```

Similar to Stage #1, Stage #2 allocates some memory to drop Stage #3 payload, initializes the
environment and performs the required relocations. Everything starts from `DllEntryPoint` at
`180002E74h`:
```c
__int64 __fastcall u_DllEntryPoint_main(HINSTANCE a1, __int64 a2, void *a3) {
  if ( !a2 && dword_18002E330 <= 0 ) return 0;

  if ( (a2 - 1) > 1 || (v7 = dllmain_raw(a1, a2, a3)) != 0 && (v7 = sub_180002C74(a1, a2_, a3)) != 0 ) {
    v8 = u_load_and_invoke_Start_from_stage_3();
    v7 = v8;
    if ( a2 == 1 && !v8 ) {
      u_load_and_invoke_Start_from_stage_3();
      sub_180002C74(a1, 0, a3);
      dllmain_raw(a1, 0i64, a3);
    }

    if ( !a2 || a2 == 3 ) {
      v7 = sub_180002C74(a1, a2_, a3);
      if ( v7 ) return dllmain_raw(a1, a2_, a3);
    }
  }
  return v7;
}
```

As its name suggests, `u_load_and_invoke_Start_from_stage_3` at `180001000h` (the very first
function in the DLL), loads Stage #3 and invokes `Start` routine:
```c
__int64 u_load_and_invoke_Start_from_stage_3() {
  char *stage_3_Start; // [rsp+38h] [rbp-10h]

  load_malware_wrapper(&unk_1800168F0, 0x17A00);
  stage_3_Start = sub_1800027D0(v0, &unk_1800168E0);
  (stage_3_Start)(v2, v1, v3, v4);
  return glo_ExitProcess(0);
}
```

The `load_malware_wrapper` at `180001FD0h` is a wrapper for `180002030h` that drops the new payload
and does all required initializations:
```c
void __fastcall sub_180002030(
    char* a1_stage_3, __int64 a2, void *a3_VirtualAlloc, void *a4_VirtualFree, int a5_LoadLibrary,
    int a6_GetProcAddress, int a7_FreeLibrary, int a8_0) {
  /* DECLS */

  v18 = 0i64;
  v15 = 0i64;
  if ( check_size(a2, 0x40ui64) ) {
    if ( *a1_stage_3 != 0x5A4D )                // starts with MZ ?
      goto LABEL_8;
    if ( !check_size(a2, *(a1_stage_3 + 15) + 264i64) ) { /* ERROR */ }
    
    v12 = &a1_stage_3[*(a1_stage_3 + 15)];
    if ( *v12 != 0x4550 || *(v12 + 2) != 34404 || (*(v12 + 14) & 1) != 0 ) { /* ERROR */ }

    v14 = &v12[*(v12 + 10) + 24];
    for ( i = 0; i < *(v12 + 3); ++i )
    {
      if ( *(v14 + 16) )
        v8 = (*(v14 + 16) + *(v14 + 12));
      else
        v8 = *(v12 + 14) + *(v14 + 12);
      if ( v8 > v18 )
        v18 = v8;
      v14 += 40i64;
    }

    glo_GetNativeSystemInfo(v21);
    v16 = sub_1800010C0(*(v12 + 20), v22);
    if ( v16 != sub_1800010C0(v18, v22) ) { /* ERROR */ }

    alloc = (a3_VirtualAlloc)(*(v12 + 6), v16, 0x3000i64, 4i64, *&a8_0);
    if ( !alloc ) {
      alloc = (a3_VirtualAlloc)(0i64, v16, 12288i64, 4i64, *&a8_0);
      if ( !alloc ) { /* ERROR */ }
    }

    while ( HIDWORD(alloc) < (v16 + alloc) >> 32 ) {
      v17 = j__malloc_base(0x10ui64);
      if ( !v17 )
        goto LABEL_24;
      *v17 = v15;
      v17[1] = alloc;
      v15 = v17;
      alloc = (a3_VirtualAlloc)(0i64, v16, 12288i64, 4i64, *&a8_0);
      if ( !alloc ) { /* ERROR */ }
    }

    ProcessHeap = glo_GetProcessHeap();         // GetProcessHeap
    alloc_h = glo_HeapAlloc(ProcessHeap, 8i64, 120i64);
    if ( !alloc_h ) { /* ERROR */ }

    *(alloc_h + 1) = alloc;
    *(alloc_h + 8) = (*(v12 + 11) & 0x2000) != 0;
    *(alloc_h + 5) = a3_VirtualAlloc;
    *(alloc_h + 6) = a4_VirtualFree;
    *(alloc_h + 7) = a5_LoadLibrary;
    *(alloc_h + 8) = a6_GetProcAddress;
    *(alloc_h + 9) = a7_FreeLibrary;
    *(alloc_h + 11) = *&a8_0;
    *(alloc_h + 26) = v22;
    *(alloc_h + 14) = v15;

    if ( check_size(a2, *(v12 + 21)) ) {
      alloc_2 = (a3_VirtualAlloc)(alloc, *(v12 + 21), 4096i64, 4i64, *&a8_0);
      qmemcpy(alloc_2, a1_stage_3, *(v12 + 21));
      *alloc_h = &alloc_2[*(a1_stage_3 + 15)];
      *(*alloc_h + 48i64) = alloc;
      if ( sub_1800011D0(a1_stage_3, a2, v12, alloc_h) )
      {
        v20 = *(*alloc_h + 48i64) - *(v12 + 6);
        *(alloc_h + 9) = !v20 || sub_180001990(alloc_h, v20);
        if ( sub_180001B70(alloc_h) && sub_180001680(alloc_h) && sub_1800018E0(alloc_h) ) {
          if ( !*(*alloc_h + 40i64) ) {
            *(alloc_h + 12) = 0i64;
            return;
          }
          if ( !*(alloc_h + 8) ) {
            *(alloc_h + 12) = *(*alloc_h + 40i64) + alloc;
            return;
          }

          if ( ((*(*alloc_h + 40i64) + alloc))(alloc, 1i64, 0i64) ) {
            *(alloc_h + 7) = 1;
            return;
          }
          
          glo_SetLastError(1114i64);
        }
      }
    }
    sub_180002AF0(alloc_h);
  }
}
```

After that, routine `(stage_3_Start)(v2, v1, v3, v4)` is invoked and execution gets transferred to
Stage #3. To get the new payload we use the following line (hit from `sub_180002030`):
```python
open('stage_3.dll', 'wb').write(bytes([ida_bytes.get_byte(0x1800168F0+i) for i in range(0x17A00)]))
```

### Reversing stage_3.dll

Stage #3 payload ([stage_3.dll](./stage_3.dll)) is even smaller (**96768** bytes) and it is the last
layer of protection. This is where flag is computed. This is how `Start` at `2C1010h` is defined:
```c
int _stdcall Start() {
  u_start_from_here();
  return 0;
}

void u_start_from_here() {
  /* DECLS */

  u_decrypt_dll_strings();
  VirtualAlloc = u_get_proc_address_using_ordinal(0i64, 1, 0x697A6AFE);
  // MEM_RESERVE | MEM_COMMIT
  v1 = (ispo_struct *)((__int64 (__fastcall *)(_QWORD, __int64, __int64, __int64))VirtualAlloc)(
                        0i64,
                        0x1E0i64,
                        0x3000i64,
                        4i64);
  sub_2C1A40(v1, 1);
  mode = 8;
  if ( u_check_if_filename_is_spell_exe(v1->MM_dd_yyyy) )
    mode = v1->two;                             // mode = 2
  dword_2D78E0 = 6;
  sleep = 360000;
  if ( mode == 64 )
    sleep = 300000;
  SleepEx = u_get_proc_address_using_ordinal(0i64, 1, 0x5CBD6D9E);
  ((void (__fastcall *)(_QWORD, _QWORD))SleepEx)(sleep, 0i64);
  sub_2C1A40(v1, mode);
}
```

Function `u_decrypt_dll_strings` at `2C1380h` uses a XOR decryption with random keys, to decrypt
the DLL names (e.g., `ws2_32.dll`, `kernel32.dll` and so on). The important function is `sub_2C1A40`
where it has **2** modes of operation based on the 2nd parameter:
```c
void __fastcall sub_2C1A40(ispo_struct *a1, int a2_mode) {
  /* DECLS */

  if ( a2_mode == 1 ) {
    VirtualAlloc = u_get_proc_address_using_ordinal(0i64, 1, 0x697A6AFE);
    v4 = 33;
    a1->aes_key = (VirtualAlloc)(0i64, 33i64, 12288i64, 4i64);
    v40 = 0;
    some_md5[0] = 0x642FF22C;                   // d41d8cd98f00b204e9800998ecf8427e
    some_md5[1] = 0x397AA570;
    some_md5[2] = 0x302EA070;
    some_md5[3] = 0x342EF42A;
    some_md5[4] = 0x3026FF2D;
    some_md5[5] = 0x3827FF78;
    some_md5[6] = 0x3878A52D;
    some_md5[7] = 0x6529F47C;
    some_md5[8] = 0x1EC648;
    for ( i = 0i64; i < 9; ++i )
      some_md5[i] ^= 0x1EC648u;
    aes_key = a1->aes_key;

    if ( aes_key ) {
      v7 = (some_md5 - aes_key);
      do {                          // copy
        *aes_key = aes_key[v7];
        ++aes_key;
        --v4;
      } while ( v4 );
    }

    GetModuleFileNameA = u_get_proc_address_using_ordinal(0i64, 1, 0x774393E8);
    (GetModuleFileNameA)(0i64, a1->module_file_name, 0x104i64);
    GetModuleHandleA = u_get_proc_address_using_ordinal(0i64, 1, 0xA48D6762);
    module_hdl = (GetModuleHandleA)(0i64);
    v35 = 'GNP';
    FindResourceA = u_get_proc_address_using_ordinal(0i64, 1, 0x8FE060C);
    v12 = (FindResourceA)(module_hdl, 128i64, &v35);
    SizeOfResource = u_get_proc_address_using_ordinal(0i64, 1, 0x86867F0E);
    a1->resource_size = (SizeOfResource)(module_hdl, v12);
    LoadResource = u_get_proc_address_using_ordinal(0i64, 1, 0x1A10BD8B);
    resource_hdl = (LoadResource)(module_hdl, v12);
    LockResource = u_get_proc_address_using_ordinal(0i64, 1, 0x1510BD8A);
    a1->loaded_resource = (LockResource)(resource_hdl);
    a1->two = 2;

LABEL_26:
    GetCurrentProcess = u_get_proc_address_using_ordinal(0i64, 1, 0xD89AD05);
    v33 = (GetCurrentProcess)(v32);
    IsWow64Process = u_get_proc_address_using_ordinal(0i64, 1, 0x52AC19C);
    (IsWow64Process)(v33, &a1->is_wow_64);
    a1->three = 3;
    u_decrypt_inactive_str(a1);
    u_get_current_date(a1);
    return;
  }

  if ( a2_mode != 2 ) {
    if ( a2_mode == 8 ) {
      inside_ntdll = u_get_proc_address_using_ordinal(0i64, 1, 0x95902B19);
      inside_ntdll();                           // KILL PROC!
    }

    goto LABEL_26;
  }


  VirtualAlloc_1 = u_get_proc_address_using_ordinal(0i64, 1, 0x697A6AFE);
  a1->flareon_str = (VirtualAlloc_1)(0i64, 32i64, 12288i64, 4i64);
  key_name_4 = 0;
  flareon_str[0] = 0x24745716;                  // flare-on.com
  flareon_str[1] = 0x387A1615;
  flareon_str[2] = 0x3B7A585E;
  flareon_str[3] = 0x56153B70;
  for ( j = 0i64; j < 4; ++j )
    flareon_str[j] ^= 0x56153B70u;
  v19 = a1->flareon_str;
  v20 = 13;
  if ( v19 )
  {
    v21 = (flareon_str - v19);
    do {
      *v19 = v19[v21];
      ++v19;
      --v20;
    } while ( v20 );
  }

  if ( u_try_to_connect(a1) ) {
    v22 = xored_val;
    v23 = 0;
    v24 = a1->flareon_str - xored_val;
    *xored_val = _mm_load_si128(&xmmword_2D5170);// 8A 1D 89 15 14 9F C1 1D  99 7E 8A 1B
    v43 = 0i64;
    while ( 1 )
    {
      v25 = a1->flareon_str;                    // "flare-on.com"
      v26 = v25 ? strnlen(v25, 0x20ui64) : 0i64;
      if ( v23 > v26 )
        break;
      ++v23;
      *v22 ^= *(v22 + v24);                     // xor 8A 1D ... with "flare-on.com"
      v22 = (v22 + 1);
    }
    v36 = 0;
    key_name = '1';
    lstrlenA = u_get_proc_address_using_ordinal(0i64, 1, 0x2D40B8E6);
    v28 = (lstrlenA)(xored_val);

    u_write_to_regkey(a1, xored_val, v28 + 1, &key_name);
    if ( !u_AES_decrypt(a1, (a1->loaded_resource + 0x5F)) ) {
      ntdll_exit = u_get_proc_address_using_ordinal(0i64, 1, 0x95902B19);
      ntdll_exit();
    }
    
    u_final_xor_decrypt(a1);
  }
}
```

When `mode` is **1**, function loads the `"PNG"` resource and returns. When the `mode` is **2** 
program performs the actual flag decryption. Recall from `u_start_from_here` how `mode` is set:
```c
  mode = 8;
  if ( u_check_if_filename_is_spell_exe(v1->MM_dd_yyyy) )
    mode = v1->two;                             // mode = 2
```

That is, if the binary is named "spell.exe" then `mode` is set to **2**. Otherwise `mode`
becomes **8**. When `mode` is **2**, function invokes `u_try_to_connect` at `2C1F80h`, where it
repeatedly (**10** times) tries to connect to `inactive.flare-on.com:888`. Server is obviously
"inactive", so we can ignore that communication as well. If connection is successful, function
decrypts the `flare-on.com` string, it XORs it with a random string and writes it to the Registry
(using `u_write_to_regkey`). This is just a *decoy*. Then it invokes `u_AES_decrypt` at `2C2F70h`
where it performs the actual decryption:
```c
__int64 __fastcall u_AES_decrypt(ispo_struct *a1, char *a2_buf) {
  /* DECLS */
  aes[0] = 0x56503B31;                          // AES (UNICODE)
  aes[1] = 0x56153B23;
  for ( i = 0i64; i < 2; ++i )
    aes[i] ^= 0x56153B70u;
  BCryptOpenAlgorithmProvider = u_get_proc_address_using_ordinal(0i64, 11, -604958260);
  if ( (BCryptOpenAlgorithmProvider)(&v45, aes, 0i64, 0i64) >= 0 ) {
    LOBYTE(v38) = 0;
    object_length[0] = 0xB93365E;               // ObjectLength (UNICODE)
    object_length[1] = 0xB94367B;
    object_length[2] = 0xB853672;
    object_length[3] = 0xB94365D;
    object_length[4] = 0xB96367F;
    object_length[5] = 0xB993665;
    object_length[6] = 0xBF13611;
    for ( j = 0i64; j < 7; ++j )
      object_length[j] ^= 0xBF13611u;
    v9 = v45;
    BCryptGetProperty = u_get_proc_address_using_ordinal(0i64, 11, 928081727);
    if ( (BCryptGetProperty)(v9, object_length, &v44, 4i64, &pbIV, 0) >= 0 )
    {
      GetProcessHeap = u_get_proc_address_using_ordinal(0i64, 1, 1753248596);
      heap = GetProcessHeap();
      v13 = v44;
      v14 = heap;
      ntdll_func = u_get_proc_address_using_ordinal(0i64, 1, 1431351399);
      pbKeyObject = (ntdll_func)(v14, 0i64, v13);
      if ( pbKeyObject )
      {
        v42 = 0;
        ChainingModeCBC[0] = 0x26E1C042;        // ChainingModeCBC
        ChainingModeCBC[1] = 0x26E0C060;
        ChainingModeCBC[2] = 0x26E0C06F;
        ChainingModeCBC[3] = 0x26EEC06F;
        ChainingModeCBC[4] = 0x26E6C04C;
        ChainingModeCBC[5] = 0x26ECC065;
        ChainingModeCBC[6] = 0x26CBC042;
        ChainingModeCBC[7] = 0x2689C042;
        for ( k = 0i64; k < 8; ++k )
          ChainingModeCBC[k] ^= 0x2689C001u;
        v40 = 0;
        ChainingMode[0] = 0x97C9654;            // ChainingMode
        ChainingMode[1] = 0x97D9676;
        ChainingMode[2] = 0x97D9679;
        ChainingMode[3] = 0x9739679;
        ChainingMode[4] = 0x97B965A;
        ChainingMode[5] = 0x9719673;
        ChainingMode[6] = 0x9149617;
        for ( m = 0i64; m < 7; ++m )
          ChainingMode[m] ^= 0x9149617u;
        v18 = v45;
        BCryptSetProperty = u_get_proc_address_using_ordinal(0i64, 11, 928080447);

        if ( BCryptSetProperty(v18, ChainingMode, ChainingModeCBC, 32i64, 0) >= 0 ) {
          aes_key = a1->aes_key;
          cbKeyObject = v44;
          hAlgorithm = v45;
          BCryptGenerateSymmetricKey = u_get_proc_address_using_ordinal(0i64, 11, 1193324930);
          if ( (BCryptGenerateSymmetricKey)(
                 hAlgorithm,
                 &phKey,
                 pbKeyObject,
                 cbKeyObject,
                 aes_key,                       // KEY: d41d8cd98f00b204e9800998ecf8427e
                 32i64,
                 0) >= 0 ) {
            hKey = phKey;
            BCryptDecrypt = u_get_proc_address_using_ordinal(0i64, 11, 0xCA9F17E6);
            if ( (BCryptDecrypt)(hKey, a2_buf, 0x20i64) >= 0 )// decrypt 32 bytes. IV = 0x80*16
            {
              decrypted_buf = a1->decrypted_buf;
              rev_i = 24;
              if ( a1 != 0xFFFFFFFFFFFFFE58i64 )
              {
                end = (&v48 - decrypted_buf);
                do
                {
                  *decrypted_buf = decrypted_buf[end];
                  ++decrypted_buf;
                  --rev_i;
                }
                while ( rev_i );
              }
              v2 = 1;
            }
          }
        }
      }
    }
  }

  /* Teardown */

  return v2;
}
```

The ciphertext here is `(a1->loaded_resource + 0x5F)` which are the contents of the `"PNG"` resource
starting at offset **0x5F**:
```
D7 FB 7E 62 8D AB 87 65 CD 71 85 CE 53 0F 5A 8C 
2D 8A 45 37 12 4B 79 1D 40 DA 76 86 26 D3 D3 72
...
```

The decryption key is `d41d8cd98f00b204e9800998ecf8427e`, and the IV is `'\x80'*16`. The resulted
plaintext is `l3rlcps_7r_vb33eehskc3\n\n\n\n\n\n\n\n\n\n`. After the decryption, `sub_2C1A40`
invokes another function, called `u_final_xor_decrypt` at `2C2730h`:
```c
__int64 __fastcall u_final_xor_decrypt(ispo_struct *a1) {
  *&flag[20] = _mm_load_si128(&xmmword_2D5160);
  v2 = flag[26];
  i = 0;
  v4 = flag[25];
  v5 = flag[24];
  v6 = flag[23];
  v7 = flag[22];
  v8 = flag[21];
  v9 = flag[20];
  *&flag[4] = _mm_load_si128(&xmmword_2D5180);
  v10 = flag[19];
  v11 = flag[18];
  v12 = flag[17];
  do {
    switch ( i ) {
      case 0u:
        flag[4] ^= a1->decrypted_buf[12];
        break;
      case 1u:
        flag[5] ^= a1->decrypted_buf[13];
        break;
      case 2u:
        flag[6] ^= a1->decrypted_buf[6];
        break;
      case 3u:
        flag[7] ^= a1->decrypted_buf[8];
        break;
      case 4u:
        flag[8] ^= a1->decrypted_buf[7];
        break;
      case 5u:
        flag[9] ^= a1->decrypted_buf[6];
        break;
      case 6u:
        flag[10] ^= a1->decrypted_buf[5];
        break;
      case 7u:
        flag[11] ^= a1->decrypted_buf[1];
        break;
      case 8u:
        flag[12] ^= a1->decrypted_buf[0];
        break;
      case 9u:
        flag[13] ^= a1->decrypted_buf[3];
        break;
      case 0xAu:
        flag[14] ^= a1->decrypted_buf[4];
        break;
      case 0xBu:
        flag[15] ^= a1->decrypted_buf[17];
        break;
      case 0xCu:
        flag[16] ^= a1->decrypted_buf[15];
        break;
      case 0xDu:
        v12 ^= a1->decrypted_buf[20];
        break;
      case 0xEu:
        v11 ^= a1->decrypted_buf[19];
        break;
      case 0xFu:
        v10 ^= a1->decrypted_buf[21];
        break;
      case 0x10u:
        v9 ^= a1->decrypted_buf[2];
        break;
      case 0x11u:
        v8 ^= a1->decrypted_buf[10];
        break;
      case 0x12u:
        v7 ^= a1->decrypted_buf[16];
        break;
      case 0x13u:
        v6 ^= a1->decrypted_buf[11];
        break;
      case 0x14u:
        v5 ^= a1->decrypted_buf[14];
        break;
      case 0x15u:
        v4 ^= a1->decrypted_buf[2];
        break;
      case 0x16u:
        v2 ^= 0x40u;
        break;
      default:
        break;
    }
    ++i;
  } while ( i < 0x20 );
  
  flag[26] = v2;
  flag[25] = v4;
  flag[24] = v5;
  flag[23] = v6;
  flag[22] = v7;
  flag[21] = v8;
  flag[20] = v9;
  flag[19] = v10;
  flag[18] = v11;
  flag[17] = v12;
  
  *flag = '0';
  lstrlenA = u_get_proc_address_using_ordinal(0i64, 1, 0x2D40B8E6);
  v14 = (lstrlenA)(&flag[4]);
  u_write_to_regkey(a1, &flag[4], v14 + 1, flag);
}
```

The flag here is *shuffled*, gets XORed with a random key and then gets written to the Registry.
From here we can extract the right order which is:
```
12,13,6,8,7,6,5,1,0,3,4,17,15,20,19,21,2,10,16,11,14,2
```

### Recovering the Flag

Now we have everything we need to write the recover the flag:
```python
from Crypto.Cipher import AES

png_data = [
    0xD7, 0xFB, 0x7E, 0x62, 0x8D, 0xAB, 0x87, 0x65, 0xCD, 0x71, 0x85, 0xCE, 0x53, 0x0F, 0x5A, 0x8C,
    0x2D, 0x8A, 0x45, 0x37, 0x12, 0x4B, 0x79, 0x1D, 0x40, 0xDA, 0x76, 0x86, 0x26, 0xD3, 0xD3, 0x72,
]

key = ("d41d8cd98f00b204e9800998ecf8427e").encode('utf-8')
iv = bytes([0x80]*16)
crypto = AES.new(key=key, IV=iv,  mode=AES.MODE_CBC)

plain = crypto.decrypt(bytes(png_data))
# [+] AES-CBC Decrypt: (IV \x80*16) ~> b'l3rlcps_7r_vb33eehskc3\n\n\n\n\n\n\n\n\n\n'
print(f"[+] AES-CBC Decrypt (IV \\x80*16): {plain}")

flag = ''
for i in [12,13,6,8,7,6,5,1,0,3,4,17,15,20,19,21,2,10,16,11,14,2]:
    flag += chr(plain[i])


print(f"[+] Final Flag: {flag}@flare-on.com")
```

When we run the above commands we get:
```
[+] AES-CBC Decrypt (IV \x80*16): b'l3rlcps_7r_vb33eehskc3\n\n\n\n\n\n\n\n\n\n'
[+] Final Flag: b3s7_sp3llcheck3r_ev3r@flare-on.com
```

Which gives us the flag: `b3s7_sp3llcheck3r_ev3r@flare-on.com`.
___
