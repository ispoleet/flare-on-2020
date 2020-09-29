
## Flare-On 2020 - #8 Aardvark
___

### Description: 

*Expect difficulty running this one. I suggest investigating why each error is occuring. Or not, whatever. You do you.*


`*7zip password: flare`
___


### Solution:

As stated in the description, this program throws some errors (`socket failed`, `bind failed` and so on).
A quick look at `WinMain` reveals why:
```C
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {    
  /* ... */
  if ( GetTempPathA(0x105u, Buffer) )
    SetCurrentDirectoryA(Buffer);
  if ( WSAStartup(0x202u, &WSAData) )
  {
    MessageBoxA(0i64, "Error initializing Winsock", "Error", 0x10u);
    goto LABEL_17;
  }
  v18 = 0i64;
  name = 1;
  v19 = 0;
  v5 = 1;
  name_2[0] = 0i64;
  name_2[1] = 0i64;
  name_2[2] = 0i64;
  name_2[3] = 0i64;
  name_2[4] = 0i64;
  name_2[5] = 0i64;
  wsprintfA((LPSTR)name_2, "%s", "496b9b4b.ed5");
  DeleteFileA("496b9b4b.ed5");
  v8 = socket(1, 1, 0);
  v6 = v8;
  if ( v8 == -1i64 )
  {
    MessageBoxA(0i64, "socket failed", "Error", 0x10u);
    v9 = "Error creating Unix domain socket";
    MessageBoxA(0i64, v9, "Error", 0x10u);
    goto LABEL_17;
  }
  if ( bind(v8, (const struct sockaddr *)&name, 110) == -1 )
  {
    v10 = "bind failed";
  }
  else
  {
    if ( listen(v6, 0x7FFFFFFF) != -1 )
      goto LABEL_12;
    v10 = "listen failed";
  }
  MessageBoxA(0i64, v10, "Error", 0x10u);

  if ( (unsigned __int8)drop_linux_bin_1400012B0() )
  {
    s = accept(v6, 0i64, 0i64);
    v12 = GetModuleHandleA(0i64);
    v13 = CreateDialogParamA(v12, "BOARD", 0i64, (DLGPROC)DialogFunc, 0i64);
    if ( !v13 )
    {
      v14 = "CreateDialog failed";
      MessageBoxA(0i64, v14, "Error", 0x10u);
      goto LABEL_37;
    }
    v4 = GetMessageA(&Msg, 0i64, 0, 0);
    if ( v4 > 0 )
    {
      while ( Msg.message - 256 > 2 || Msg.wParam - 37 > 3 )
      {
        if ( !IsDialogMessageA(v13, &Msg) )
          goto LABEL_32;
        v4 = GetMessageA(&Msg, 0i64, 0, 0);
        if ( v4 <= 0 )
          goto LABEL_34;
      }
      Msg.hwnd = v13;
      TranslateMessage(&Msg);
      DispatchMessageA(&Msg);
      goto LABEL_33;
    }
    if ( v4 < 0 )
    {
      v14 = "GetMessage failed";
      goto LABEL_36;
    }
  }
}
```

The problem is with the parameters in `WSAStartup`, `socket`, `bind` and `listen`. We just modify
their parameters to to make the server properly listen for connections. The trickest part is with
`bind` where it needs a valid `sockaddr_in` struct:
```
struct sockaddr_in server;

//Prepare the sockaddr_in structure
server.sin_family = AF_INET;
server.sin_addr.s_addr = INADDR_ANY;
server.sin_port = htons( 8888 );

//Bind
if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)

typedef struct sockaddr_in {
  short          sin_family;
  u_short        sin_port;
  struct in_addr sin_addr;
  char           sin_zero[8];
} SOCKADDR_IN, *PSOCKADDR_IN, *LPSOCKADDR_IN;
```

We make sure that the first parameter of `bind` points to an address that contains
the following (bind at address `127.0.0.1:30583`):
```
02 00 77 77 7F 00 00 01 00 00 00 00 00 00 00 00
```


The next function is `drop_linux_bin_1400012B0`, which extracts an ELF binary from
a `Resource` and stores it under `%TEMP%`:
```C
__int64 drop_linux_bin_1400012B0() {
  v11[0] = (__int64)Str;
  v11[1] = 0i64;
  NumberOfBytesWritten[0] = 0;
  v0 = 0;
  v1 = -1i64;
  if ( !GetTempFileNameA(".", PrefixString, 0, FileName) )
  {
    v2 = "GetTempFileName failed";
    goto LABEL_7;
  }
  wsprintfA(Str, "%s", FileName);
  *strchr(Str, 92) = 47;
  v1 = (__int64)CreateFileA(FileName, 0x40000000u, 0, 0i64, 3u, 0x80u, 0i64);
  if ( !v1 )
  {
    v2 = "CreateFile failed";
    goto LABEL_7;
  }
  v3 = FindResourceA(0i64, (LPCSTR)0x12C, (LPCSTR)0x100);
  v4 = v3;
  if ( !v3 )
  {
    v2 = "FindResource failed";
LABEL_7:
    MessageBoxA(0i64, v2, "Error", 0x10u);
    v5 = *(void **)NumberOfBytesWritten;
    if ( !*(_QWORD *)NumberOfBytesWritten )
      goto LABEL_16;
    goto LABEL_15;
  }
  v6 = SizeofResource(0i64, v3);
  v7 = LoadResource(0i64, v4);
  v5 = v7;
  if ( !v7 )
  {
    MessageBoxA(0i64, "LockResource failed", "Error", 0x10u);
    goto LABEL_16;
  }
  v8 = LockResource(v7);
  if ( WriteFile((HANDLE)v1, v8, v6, NumberOfBytesWritten, 0i64) && NumberOfBytesWritten[0] == v6 )
  {
    CloseHandle((HANDLE)v1);
    FreeResource(v5);
    check_win_distro_140001930((__int64)Str, 1u, (__int64)v11);
    v0 = 1;
  }
  else
  {
    MessageBoxA(0i64, "WriteFile failed", "Error", 0x10u);
  }
LABEL_15:
  FreeResource(v5);
LABEL_16:
  if ( v1 != -1 )
    CloseHandle((HANDLE)v1);
  return v0;
}
```

Then function `check_win_distro_140001930` checks the windows distribution:
```C
__int64 __fastcall check_win_distro_140001930(__int64 a1, unsigned int a2, __int64 a3) {  
  VersionInformation.dwOSVersionInfoSize = 156;
  if ( !GetVersionExA(&VersionInformation) )

  if ( VersionInformation.dwBuildNumber >= 0x42EE )
  {
    if ( VersionInformation.dwBuildNumber == 17134 )
    {
      log_maybe_140001AB0((int)"Windows 10 1803\n");
      sub_140001B10(a1, a2, a3);
      return 0i64;
    }
    if ( VersionInformation.dwBuildNumber == 17763 )
    {
      log_maybe_140001AB0((int)"Windows 10 1809\n");
      sub_140001D60(a1, a2, a3);
      return 0i64;
    }
    if ( VersionInformation.dwBuildNumber - 18362 <= 1 )
    {
      log_maybe_140001AB0((int)"Windows 10 1903/1909\n");
      sub_140001FB0(a1, a2, a3);
      return 0i64;
    }
    if ( VersionInformation.dwBuildNumber - 19041 <= 1 )
    {
      log_maybe_140001AB0((int)"Windows 10 2004/20H2\n");
    }
    else
    {
      if ( VersionInformation.dwBuildNumber <= 0x4A62 )
        goto LABEL_4;
      log_maybe_140001AB0((int)"Windows version too new, hoping for the best...\n");
    }
    CreateLxProcess_1400021E0(a1, a2, a3);
    return 0i64;
  }
  log_maybe_140001AB0((int)"Windows version too old\n");
LABEL_4:
  MessageBoxA(
    0i64,
    "Windows version too old\r\nPlease use Windows 10 1803, 1809, 1903, 1909, 2004, or 20H2",
    "Error",
    0x10u);
  return 0i64;
}
```

If the distribution is suitable, function `CreateLxProcess_1400021E0` creates a Linux process
through [WSL](https://docs.microsoft.com/en-us/windows/wsl/about):
```C
__int64 __fastcall CreateLxProcess_1400021E00(__int64 a1, unsigned int a2, __int64 a3) {
  v3 = 0;
  ppv = 0i64;
  if ( CoCreateInstance(&rclsid, 0i64, 4u, &riid, &ppv) )
  {
    MessageBoxA(0i64, "CoCreateInstance failed", "Error", 0x10u);
  }
  else if ( (*(unsigned int (__fastcall **)(LPVOID, __int64 *))(*(_QWORD *)ppv + 88i64))(ppv, v22) )
  {
    MessageBoxA(0i64, "GetDefaultDistribution failed", "Error", 0x10u);
  }
  else
  {
    v13 = 0;
    pv = 0i64;
    if ( (*(unsigned int (__fastcall **)(LPVOID, unsigned int *, LPVOID *))(*(_QWORD *)ppv + 104i64))(ppv, &v13, &pv) )
    {
      MessageBoxA(0i64, "EnumerateDistributions failed", "Error", 0x10u);
    }
    else
    {
      v7 = 0;
      if ( v13 )
      {
        while ( 1 )
        {
          v8 = 28i64 * v7;
          if ( *(_QWORD *)((char *)pv + v8) == v22[0]
            && *(_QWORD *)((char *)pv + v8 + 8) == v22[1]
            && *(_DWORD *)((char *)pv + v8 + 20) != 1 )
          {
            break;
          }
          if ( ++v7 >= v13 )
            goto LABEL_12;
        }
        MessageBoxA(0i64, "Default distribution must be WSL 1", "Error", 0x10u);
      }
      else
      {
        if ( pv )
          CoTaskMemFree(pv);

        v9 = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters->Reserved2[0];
        GetCurrentDirectoryW(0x105u, Buffer);
        v12 = 0;
        v11 = 0;
        if ( (*(unsigned int (__fastcall **)(LPVOID, __int64 *, __int64, _QWORD, __int64, WCHAR *, _QWORD, _QWORD, _DWORD, const wchar_t *, __int16, __int16, _DWORD, __int128 *, char *, char *, __int64 *, __int64 *, __int64 *, __int64 *, __int64 *, __int64 *))(*(_QWORD *)ppv + 112i64))(
               ppv,
               v22,
               a1,
               a2,
               a3,
               Buffer,
               0i64,
               0i64,
               0,
               L"root",
               v11,
               v12,
               (_DWORD)v9,
               &v23,
               v26,
               v25,
               &v21,
               &v20,
               &v19,
               &v18,
               &v17,
               &v16) )
        {
          MessageBoxA(0i64, "CreateLxProcess failed", "Error", 0x10u);
        }
        else
        {
          v3 = 1;
        }
      }
    }
  }
  if ( ppv )
    (*(void (__fastcall **)(LPVOID))(*(_QWORD *)ppv + 16i64))(ppv);
  return v3;
}
```

After that, program creates a dialog window with `DialogFunc` implementing a
Tic-Tac-Toe game.


#### Reversing the ELF binary

The ELF binary also has incorrect parameters in the socket functions, so our first
task is to fix the parameters as well. After that program connects to server and
stats playing Tic-Tac-Toe. Function `check_winner_5555555554B0` checks if there
is a winner on the board and returns `0` for draw, `X` if computer wins or `O`
if user wins. If the user wins, it generates a flag:


```C
__int64 __fastcall main(int a1, char **a2, char **a3) {
	/* ... */
	    v17 = check_winner_5555555554B0();
	    v18 = flag_202010;
	    do
	      *v18++ ^= v17;
	    while ( &unk_555555756020 != (_UNKNOWN *)v18 );
	    v19 = 0LL;
	    stream = fopen("/proc/modules", "r");
	    if ( stream )
	    {
	      while ( 1 )
	      {
	        ptr = 0LL;
	        linelen = 0LL;
	        if ( getline((char **)&ptr, &linelen, stream) <= 0 )
	          break;
	        v31 = strtok((char *)ptr, " ");
	        if ( v31 && !memcmp(v31, "cpufreq_", 8uLL) )
	        {
	          while ( *v31 )
	          {
	            flag_202010[v19] ^= *v31++;
	            v19 = ((_BYTE)v19 + 1) & 0xF;
	          }
	        }
	        if ( ptr )
	          free(ptr);
	      }
	      if ( ptr )
	      {
	        free(ptr);
	        ptr = 0LL;
	      }
	      fclose(stream);
	    }
	    streama = fopen("/proc/mounts", "r");
	    if ( streama )
	    {
	      while ( 1 )
	      {
	        ptr = 0LL;
	        linelen = 0LL;
	        if ( getline((char **)&ptr, &linelen, streama) <= 0 )
	          break;
	        strtok((char *)ptr, " ");
	        mount_point_168a = strtok(0LL, " ");
	        v30 = strtok(0LL, " ");
	        if ( mount_point_168a && !strcmp(mount_point_168a, "/") && v30 )
	        {
	          v32 = *v30;
	          if ( *v30 != 'f' && v32 )
	          {
	            while ( 1 )
	            {
	              v32 = *++v30;
	              if ( !*v30 )
	                break;
	              if ( v32 == 'f' )
	                goto XOR_FLAG_555555555344;
	            }
	          }
	          else
	          {
	XOR_FLAG_555555555344:
	            while ( v32 )
	            {
	              flag_202010[v19] ^= v32;
	              v32 = *++v30;
	              v19 = ((_BYTE)v19 + 1) & 0xF;
	            }
	          }
	        }
	        if ( ptr )
	          free(ptr);
	      }
	      if ( ptr )
	      {
	        free(ptr);
	        ptr = 0LL;
	      }
	      fclose(streama);
	    }
	    streamb = fopen("/proc/version\x00signature", "r");
	    if ( streamb )
	    {
	      mount_point_168 = v4;
	      v20 = 9LL;
	      do
	      {
	        v21 = _IO_getc(streamb);
	        if ( v21 == -1 )
	          break;
	        flag_202010[v19] ^= v21;
	        --v20;
	        v19 = ((_BYTE)v19 + 1) & 0xF;
	      }
	      while ( v20 );
	      v4 = mount_point_168;
	      fclose(streamb);
	    }
	    v22 = getauxval(0x21uLL);
	    v23 = *(unsigned __int16 *)(v22 + offsetof(elf64_hdr, e_phnum));
	    v24 = v22 + *(_QWORD *)(v22 + offsetof(elf64_hdr, e_phoff));
	    if ( *(_WORD *)(v22 + offsetof(elf64_hdr, e_phnum)) )
	    {
	      v25 = 0LL;
	      do
	      {
	        for ( j = *(_QWORD *)(v24 + 16) >> 16; j; v19 = ((_BYTE)v19 + 1) & 0xF )
	        {
	          flag_202010[v19] ^= j;
	          j >>= 8;
	        }
	        ++v25;
	        v24 += 56LL;
	      }
	      while ( v25 != v23 );
	    }
	    chdir("/proc");
	    streamc = opendir(".");
	    if ( streamc )
	    {
	      while ( 1 )
	      {
	        v27 = readdir(streamc);
	        if ( !v27 )
	          break;
	        while ( !__lxstat(1, v27->d_name, &v44) )
	        {
	          if ( (v44.st_mode & 0xD000) != 0x8000 )
	            break;
	          v28 = v44.st_ino >> 16;
	          if ( !(v44.st_ino >> 16) )
	            break;
	          do
	          {
	            flag_202010[v19] ^= v28;
	            v28 >>= 8;
	            v19 = ((_BYTE)v19 + 1) & 0xF;
	          }
	          while ( v28 );
	          v27 = readdir(streamc);
	          if ( !v27 )
	            goto READDIR_DONE_555555555165;
	        }
	      }
	READDIR_DONE_555555555165:
	      closedir(streamc);
	    }
	    v29 = flag_202010;
	    do
	    {
	      if ( *v29 < 0 )
	      {
	        v16 = fd;
	        goto SEND_RESULT_STR;
	      }
	      ++v29;
	    }
	    while ( v18 != v29 );
	    strcpy(
	      (char *)__stpcpy_chk(
	                (char *)&result_str_555555756060 + strlen((const char *)&result_str_555555756060),
	                flag_202010,
	                64LL),
	      "@flare-on.com");
	    v16 = fd;
	SEND_RESULT_STR:
	    send(v16, &result_str_555555756060, 0x40uLL, 0);
	  }
```


The initial flag (which is shown below) goes through a series of XORs before the `@flare-on.com` is appended to it:
```
4A 82 43 AB 95 ED 8F 7E  9C BC AD 84 17 91 06 15
```

The only tricky part here is to make sure that the program runs on `WSL1` (and **not** `WSL2`)
according to this message as environment variables can be changed:
```C
	MessageBoxA(0i64, "Default distribution must be WSL 1", "Error", 0x10u);
```

For more details please take a look at the crack file: [ttt2_crack.py](./ttt2_crack.py)

The final flag (which does not make sense) is: `c1ArF/P2CjiDXQIZ@flare-on.com`

___
