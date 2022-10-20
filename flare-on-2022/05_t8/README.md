## Flare-On 2022 - #5 T8
___

### Description: 

*FLARE FACT #823: Studies show that C++ Reversers have fewer friends on average than normal people do. That's why you're here, reversing this, instead of with them, because they don't exist.*

*We’ve found an unknown executable on one of our hosts. The file has been there for a while, but our networking logs only show suspicious traffic on one day. Can you tell us what happened?*

`7-zip password: flare`
___

### Solution:

First we open *traffic.pcapng* using Wireshark. It contains **2** HTTP streams:
```
POST / HTTP/1.1
Connection: Keep-Alive
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; 11950)
Content-Length: 24
Host: flare-on.com

y.d.N.8.B.X.q.1.6.R.E.=.


HTTP/1.0 200 OK
Server: Apache On 9 
Date: Tue, 14 Jun 2022 16:14:36 GMT

TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4Lu3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUyagT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KWgALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+LezJEtrDXP1DJNg==
```

```
POST / HTTP/1.1
Connection: Keep-Alive
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; CLR)
Content-Length: 16
Host: flare-on.com

V.Y.B.U.p.Z.d.G.


HTTP/1.0 200 OK
Server: Apache On 9 
Date: Tue, 14 Jun 2022 16:14:36 GMT

F1KFlZbNGuKQxrTD/ORwudM8S8kKiL5F906YlR8TKd8XrKPeDYZ0HouiBamyQf9/Ns7u3C2UEMLoCA0B8EuZp1FpwnedVjPSdZFjkieYqWzKA7up+LYe9B4dmAUM2lYkmBSqPJYT6nEg27n3X656MMOxNIHt0HsOD0d+
```

Our goal is to reverse the binary (*t8.exe*) and decrypt the above messages.

#### Reversing the binary

This is a C++ binary with classes and vtables. We start from `main` at `0x0D74680`.

The first step is to bypass the anti-cloaking trick that puts program to sleep
(we simply patch the instructions):
```assembly
.text:00D746E0 SLEEP_LOOP:                             ; CODE XREF: _main+81↓j
.text:00D746E0         push    2932E00h                ; dwMilliseconds
.text:00D746E5         call    esi ; Sleep             ; PATCH ME: EIP+2
.text:00D746E7         movups  xmm0, xmmword ptr glo_system_time.wYear
.text:00D746EE         sub     esp, 10h
.text:00D746F1         mov     eax, esp
.text:00D746F3         movups  xmmword ptr [eax], xmm0
.text:00D746F6         call    u_custom_decrypt
.text:00D746FB         add     esp, 10h
.text:00D746FE         cmp     eax, 0Fh
.text:00D74701         jnz     short SLEEP_LOOP        ; PATCH ME: ZF = 1
```

The next important function is `0xD734C0` that initializes a `CClientSock` object:
```c
CClientSock *__thiscall u_CClientSock_ctor(CClientSock *cclient, _DWORD *Block) {
  /* ... */

  cclient->vtable = &CClientSock::`vftable';
  cclient->http_method_str = 0;
  cclient->field_6 = 0i64;
  cclient->field_E = 0;
  cclient->field_12 = 0;
  cclient->field_24 = 0;
  cclient->field_28 = 7;
  cclient->field_14 = 0;
  cclient->field_3C = 0;
  cclient->field_40 = 7;
  cclient->md5_digest = 0;
  p_Block = &Block;
  if ( &cclient->field_14 != (__int16 *)&Block )
  {
    if ( (unsigned int)v8 >= 8 )
      p_Block = Block;
    u_string_ctor((void **)&cclient->field_14, p_Block, v7);
  }
  buf = unknown_libname_56(0x800u);
  cclient->serv_resp_buf_0x800 = (int)buf;
  /* ... */

  return cclient;
}
```

We can also see all class functions from the vtable  (`CClientSock::vftable`):
```assembly
.rdata:00DBB918 ; const CClientSock::`vftable'
.rdata:00DBB918 ??_7CClientSock@@6B@ dd offset sub_D735F0
.rdata:00DBB918                                         ; DATA XREF: u_CClientSock_ctor+3D↑o
.rdata:00DBB918                                         ; sub_D735F0+9↑o
.rdata:00DBB91C                 dd offset u_set_http_method
.rdata:00DBB920                 dd offset u_do_MD5_digest
.rdata:00DBB924                 dd offset u_do_base64
.rdata:00DBB928                 dd offset u_base64_decode_0
.rdata:00DBB92C                 dd offset sub_D736D0
.rdata:00DBB930                 dd offset u_do_rc4_crypt
.rdata:00DBB934                 dd offset u_do_http_transaction
.rdata:00DBB938                 dd offset u_process_HTTP_response
.rdata:00DBB93C                 dd offset u_decrypt_HTTP_response
.rdata:00DBB940                 dd offset u_md5_digest
```

Program invokes class methods using indirect calls to the vtable:
```assembly
.text:00D74824                 push    ecx
.text:00D74825                 mov     ecx, edi
.text:00D74827                 mov     [ebp+cclient___], edi
.text:00D7482D                 call    dword ptr [eax+4]
```

Knowing that, we can find exactly which function calls are called through `client` object.
Let's see now the most important parts of `main`:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  /* ... */
  for ( i = glo_system_time;
        u_custom_decrypt(*(unsigned int *)&i.wYear, *(unsigned int *)&i.wDayOfWeek) != 15;
        i = glo_system_time )
  {
    Sleep(43200000u);
  }
  /* ... */  
  do
    v43.m128i_i16[v3++] ^= 0x11u;               // decrypt "flare-on.com"
  while ( v3 < 0xC );
  /* ... */
  cclient_ = u_CClientSock_ctor(cclient, v31);
  LOBYTE(v52) = 0;
  cclient__ = cclient_;
  v47 = 0x540053004F0050i64;                    // "POST"
  v48 = 0;
  v49 = 0;
  v50 = 0;
  v51 = 0;
  vtable = cclient_->vtable;
  cclient___ = cclient__;
  (*((void (__thiscall **)(CClientSock *, __int64 *))vtable + 1))(cclient__, &v47);// set HTTP method
  rand_string_str = u_itoa(Block, glo_rand_string);
  LOBYTE(v52) = 2;
  v9 = rand_string_str;
  v10 = *((_DWORD *)rand_string_str + 5) < 8u;
  Src = rand_string_str;
  /* ... */
  if ( v11 > dword_DC0888 - dword_DC0884 )
  {
    LOBYTE(Src) = 0;
    v15 = u_string_ctor_0((const void **)&glo_decr_key, v11, (int)Src, v9, v11);
  }
  /* ... */
  u_some_ctor(&v30, v15);
  (*((void (__thiscall **)(CClientSock *))cclient__->vtable + 2))(cclient__);// calc MD5
  /* ... */
  *(_QWORD *)ahoy = 0x79006F00680061i64;        // "ahoy"
  /* ... */
  (*((void (__thiscall **)(CClientSock *))cclient__->vtable + 7))(cclient__);// do HTTP
  (*((void (__thiscall **)(CClientSock *, void **))cclient__->vtable + 8))(cclient__, v40);// process HTTP response
  /* ... */
  else
  {
    if ( v42 >= 8 )
      flag = v40[0];
    ++v41;
    flag[idx] = '@';
    flag[idx + 1] = 0;                          // The decrypted flag is here!
    v20 = (const void **)v40;
  }
  /* ... */
  // Process 2nd HTTP message
  u_some_ctor(&v27, v20);
  (*((void (__thiscall **)(CClientSock *))cclient__->vtable + 2))(cclient__);// u_do_MD5_digest
  u_exhange_2nd_HTTP_msg(cclient__);
  /* ... */
  return result;
}
```

So what `main` does? it first decrypts the server name (`flare-on.com`) and then initializes the
HTTP method to `POST`. Then it computes the MD5 digest of the decryption key (see below) as the
RC4 key. Then, it uses the RC4 key and the text `ahoy` to send an HTTP request. Finally, it
processes the HTTP response which contains the flag.

Furthermore, the program continues and computes a new RC4 key from the flag and sends a 2nd HTTP
request. Finally, it receives another HTTP response and then terminates.


#### Decryption Key

Before `main` a SEH is called to initialized `glo_rand_string` and `glo_decr_key` globals: 
```c
int u_SEH_calc_rand_str() {
  struct _SYSTEMTIME SystemTime; // [esp+4h] [ebp-20h] BYREF
  int v2; // [esp+20h] [ebp-4h]

  v2 = 0;
  u_string_ctor(&glo_decr_key, L"FO9", 3u);
  GetLocalTime(&SystemTime);
  srand(SystemTime.wMilliseconds + 1000 * (SystemTime.wSecond + 60 * SystemTime.wMinute));
  glo_rand_string = rand();
  glo_system_time = SystemTime;
  return atexit(u_dtor_maybe);
}
```

`glo_decr_key` contains the decryption key which is `F09` followed by a random integer.


#### Analyzing HTTP Request

The important function here is `u_do_http_transaction` at `0xD73D70`, which are called from `main`:
```c
bool __thiscall u_do_http_transaction(
        CClientSock *this,
        _DWORD *Block,
        int a3,
        int a4,
        int a5,
        int a6,
        unsigned int a7,
        char a8)
{
  /* ... */
  u_some_ctor(md5_hash, &this->md5_digest);
  v11 = (*((int (__thiscall **)(CClientSock *, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, HINTERNET, int *))this->vtable
         + 6))(
          this,
          md5_hash[0],
          md5_hash[1],
          md5_hash[2],
          md5_hash[3],
          md5_hash[4],
          md5_hash[5],
          v34,
          ahoy_plaintext);                      // do RC4
  (*((void (__thiscall **)(CClientSock *, LPVOID *, int, int))this->vtable + 3))(this, lpOptional, v11, v9);// base64 encode
  /* ... */
  if ( ObtainUserAgentString(0, pszUAOut, &cbSize) )
  {
      /* ... */
  }
  /* ... */
  rand_str = glo_rand_string;
  pszUAOut[cbSize - 2] = 0;
  u_itoa((void **)Source, rand_str);
  mbstowcs_s(&PtNumOfCharConverted, DstBuf, 0x200u, pszUAOut, strlen(pszUAOut));
  wcscat_s(DstBuf, 0x200u, L"; ");
  if ( a8 )
  {
    v19 = (const wchar_t *)Source;
    if ( v41 >= 8 )
      v19 = Source[0];
  }
  else
  {
    v19 = L"CLR";
  }
  wcscat_s(DstBuf, 0x200u, v19);
  wcscat_s(DstBuf, 0x200u, L")");               // key seed in user agent!
  v20 = WinHttpOpen(DstBuf, 0, 0, 0, 0);
  v37 = v20;
  if ( v20 )
  {
    v21 = (const WCHAR *)&this->field_14;
    if ( this->field_28 >= 8u )
      v21 = *(const WCHAR **)v21;
    WinHttpCloseHandle = (void (__stdcall *)(HINTERNET))::WinHttpCloseHandle;
    http_hdl = WinHttpConnect(v20, v21, 0x50u, 0);
    hInternet = http_hdl;
    if ( http_hdl )
    {
      v24 = WinHttpOpenRequest(http_hdl, (LPCWSTR)&this->http_method_str, 0, 0, 0, 0, 0);
      if ( v24 )
      {
        v25 = lpOptional;
        if ( v45 >= 8 )
          v25 = (LPVOID *)lpOptional[0];
        v38 = WinHttpSendRequest(v24, 0, 0, v25, 2 * v44, 2 * v44, 0);
        if ( v38 )
        {
          v38 = WinHttpReceiveResponse(v24, 0);
          if ( v38 )
          {
            v26 = (DWORD *)&this->field_48;
            do
            {
              while ( 1 )
              {
                ahoy_plaintext = &this->field_48;
                v34 = v24;
                *v26 = 0;
                WinHttpQueryDataAvailable(v34, (LPDWORD)ahoy_plaintext);
                if ( *v26 <= 0x800 )
                  break;
                this->field_48 = 2048;
              }
              WinHttpReadData(v24, (LPVOID)this->serv_resp_buf_0x800, *v26, &dwNumberOfBytesRead);
            }
            while ( this->field_48 );
            WinHttpCloseHandle = (void (__stdcall *)(HINTERNET))::WinHttpCloseHandle;
          }
        }
        WinHttpCloseHandle(v24);
  /* ... */

  return v12;
}
```

This function encrypts a plaintext (here `ahoy`) using RC4. The key is the MD5 digest of 
`glo_decr_key` (in unicode). Then it computes the Base64 encoding of it and sends an HTTP request
to `flare-on.com` server.

It is important to notice that the value of `glo_rand_string` which is essentially used to compute
the key is appended to the user agent.


#### Analyzing HTTP Response

Once program receives the response, `main` invokes `u_process_HTTP_response` at `0xD74200`. The
first task of `u_process_HTTP_response` is to call `u_decrypt_HTTP_response` at `0xD743F0` to
base64 decode and RC4 decrypt the message:
```c
void **__thiscall u_decrypt_HTTP_response(CClientSock *this, void **a2) {
  /* ... */
  serv_resp_buf_0x800 = (void *)this->serv_resp_buf_0x800;
  v21 = a2;
  Src[4] = 0;
  v23 = 15;
  LOBYTE(Src[0]) = 0;
  u_another_ctor(Src, serv_resp_buf_0x800, strlen((const char *)serv_resp_buf_0x800));
  v27 = 0;
  u_ctor_too(&v15, Src);
  (*((void (__thiscall **)(CClientSock *, void **, int, int, int, int, void **, int))this->vtable + 4))(
    this,
    base64_resp,
    v15,
    v16,
    v17,
    v18,
    v19,
    v20);                                       // do base64 decode
  LOBYTE(v27) = 1;
  v4 = base64_resp;
  v20 = v25;
  if ( v26 >= 0x10 )
    v4 = (void **)base64_resp[0];
  v19 = v4;
  u_some_ctor(v14, &this->md5_digest);
  v5 = (_WORD *)(*((int (__thiscall **)(CClientSock *, _DWORD, _DWORD, int, int, int, int, void **, int))this->vtable + 6))(
                  this,
                  v14[0],
                  v14[1],
                  v15,
                  v16,
                  v17,
                  v18,
                  v19,
                  v20);                         // do RC4 decrypt
  /* ... */
  return a2;
}
```

After the decryption, a second, weird, layer of decryption is applied to the plaintext:
```c
wchar_t *__thiscall u_process_HTTP_response(CClientSock *this, wchar_t *a2) {
  /* ... */
  v2 = a2;
  Context = a2;
  (*((void (__thiscall **)(CClientSock *, wchar_t **))this->vtable + 9))(this, String);// decrypt HTTP response
  v21 = 0;
  v3 = (wchar_t *)String;
  if ( v16 >= 8 )
    v3 = String[0];
  next = (unsigned int *)wcstok_s(v3, L",", &Context);
  v18 = 0;
  v19 = 7;
  LOWORD(Block[0]) = 0;
  LOBYTE(v21) = 1;
  if ( next )
  {
    do
    {
      num = u_custom_decrypt(*next, next[1]);
      Src = (unsigned __int16)u_map_to_ascii(num);
      v6 = wcslen((const unsigned __int16 *)&Src);
      v7 = v18;
      if ( v6 > v19 - v18 )
      {
        LOBYTE(v13) = 0;
        u_string_ctor_0((const void **)Block, v6, v13, &Src, v6);
      }
      else
      {
        v8 = v18 + v6;
        v9 = Block;
        v18 += v6;
        if ( v19 >= 8 )
          v9 = (void **)Block[0];
        memmove((char *)v9 + 2 * v7, &Src, 2 * v6);
        *((_WORD *)v9 + v8) = 0;
      }
      next = (unsigned int *)wcstok_s(0, L",", &Context);
    }
    while ( next );
    v2 = a2;
  }
  /* ... */
}
```

The plaintext is split into chunks using comma `,` as delimiter. For each chunk, function takes
the first 8 bytes to make **2** DWORDs. These DWORDs are passed onto `u_custom_decrypt` at
`0xD74570` to yield an single byte. This byte is finally mapped to a character which is returned
to main.

```c
int __cdecl u_custom_decrypt(unsigned int X, unsigned int Y) {
  unsigned int v2; // ecx
  int v3; // esi
  unsigned int v4; // eax
  float v5; // xmm0_4
  float v7; // [esp+2Ch] [ebp+14h]

  v2 = HIWORD(X);
  v3 = (unsigned __int16)X - 1;
  if ( HIWORD(X) > 2u )
    v3 = (unsigned __int16)X;
  v4 = v2 + 12;
  if ( v2 > 2 )
    v4 = HIWORD(X);
  v7 = (float)((float)((double)(int)(v3 / 100 / 4
                                   + HIWORD(Y)
                                   + (int)((double)(v3 + 4716) * 365.25)
                                   - (int)((double)(int)(v4 + 1) * -30.6001)
                                   - v3 / 100
                                   + 2)
                     - 1524.5)
             - 2451549.5)
     / 29.53;
  v5 = floor(v7);
  return (int)roundf((float)(v7 - v5) * 29.53);
}
```

**NOTE:** This function actually calculates the
[moon phase](https://www.subsystems.us/uploads/9/8/9/4/98948044/moonphase.pdf) and returns
a date of the month.

```c
wchar_t __fastcall u_map_to_ascii(int a1) {
  if ( a1 > 26 )
    return glo_unicode_alphabet[a1 + 1];
  else
    return glo_unicode_alphabet[a1];
}
```

```assembly
.rdata:00DBB840 glo_unicode_alphabet:                   ; DATA XREF: u_map_to_ascii+5↑r
.rdata:00DBB840                                         ; u_map_to_ascii:loc_D741EE↑r
.rdata:00DBB840                 text "UTF-16LE", ' abcdefghijklmnopqrstuvwxyz',0
.rdata:00DBB878 a03:
.rdata:00DBB878                 text "UTF-16LE", '0_3',0
```

The final decryption is the flag as main appends `@flare-on.com` to it.

#### Breaking the HTTP Ciphertext

To break the ciphertext in the HTTP response and decrypt the flag, we first need to build the
decryption key which is `F091950` (see the end of the user agent in the first HTTP message):
```
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; 11950)
```

Then we take the HTTP response:
```
TdQdBRa1nxGU06dbB27E7SQ7TJ2+cd7zstLXRQcLbmh2nTvDm1p5IfT/Cu0JxShk
6tHQBRWwPlo9zA1dISfslkLgGDs41WK12ibWIflqLE4Yq3OYIEnLNjwVHrjL2U4L
u3ms+HQc4nfMWXPgcOHb4fhokk93/AJd5GTuC5z+4YsmgRh1Z90yinLBKB+fmGUy
agT6gon/KHmJdvAOQ8nAnl8K/0XG+8zYQbZRwgY6tHvvpfyn9OXCyuct5/cOi8KW
gALvVHQWafrp8qB/JtT+t5zmnezQlp3zPL4sj2CJfcUTK5copbZCyHexVD4jJN+L
ezJEtrDXP1DJNg==
```

We base64 decode it and then we apply an RC4 decryption to it. The RC4 key is the key (in unicode)
that we calculated above. Once we get the plaintext, we split it into chunks (delimiter is `,`)
and for each chunk we recover a single character from the flag:
```
[+] Decrypting chunk : E5-07-09-00-03-00-0F-00-0D-00-25-00-03-00-62-02 
[+]    Extracting magic numbers: 0x907E5 & 0xF0003
[+]    Result: 0x09 ~> Decrypted character: 'i'
[+] Decrypting chunk : DC-07-0A-00-06-00-0D-00-0D-00-25-00-09-00-2A-03 
[+]    Extracting magic numbers: 0xA07DC & 0xD0006
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : E1-07-0C-00-04-00-07-00-0D-00-25-00-24-00-E5-00 
[+]    Extracting magic numbers: 0xC07E1 & 0x70004
[+]    Result: 0x13 ~> Decrypted character: 's'
[+] Decrypting chunk : E0-07-05-00-05-00-06-00-0D-00-25-00-0B-00-26-00 
[+]    Extracting magic numbers: 0x507E0 & 0x60005
[+]    Result: 0x1d ~> Decrypted character: '3'
[+] Decrypting chunk : E2-07-0A-00-01-00-08-00-0D-00-25-00-1F-00-45-03 
[+]    Extracting magic numbers: 0xA07E2 & 0x80001
[+]    Result: 0x1d ~> Decrypted character: '3'
[+] Decrypting chunk : E6-07-03-00-02-00-01-00-0D-00-25-00-32-00-DA-00 
[+]    Extracting magic numbers: 0x307E6 & 0x10002
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : DE-07-07-00-02-00-16-00-0D-00-25-00-36-00-D1-02 
[+]    Extracting magic numbers: 0x707DE & 0x160002
[+]    Result: 0x19 ~> Decrypted character: 'y'
[+] Decrypting chunk : DE-07-05-00-03-00-0E-00-0D-00-25-00-01-00-E8-00 
[+]    Extracting magic numbers: 0x507DE & 0xE0003
[+]    Result: 0x0f ~> Decrypted character: 'o'
[+] Decrypting chunk : DA-07-04-00-01-00-05-00-0D-00-25-00-3A-00-0B-00 
[+]    Extracting magic numbers: 0x407DA & 0x50001
[+]    Result: 0x15 ~> Decrypted character: 'u'
[+] Decrypting chunk : DD-07-0A-00-04-00-03-00-0D-00-25-00-16-00-16-03 
[+]    Extracting magic numbers: 0xA07DD & 0x30004
[+]    Result: 0x1c ~> Decrypted character: '_'
[+] Decrypting chunk : DE-07-01-00-02-00-0E-00-0D-00-25-00-10-00-C9-00 
[+]    Extracting magic numbers: 0x107DE & 0xE0002
[+]    Result: 0x0d ~> Decrypted character: 'm'
[+] Decrypting chunk : DC-07-0C-00-01-00-0A-00-0D-00-25-00-30-00-0C-02 
[+]    Extracting magic numbers: 0xC07DC & 0xA0001
[+]    Result: 0x1b ~> Decrypted character: '0'
[+] Decrypting chunk : E6-07-02-00-01-00-1C-00-0D-00-25-00-22-00-4B-01 
[+]    Extracting magic numbers: 0x207E6 & 0x1C0001
[+]    Result: 0x1b ~> Decrypted character: '0'
[+] Decrypting chunk : E6-07-09-00-05-00-09-00-0D-00-25-00-21-00-6D-01 
[+]    Extracting magic numbers: 0x907E6 & 0x90005
[+]    Result: 0x0e ~> Decrypted character: 'n'
```

Therefore, the flag is: `i_s33_you_m00n@flare-on.com`

For more details, please refer to the [t8_crack.py](./t8_crack.py) file.

___
