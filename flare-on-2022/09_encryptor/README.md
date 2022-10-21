## Flare-On 2022 - #9 encryptor
___

### Description: 

*You're really crushing it to get this far. This is probably the end for you. Better luck next year!*

`7-zip password: flare`
___

### Solution:

In this challenge we are dealing with a ransomware. It takes a file as input, encrypts it
and then creates a `HOW_TO_DECRYPT.txt` file in the `Desktop` folder:
```
~*~*~* The FLARE-ON Encryptor ~*~*~*

All your files have been encrypted with a powerful combination of
symmetric and asymmetric cryptography. Do not tamper with the encrypted files.
It is of no use and will only risk corrupting your data.

To get your files decrypted send lots of cryptocurrency over Tor.

You'll need to copy and paste us these values to get your key.

<9f18776bd3e78835b5ea24259706d89cbe7b5a79010afb524609efada04d0d71170a83c853525888c942e0dd1988251dfdb3cd85e95ce22a5712fb5e235dc5b6ffa3316b54166c55dd842101b1d77a41fdcc08a43019c218a8f8274e8164be2e857680c2b11554b8d593c2f13af2704e85847f80a1fc01b9906e22baba2f82a1,
c07b114db9bfdd8561cac945e0fb0d614817376f4c586a603c6475b7215c96e55d19b458e67f5652e372feb830fc7eca1092a9314290455a29e52fe1f2a2bf4941737a59dd40d147a5e742750abcf737bec610f9dad9bfde48d232d68b2b2a00e882af8b3d568dc729f01ea99185c6c08dfa4f8314afe81ffbecbd3cf2cb0f65,
5123ad61b5863550bc806ee9ca7cada0d776ea365750d6aee47b761f99d10f48be495f9ae7dedc73c05a82bd475f2c3ebd762a58e7495e92c638669137dd48d1bd22c0be6bbb4d4d071101ae82ed7074257aaf56e9a9e55b6e91386f1369955ef8a57d77ec7968f262a81d11dada317941cb38f9159937002abec6c516d0ab46>
```

Let's start with the `main` at `0x403BF0`:
```c
int __fastcall u_main(int argc, const char **argv) {
  /* ... */
  u_invoke_ctors_iff();
  qmemcpy(EncryptMe, ".EncryptMe", 10);
  LibraryA = LoadLibraryA("advapi32");
  if ( !LibraryA )
    return -1;
  // *"This function has no associated import library. This function is available as a resource named SystemFunction036 in Advapi32.dll.
  // You must use the LoadLibrary and GetProcAddress functions to dynamically link to Advapi32.dll."*
  glo_RtlGenRandom = (__int64 (__fastcall *)(_QWORD, _QWORD))GetProcAddress(LibraryA, "SystemFunction036");
  if ( !glo_RtlGenRandom )
    return -1;
  if ( argc <= 1 )
  {
    std_maybe = (FILE *)u_get_std_maybe(2i64);
    fputs("usage: flareon path [path ...]\n", std_maybe);
    return -1;
  }
  u_gen_pub_keys();
  encr_file_cnt = 0;
  while ( 1 )
  {
    nxt_argv = *++argv;
    if ( !*argv )
      break;
    argvlen = strlen(*argv) - 10;
    if ( argvlen > 0 && !memcmp(&nxt_argv[argvlen], EncryptMe, 0xAui64) )
    {
      fin = fopen(nxt_argv, "rb");
      if ( fin )
      {
        argv_copy = strdup(*argv);
        strcpy(&argv_copy[argvlen], ".Encrypted");
        fout = fopen(argv_copy, "rb");
        if ( !fout )
        {
          fout2 = fopen(argv_copy, "wb");
          fout = fout2;
          if ( !fout2 )
            goto HALT;
          ++encr_file_cnt;
          u_do_encrypt(fout2, fin);
          nxt_argv_ = *argv;
          stderr = (FILE *)u_get_std_maybe(2i64);
          fprintf(stderr, "%s\n", nxt_argv_);
        }
        fclose(fout);
HALT:
        fclose(fin);
        free(argv_copy);
      }
    }
  }
  stderr_ = (FILE *)u_get_std_maybe(2i64);
  fprintf(stderr_, "%u File(s) Encrypted\n", encr_file_cnt);
  if ( encr_file_cnt )
  {
    u_create_ransom_file_in_desktop();
    return 0;
  }
  return encr_file_cnt;
}
```

Function takes as input a file with the `.EncryptMe` file extension and produces an encrypted
file with the `.Encrypted` file extension. Here's an example:
```
ispo@localhost:~/ctf/flare-on-challenges/flare-on-2022/09_encryptor$ hexdump -C ispo.EncryptMe 
00000000  69 73 70 6f 6c 65 65 74  0a                       |ispoleet.|
00000009
ispo@localhost:~/ctf/flare-on-challenges/flare-on-2022/09_encryptor$ hexdump -C ispo.Encrypted.fixed 
00000000  89 2b 54 09 f2 8c a7 4c  39 66 31 38 37 37 36 62  |.+T....L9f18776b|
00000010  64 33 65 37 38 38 33 35  62 35 65 61 32 34 32 35  |d3e78835b5ea2425|
........
000000f0  61 31 66 63 30 31 62 39  39 30 36 65 32 32 62 61  |a1fc01b9906e22ba|
00000100  62 61 32 66 38 32 61 31  0a 63 32 30 38 31 39 61  |ba2f82a1.c20819a|
........
000001f0  33 64 66 30 64 61 39 35  36 62 32 31 37 39 35 35  |3df0da956b217955|
00000200  62 64 37 38 63 35 61 30  39 0a 36 63 64 30 35 33  |bd78c5a09.6cd053|
00000210  63 38 65 33 66 38 36 63  64 64 37 66 63 37 62 30  |c8e3f86cdd7fc7b0|
........
00000300  33 64 32 64 34 32 39 62  30 38 0a 32 39 30 66 62  |3d2d429b08.290fb|
00000310  66 65 35 65 31 34 32 66  33 30 65 65 30 30 38 31  |fe5e142f30ee0081|
........
000003f0  39 36 37 33 61 34 37 39  64 36 65 38 31 31 65 61  |9673a479d6e811ea|
00000400  61 30 62 33 61 35 63 34  62 37 30 0a              |a0b3a5c4b70.|
0000040c
```

Encrypted file contains **9** bytes for the ciphertext (exactly as many as they are for
the plaintext and then contains **4** bignums of **1024** bits each). From this we can tell
that we have a **stream cipher** (if we had a block cipher the ciphertext size would be a
multiple of **16**, **32**, or some other power of **2**). We can also tell that the key of
the symmetric encryption was encrypted with some form of assymetric encryption (it would be
stupid to have the decryption key in the file as it is), so one of these bignums should be the
ciphertext of the decryption key.


#### Reversing the Symmetric Encryption

Let's see the `u_do_encrypt` at `0x4022A3`:
```c
void __fastcall u_do_encrypt(FILE *fout, FILE *fin) {
  /* ... */
  sz_x = 34i64;
  encrypted_key_ = encrypted_key;
  while ( sz_x )                                // bzero
  {
    *(_DWORD *)encrypted_key_ = 0;
    encrypted_key_ += 4;
    --sz_x;
  }
  sz_y = key;
  for ( i = 34i64; i; --i )                     // bzero
  {
    *(_DWORD *)sz_y = 0;                        // also initialize counter to 0
    sz_y += 4;
  }
  glo_RtlGenRandom(key, 32i64);
  glo_RtlGenRandom(&nonce[4], 12i64);
  u_chacha20_stream_cipher_encrypt(fout, fin, key, nonce);

  /* .... */
}
```

Function takes as input two `FILE*` pointers (input and output) and generates a **32** byte
random key along with at **16** byte nonce (the first 4 bytes of the nonce are initialized to
zero as it is used as a block counter) and calls `u_chacha20_stream_cipher_encrypt` at
`0x4020F0`:
```c
void __fastcall u_chacha20_stream_cipher_encrypt(FILE *out, FILE *in, _BYTE *key, _BYTE *nonce) {
  /* ... */
  v6 = *(_OWORD *)key;
  v7 = *((_OWORD *)key + 1);
  v8 = *(_OWORD *)nonce;
  qmemcpy(state, "expand 32-byte k", 16);
  *(_OWORD *)&state[16] = v6;
  *(_OWORD *)&state[32] = v7;
  *(_OWORD *)&state[48] = v8;
  while ( 1 )
  {
    nread = fread(cipher, 1ui64, 0x40ui64, in); // encrypt in 64-byte blocks
    if ( nread <= 0 )                           // encrypt in ECB mode
      break;
    u_chacha20_do_block(next_state, state);
    j = 0i64;
    do
    {
      cipher[j] ^= next_state[j];
      ++j;
    }
    while ( nread > (int)j );
    fwrite(cipher, 1ui64, nread, out);
    ++*(_DWORD *)&state[48];                    // increment counter (initialized to 0)
  }
}
```

This function reads a **64** byte block for the input file, generates a **64** byte stream cipher
from the key, then XORs it with the plaintext and writes it back to the output file. Then, the
counter in the nonce is incremented to encrypt the next block (`++*(_DWORD *)&state[48]`). The 
function that does the encryption is `u_chacha20_do_block` at `0x401F10`:
```assembly
.text:0000000000401F10 ; void __fastcall u_chacha20_do_block(_DWORD *a1_out, _DWORD *a2_in)
.text:0000000000401F10 u_chacha20_do_block proc near           ; CODE XREF: u_chacha20_stream_cipher_encrypt+91↓p
.text:0000000000401F10        push    rbx
.text:0000000000401F11        push    rsi             ; we have a 4x4 matrix
.text:0000000000401F12        push    rdi
.text:0000000000401F13        mov     rdi, rcx
.text:0000000000401F16        mov     rsi, rdx
.text:0000000000401F19        mov     rax, rdi
.text:0000000000401F1C        mov     r8, rsi
.text:0000000000401F1F        mov     ecx, 10h
.text:0000000000401F24        rep movsd
.text:0000000000401F26        mov     rdi, rax
.text:0000000000401F29        mov     esi, 0Ah
.text:0000000000401F2E ----------------------------------------------------
.text:0000000000401F2E do the columns
.text:0000000000401F2E
.text:0000000000401F2E NEXT_ROUND:                    ; CODE XREF: u_chacha20_do_block+1BC↓j
.text:0000000000401F2E        mov     eax, [rdi]      ; get 1st column
.text:0000000000401F30        mov     ebx, [rdi+10h]
.text:0000000000401F33        mov     ecx, [rdi+20h]
.text:0000000000401F36        mov     edx, [rdi+30h]
.text:0000000000401F39        add     eax, ebx        ; eax = A + B
.text:0000000000401F3B        xor     edx, eax        ; edx = D ^ (A + B)
.text:0000000000401F3D        rol     edx, 10h        ; edx = ROL(D ^ (A + B), 16) = x
.text:0000000000401F40        add     ecx, edx        ; ecx = C + x
.text:0000000000401F42        xor     ebx, ecx        ; ebx = B ^ (C + x)
.text:0000000000401F44        rol     ebx, 0Ch        ; ebx = ROL(B ^ (C + x), 12) = y
.text:0000000000401F47        add     eax, ebx        ; eax = A + B + y
.text:0000000000401F49        xor     edx, eax        ; edx = (A + B + y) ^ x
.text:0000000000401F4B        rol     edx, 8          ; edx = ROL((A + B + y) ^ x, 8) = z
.text:0000000000401F4E        add     ecx, edx        ; ecx = C + x + z
.text:0000000000401F50        xor     ebx, ecx        ; ebx = (C + x + z) ^ y
.text:0000000000401F52        rol     ebx, 7          ; ebx = ROL((C + x + z) ^ y, 7) = w
.text:0000000000401F55        mov     [rdi], eax      ; A' = A + B + y
.text:0000000000401F57        mov     [rdi+10h], ebx  ; B' = w
.text:0000000000401F5A        mov     [rdi+20h], ecx  ; C' = C + x + z
.text:0000000000401F5D        mov     [rdi+30h], edx  ; D' = z
.text:0000000000401F60        mov     eax, [rdi+4]    ; repeat for 2nd column
.text:0000000000401F63        mov     ebx, [rdi+14h]
.text:0000000000401F66        mov     ecx, [rdi+24h]
.text:0000000000401F69        mov     edx, [rdi+34h]
.text:0000000000401F6C        add     eax, ebx        ; A += B
.text:0000000000401F6E        xor     edx, eax        ; D ^= A
.text:0000000000401F70        rol     edx, 10h        ; D = ROL(D, 16)
.....
```

This function treats the **64** byte input as a **4x4** DWORD matrix and performs **10** rounds
of shuffling in the columns and the diagonals. This encryption scheme looks very similar to
[Salsa20](https://en.wikipedia.org/wiki/Salsa20) but it is not Salsa20. With a little bit of
searching I found that it is [Chacha20](https://datatracker.ietf.org/doc/rfc8439/) (with no
modifications).


#### Reversing the Asymmetric Encryption

For the assymetric encryption, we go back to `main` where it invokes `u_gen_pub_keys`
at `0x4021D0`:
```c
void __stdcall u_gen_pub_keys() {
  /* ... */
  do
  {
    u_gen_rand_bignum(p);
    LOBYTE(result1) = u_is_prime_maybe(p);
  }
  while ( !result1 );                           // IS PRIME maybe?
  do
  {
    u_gen_rand_bignum(q);
    LOBYTE(result2) = u_is_prime_maybe(q);
  }
  while ( !result2 );
  u_bignum_mult(glo_rsa_n, p, q);
  u_bignum_copy(p_copy, p);
  u_bignum_copy(q_copy, q);
  u_bignum_mult(n_copy, p_copy, q_copy);
  u_gen_private_key_d(glo_rsa_d, glo_rsa_d, n_copy);// originally d is set to 0x10001
  u_bignum_power(glo_key_C, unint_buf, glo_rsa_e, glo_key_A);
}
```

After we rename the variables it is very easy to see that it implements an
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) cryptosystem. But how do we know what
these functions do? Let's start from `u_bignum_mult` at `0x401550`:
```c
void __fastcall u_bignum_mult(_QWORD *result, _QWORD *num1, _QWORD *num2) {
  /* ... */

  result_ = result;
  num2_ = num2;
  memset(result, 0, 0x88ui64);
  ii = 17;
  do
  {
    result__ = result_;
    num2__ = num2_;
    jj = 17;
    do
    {
      mult = *num2__ * (unsigned __int128)(unsigned __int64)*num1;
      v11 = __CFADD__((_QWORD)mult, *result__);
      *result__++ += mult;
      LODWORD(mult) = jj - 1;
      if ( jj != 1 )
      {
        v14 = v11;
        v13 = __CFADD__(v11, *result__) | __CFADD__(*((_QWORD *)&mult + 1), v11 + *result__);
        *result__ += *((_QWORD *)&mult + 1) + v14;
        for ( i = result__ + 1; v13; ++i )
        {
          LODWORD(mult) = mult - 1;
          if ( !(_DWORD)mult )
            break;
          v16 = v13;
          v13 = __CFADD__(v13, *i);
          *i += v16;
        }
      }
      ++num2__;
      --jj;
    }
    while ( jj );
    ++result_;
    ++num1;
    --ii;
  }
  while ( ii );
}
```

This function implements its own bignum arithmetic: It reads **2** bignums and multiplies them
QWORD by QWORD (in little endian). The high **64** bits from the multiplication (stored in `rdx`)
are stored in the next QWORD in the result:
```assembly
.text:000000000040157C         mov     rax, [rsi]
.text:000000000040157F         mul     qword ptr [r10]
.text:0000000000401582         add     [rdi], rax
.text:0000000000401585         mov     eax, ebx
.text:0000000000401587         lea     rdi, [rdi+8]            ; move on
.text:000000000040158B         dec     eax
.text:000000000040158D         jz      short loc_4015A6
.text:000000000040158F         adc     [rdi], rdx              ; add high 64 bits of multiplication
.text:0000000000401592         lea     rdx, [rdi+8]
.text:0000000000401596         jmp     short loc_4015A0
```

Similarly, we can understand what `u_bignum_copy` at `0x4018A0` and `u_bignum_power` 
at `0x401550` do.

The primary algorithm for generating large prime numbers, is to first generate a random number
and then check if it is a prime. So we know that the first `while` loop generates a large prime:
```c
do {
    u_gen_rand_bignum(p);
    LOBYTE(result1) = u_is_prime_maybe(p);
} while ( !result1 );       
```

Function `u_gen_rand_bignum` at `0x401CAF` first invokes `u_gen_512bit_prng_bignum` at `0x401A70`
```c
void __fastcall u_gen_rand_bignum(_QWORD *rand_bignum) {
  /* ... */
  do
  {
LABEL_1:
    j = 1i64;
    u_gen_512bit_prng_bignum(rand_bignum);
    do
    {
      word = glo_16bit_primes[j++];
      *(_WORD *)&v6[j * 2 - 2] = sub_401941((unsigned __int8 *)rand_bignum, word);
    }
    while ( j != 2048 );
    /* ... */
}

void __fastcall u_gen_512bit_prng_bignum(_QWORD *buf) {
  __int64 cnt; // rcx
  _QWORD *ptr; // rdi

  cnt = 34i64;
  ptr = buf;
  while ( cnt )
  {
    *(_DWORD *)ptr = 0;
    ptr = (_QWORD *)((char *)ptr + 4);
    --cnt;
  }
  ((void (__fastcall *)(_QWORD *, __int64))*glo_RtlGenRandom_ptr)(buf, 64i64);
  *buf |= 1ui64;                                // set LSBit of MSByte
  buf[7] |= 0xC000000000000000ui64;             // set the last 2 bits of big num
}
```

Also `glo_16bit_primes` contains a list of many **16** bit primes:
```assembly
.rdata:0000000000405160 glo_16bit_primes dw 2, 3, 5, 7, 0Bh, 0Dh, 11h, 13h, 17h, 1Dh, 1Fh, 25h, 29h, 2Bh
.rdata:0000000000405160                                         ; DATA XREF: u_gen_rand_bignum+3↑o
.rdata:0000000000405160         dw 2Fh, 35h, 3Bh, 3Dh, 43h, 47h, 49h, 4Fh, 53h, 59h, 61h, 65h
.rdata:0000000000405160         dw 67h, 6Bh, 6Dh, 71h, 7Fh, 83h, 89h, 8Bh, 95h, 97h, 9Dh, 0A3h
......
```

Once we know that, we can also rename the variables in the `while` loops as `p` and `q`. We also
see that `glo_rsa_e` is intialized to `0x10001` or `65537` which is a common value for RSA.
Then we can tell that `u_gen_private_key_d` at `0x401B46` generates a private key, just by
looking at its parameters:
```c
  u_gen_private_key_d(glo_rsa_d, glo_rsa_d, n_copy);  // originally d is set to 0x10001
```

Then we can go back to `u_do_encrypt`:
```c
void __fastcall u_do_encrypt(FILE *fout, FILE *fin) {
  /* ... */
  sz_x = 34i64;
  encrypted_key_ = encrypted_key;
  while ( sz_x )                                // bzero
  {
    *(_DWORD *)encrypted_key_ = 0;
    encrypted_key_ += 4;
    --sz_x;
  }
  sz_y = key;
  for ( i = 34i64; i; --i )                     // bzero
  {
    *(_DWORD *)sz_y = 0;                        // also initialize counter to 0
    sz_y += 4;
  }
  glo_RtlGenRandom(key, 32i64);
  glo_RtlGenRandom(&nonce[4], 12i64);
  u_chacha20_stream_cipher_encrypt(fout, fin, key, nonce);
  // NOTE: Patch RIP and rerun:
  // u_bignum_power(buf, encrypted_key, glo_rsa_e, glo_rsa_n);
  // to get the key!
  u_bignum_power(encrypted_key, key, glo_rsa_d, glo_rsa_n);// WHY USE PRIVATE KEY TO ENCRYPT?
  u_write_key_buf_to_fp(fout, glo_key_A);
  putc(10, fout);
  u_write_key_buf_to_fp(fout, glo_rsa_n);
  putc(10, fout);
  u_write_key_buf_to_fp(fout, glo_key_C);
  putc(10, fout);
  u_write_key_buf_to_fp(fout, (unsigned __int64 *)encrypted_key);
  putc(10, fout);
}
```

After the Chacha20 encryption, we write to file **4** bignums: `A` (which is a random
contant bignum at `0x4050A0`), `n` which is `p * q`, `C` at `0x409060`, which the RSA encryption
of an uninitialized buffer in `gen_pub_keys`:
```c
  u_bignum_power(glo_key_C, unint_buf, glo_rsa_e, glo_key_A);
```

And finally the `encrypted_key` which is the result of `key ** d mod n`:
```c
  u_bignum_power(encrypted_key, key, glo_rsa_d, glo_rsa_n);// WHY USE PRIVATE KEY TO ENCRYPT?
```


#### Breaking the Cipher

To break the cipher, we first need to recover the symmetric key for Chacha20. From the **4**
bignums, the first and the third are decoys (we do not need them). The problem is that 
function uses the **private key to encrypt** the key, so we can use the public key (which we
know is **0x10001**) to decrypt the ciphertext (we also have `n`) just by doing
`encrypted_key ** e mod n`. This scheme is used in digital signatures
(so parties can easily decrypt and verify that the data come from the private key holder).


From *SuspiciouFile.txt.Encrypted* we read `n` and `C = key ** d mod n`:
```
n = dc425c720400e05a92eeb68d0313c84a978cbcf47474cbd9635eb353af864ea46221546a0f4d09aaa0885113e31db53b565c169c3606a241b569912a9bf95c91afbc04528431fdcee6044781fbc8629b06f99a11b99c05836e47638bbd07a232c658129aeb094ddaf4c3ad34563ee926a87123bc669f71eb6097e77c188b9bc9

C = 5a04e95cd0e9bf0c8cdda2cbb0f50e7db8c89af791b4e88fd657237c1be4e6599bc4c80fd81bdb007e43743020a245d5f87df1c23c4d129b659f90ece2a5c22df1b60273741bf3694dd809d2c485030afdc6268431b2287c597239a8e922eb31174efcae47ea47104bc901cea0abb2cc9ef974d974f135ab1f4899946428184c
```

We raise `C` to `e` modulo `n` to get the Chacha20 key and then, we use it to decrypt the
ciphertext (decrypting 1 block is sufficient).

For more details, please visit [encryptor_crack.py](./encryptor_crack.py).

The flag is: `R$A_$16n1n6_15_0pp0$17e_0f_3ncryp710n@flare-on.com`

___
