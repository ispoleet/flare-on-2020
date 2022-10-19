## Flare-On 2022 - #4 darn_mice
___

### Description: 

*"If it crashes its user error." -Flare Team*

`7-zip password: flare`

___

### Solution:

Everything starts from function `0x5E1000`:
```c
void __cdecl u_actual_main(char *argv1) {
  void (__cdecl *buf)(_DWORD); // eax
  size_t arglen; // [esp+4h] [ebp-30h]
  unsigned int i; // [esp+8h] [ebp-2Ch]
  char v4[36]; // [esp+Ch] [ebp-28h] BYREF

  qmemcpy(v4, "P^^", 3);
  v4[3] = 0xA3;
  v4[4] = 0x4F;
  v4[5] = 0x5B;
  v4[6] = 0x51;
  v4[7] = 0x5E;
  v4[8] = 0x5E;
  v4[9] = 0x97;
  v4[10] = 0xA3;
  v4[11] = 0x80;
  v4[12] = 0x90;
  v4[13] = 0xA3;
  v4[14] = 0x80;
  v4[15] = 0x90;
  v4[16] = 0xA3;
  v4[17] = 0x80;
  v4[18] = 0x90;
  v4[19] = 0xA3;
  v4[20] = 0x80;
  v4[21] = 0x90;
  v4[22] = 0xA3;
  v4[23] = 0x80;
  v4[24] = 0x90;
  v4[25] = 0xA3;
  v4[26] = 0x80;
  v4[27] = 0x90;
  v4[28] = 0xA3;
  v4[29] = 0x80;
  v4[30] = 0x90;
  v4[31] = 0xA2;
  v4[32] = 0xA3;
  v4[33] = 0x6B;
  v4[34] = 0x7F;
  v4[35] = 0;
  u_print_msg(aOnYourPlateYou);
  arglen = strlen(argv1);
  if ( arglen && arglen <= 0x23 ) {
    u_print_msg(aYouLeaveTheRoo);
    for ( i = 0; i < 0x24 && v4[i] && argv1[i]; ++i )
    {
      buf = (void (__cdecl *)(_DWORD))VirtualAlloc(0, 0x1000u, 0x3000u, 0x40u);
      *(_BYTE *)buf = argv1[i] + v4[i];
      buf(buf);
      u_print_msg(aNibble);
    }

    u_print_msg("When you return, you only: %s\n", argv1);
    u_decrypt_flag(glo_ciphertext, glo_cipherlen, argv1, pbSalt, glo_ciphertext, glo_cipherlen);
    u_print_msg("%s\n", (const char *)glo_ciphertext);
  } else {
    u_print_msg(aNoNevermind);
  }
}
```

Function reads bytes from the `argv`, adds the value of the next item in `v4` array,
then writes the result into a newly allocated buffer and executes it. If the program
does not crash, it decrypts the flag using RC4 (key is the SHA512 of the `argv`):
```c
int __cdecl u_decrypt_flag(
        unsigned __int8 *buf,
        unsigned int buflen,
        char *pbPassword,
        char *pbSalt,
        unsigned __int8 *out,
        unsigned int a6)
{
  /* ... */
  phAlgorithm = 0;
  v17 = 0;
  if ( out )
  {
    if ( a6 >= buflen )
    {
      status = BCryptOpenAlgorithmProvider(&phAlgorithm, pszAlgId, 0, 8u); // 'SHA512'
      if ( status >= 0 )
      {
        v12 = strlen(pbSalt);
        v9 = strlen(pbPassword);
        status = BCryptDeriveKeyPBKDF2(
                   phAlgorithm,
                   (PUCHAR)pbPassword,
                   v9,
                   (PUCHAR)pbSalt,
                   v12,
                   0x800ui64,
                   pbDerivedKey,
                   0x40u,
                   0);
        if ( status >= 0 )
        {
          u_do_rc4(pbDerivedKey, 0x40u, buf, buflen, out);
          return 1;
        }
        
    /* ... error handling ... */
}
```

The ciphertext and the SHA salt are shown below:
```assembly
.data:005F9000 ; unsigned __int8 glo_ciphertext[48]
.data:005F9000 glo_ciphertext  db 7Fh, 37h, 71h, 40h, 23h, 98h, 93h, 0D4h, 0, 51h, 0BFh
.data:005F9000                                         ; DATA XREF: u_actual_main+186↑o
.data:005F9000                                         ; u_actual_main+19A↑o ...
.data:005F9000                 db 4Eh, 4, 63h, 0Bh, 0B1h, 0E3h, 0BCh, 68h, 14h, 0F6h
.data:005F9000                 db 76h, 0B6h, 36h, 75h, 8Eh, 86h, 4Dh, 6Ah, 0B4h, 7, 93h
.data:005F9000                 db 2Ch, 0B2h, 0E1h, 0D0h, 16h, 0DFh, 0BCh, 0FDh, 0C7h
.data:005F9000                 db 0F5h, 73h, 2Dh, 59h, 3 dup(0)
.....
.data:005F90C4 ; char pbSalt[]
.data:005F90C4 pbSalt          db 'salty',0            ; DATA XREF: u_actual_main+18B↑o
.data:005F90CA                 align 4
```

#### Getting the Flag

The only way to not crash the program is for the byte to be a `retn` instruction
(`0xC3`). Using that we can decrypt the values and find the correct program input:
```python
secret = [
  0x50, 0x5E, 0x5E, 0xA3, 0x4F, 0x5B, 0x51, 0x5E, 
  0x5E, 0x97, 0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90,
  0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90, 0xA3, 0x80,
  0x90, 0xA3, 0x80, 0x90, 0xA3, 0x80, 0x90, 0xA2,
  0xA3, 0x6B, 0x7F
]

print(''.join(chr(0xC3 - s) for s in secret))
```

Which gives us: `see three, C3 C3 C3 C3 C3 C3 C3! XD`. We type this and we get the flag:
```
ispo@localhost:~/flare-on-2022/04_darn_mice$ wine darn_mice.exe 'see three, C3 C3 C3 C3 C3 C3 C3! XD'
On your plate, you see four olives.
You leave the room, and a mouse EATS one!
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
Nibble...
When you return, you only: see three, C3 C3 C3 C3 C3 C3 C3! XD
i_w0uld_l1k3_to_RETurn_this_joke@flare-on.com
```

So the flag is: `i_w0uld_l1k3_to_RETurn_this_joke@flare-on.com`
___
