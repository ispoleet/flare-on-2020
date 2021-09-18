## Flare-On 2021 - #2 Known
___

### Description: 

*We need your help with a ransomware infection that tied up some of our critical files. Good luck.*

`7-zip password: flare`

___


We open the **UnlockYourFiles.exe**. The encryption routine is `u_rol_xor_qword_decrypt` at `004011F0h`:
```C
void __cdecl u_rol_xor_qword_decrypt(char *a1_plain, const char *a2_key)
{
  int i; // ecx

  for ( i = 0; (char)i < 8; LOBYTE(i) = i + 1 )
    a1_plain[i] = __ROL1__(a2_key[i] ^ a1_plain[i], i) - i;
}
```

To recover the key we need a plaintext-ciphertext pair. Since one of the files is a
[PNG](https://en.wikipedia.org/wiki/Portable_Network_Graphics) file, we know the first **8** bytes
of its header: `89 50 4E 47 0D 0A 1A 0A`. Thus we can easily recover the key: `No1Trust`.

Once we have the key we can decrypt all files one by one. The flag is inside
[critical_data.txt](./DecryptedFiles/critical_data.txt) (The extra bytes at the end are from the padding):
```

(>0_0)> You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com <(0_0<)
```

Which gives us the flag: `You_Have_Awakened_Me_Too_Soon_EXE@flare-on.com`

For more details, please take a look at the [known_crack.py](./known_crack.py) file.


The **UnlockYourFiles.exe** also contains a hidden Base64 encode string:
```
echo KD4wXzApPiBJdCdzIGRhbmdlcm91cyB0byBhZGQrcm9yIGFsb25lISBUYWtlIHRoaXMgPCgwXzA8KQo= | base64 -d

(>0_0)> It's dangerous to add+ror alone! Take this <(0_0<)
```

___

