## Flare-On 2022 - #6 à la mode
___

### Description: 

*FLARE FACT #824: Disregard flare fact #823 if you are a .NET Reverser too.*

*We will now reward your fantastic effort with a small binary challenge. You've earned it kid!*

`7-zip password: flare`
___

### Solution:


In this challenge, wee are given a .NET  dll that contains a single function:
```c#
// FlareOn.Flag
// Token: 0x06000001 RID: 1 RVA: 0x0000D078 File Offset: 0x0000C478
public string GetFlag(string password)
{
	Decoder decoder = Encoding.UTF8.GetDecoder();
	UTF8Encoding utf8Encoding = new UTF8Encoding();
	string text = "";
	byte[] array = new byte[64];
	char[] array2 = new char[64];
	byte[] bytes = utf8Encoding.GetBytes(password + "\0");
	using (NamedPipeClientStream namedPipeClientStream = new NamedPipeClientStream(".", "FlareOn", PipeDirection.InOut))
	{
		namedPipeClientStream.Connect();
		namedPipeClientStream.ReadMode = PipeTransmissionMode.Message;
		namedPipeClientStream.Write(bytes, 0, Math.Min(bytes.Length, 64));
		int byteCount = namedPipeClientStream.Read(array, 0, array.Length);
		int chars = decoder.GetChars(array, 0, byteCount, array2, 0);
		text += new string(array2, 0, chars);
	}
	return text;
}
```

This function makes no sense, so it should be a decoy. Furthermore, the size of the dll
file is **77KB** which means there must be something else in this file.

We open file in IDA we look at the very first function at `0x10001000`:
```c
void __cdecl REVERSE_ME_10001000(char *out, char *res) {
  char *buf_B; // esi
  char buf[1032]; // [esp+8h] [ebp-408h] BYREF

  u_rc4_key_gen(buf, glo_buffer_A, 8u);
  u_rc4_DECRYPT(buf, glo_buffer_C, 9u);

  if ( glo_lstrcmpA(glo_buffer_C, out) ) {
    *res = 21;
    buf_B = u_xor_decrypt(glo_auth_failed, &glo_dst_buf);
  } else {
    buf_B = glo_buffer_B;
    u_DECRYPT(buf, glo_buffer_B, 31u);
    *res = 31;
  }
  glo_strcpy(out, buf_B);
}
```

The global buffers are obviously encrypted:
```assembly
.data:10015000 glo_buffer_A    db 55h, 8Bh, 0ECh, 83h, 0ECh, 20h, 0EBh, 0FEh
.data:10015000                                         ; DATA XREF: REVERSE_ME_10001000+13↑o
.data:10015008 ; char glo_buffer_B[]
.data:10015008 glo_buffer_B    db 0E1h, 60h, 0A1h, 18h, 93h, 2Eh, 96h, 0ADh, 73h, 0BBh
.data:10015008                                         ; DATA XREF: REVERSE_ME_10001000+67↑o
.data:10015008                 db 4Ah, 92h, 0DEh, 18h, 0Ah, 0AAh, 41h, 74h, 0ADh, 0C0h
.data:10015008                 db 1Dh, 9Fh, 3Fh, 19h, 0FFh, 2Bh, 2, 0DBh, 0D1h, 0CDh
.data:10015008                 db 1Ah
.data:10015027                 db    0
.data:10015028 ; char glo_buffer_C[]
.data:10015028 glo_buffer_C    db 3Eh, 39h, 51h, 0FBh, 0A2h, 11h, 0F7h, 0B9h, 2Ch
.data:10015028                                         ; DATA XREF: REVERSE_ME_10001000+20↑o
.data:10015031                 db    0
.data:10015032                 db    0
.data:10015033                 db    0
.data:10015034 glo_auth_failed db 'Vbc',7Fh,'xe~mvc~xy7Qv~{rs',0
.data:10015034                                         ; DATA XREF: REVERSE_ME_10001000+4B↑o
.data:10015034                                         ; "Authorization Failed"
```

First function is the RC4 key generation at `0x100011EF`:
```c
void __cdecl u_rc4_key_gen(int *dst, char *key, size_t keylen) {
  /* ... */
  j = 0;
  k = 0;
  *dst = 0;
  dst[1] = 0;
  // dwords from 0-255
  do {
    // _mm_cvtsi32_si128: Copy 32-bit integer a to the lower elements of dst, and zero the upper elements of dst.
    // _mm_shuffle_epi32: Shuffle 32-bit integers in a using the control in imm8, and store the results in dst.
    // _mm_add_epi32    : Add packed 32-bit integers in a and b, and store the results in dst.
    *&dst[k + 2] = _mm_add_epi32(_mm_shuffle_epi32(_mm_cvtsi32_si128(k), 0), xmmword_1000E150);
    k += 4;
  } while ( k < 256 );
  LOBYTE(B) = 0;
  for ( i = 0; i < 256; ++i )                   // rc4!
  {
    A = dst[i + 2];
    B = (A + B + key[j]);
    dst[i + 2] = dst[B + 2];
    jj = j + 1;
    j = 0;
    dst[B + 2] = A;
    if ( jj < keylen )
      j = jj;
  }
}
```

The second function is the actual RC4 decryption at `0x10001187`:
```c
void __cdecl u_DECRYPT(int *key, char *buf, size_t len) {
  /* ... */
  v3 = key;
  i = 0;
  v5 = key[1];
  v6 = *key;
  v9 = v5;
  if ( len > 0 ) {
    do {
      v6 = (v6 + 1);
      v7 = v3[v6 + 2];
      v3 = key;
      v9 += v7;
      v8 = key[v9 + 2];
      key[v6 + 2] = v8;
      key[v9 + 2] = v7;
      buf[i++] ^= LOBYTE(key[(v8 + v7) + 2]);
    } while ( i < len );
    v5 = v9;
  }
  *v3 = v6;
  v3[1] = v5;
}
```

Finally, `u_xor_decrypt` at `0x100014AE` performs a single byte XOR:
```c
char *__cdecl u_xor_decrypt(char *a1, char *a2) {
  char *v2; // ecx
  int j; // esi
  char i; // al

  v2 = a1;
  j = 0;
  for ( i = *a1; *v2; i = *v2 ) {
    ++j;
    (v2++)[a2 - a1] = i ^ 0x17;
  }
  a2[j] = 0;
  return a2;
}
```

Let's decrypt all buffers one by one:
```python
Python>''.join(chr(ida_bytes.get_byte(0x100150F0+i) ^ 0x17) for i in range(8))
'lstrcmpA'

Python>''.join(chr(ida_bytes.get_byte(0x10015034+i) ^ 0x17) for i in range(20))
'Authorization Failed'

Python>from Crypto.Cipher import ARC4

Python>ARC4.new(bytes(ida_bytes.get_byte(0x10015000 + i) for i in range(8))).decrypt(
			bytes(ida_bytes.get_byte(0x10015028 + i) for i in range(9)))
b'MyV0ic3!\x00'

Python>ARC4.new(bytes(ida_bytes.get_byte(0x10015000 + i) for i in range(8))).decrypt(
			bytes(ida_bytes.get_byte(0x10015028 + i) for i in range(9)) + 
			bytes(ida_bytes.get_byte(0x10015008 + i) for i in range(31)))
b'MyV0ic3!\x00M1x3d_M0dE_4_l1f3@flare-on.com\x00'
```

So the flag is: `M1x3d_M0dE_4_l1f3@flare-on.com`
___
