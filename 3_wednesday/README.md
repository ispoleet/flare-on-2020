

## Flare-On 2020 - #2 wednesday
___

### Description: 

*Be the wednesday. Unlike challenge 1, you probably won't be able to beat this game the old fashioned way. Read the README.txt file, it is very important.*

`*7zip password: flare`
___

### Solution:

The goal of this challenge is to win the game. The interesting part starts at the bottom of
the `update` function:
```c
void __thiscall update__Arw3f6ryHvqdibU49aaayOg(int this, double a2){
    /* ... */
  
    v15 = *(_DWORD **)(*(_DWORD *)(this + 0x28) + 0xFC);
    if ( v15 ) {
        if ( *v15 == 296 )
            sceneeq___HC7o4hYar8OQigU09cNyehg(game__7aozTrKmb7lwLeRmW9a9cs9cQ, winScene__eVaCVkG1QBiYVChMxpMGBQ);
    }
}
```

This code essentially says that if you score `296` points then show the win scene. My first attempt was to
patch the `score__h34o6jaI3AO6iOQqLKaqh` counter that holds the current score. However this approach did not
work. My second approach was to modify the score increase step:
```assembly
.text:00432261 loc_432261:                             ; CODE XREF: @onCollide__9byAjE9cSmbSbow3F9cTFQfLg@8+238↓j
.text:00432261        mov     ebx, ds:_score__h34o6jaI3AO6iOQqLKaqhw
.text:00432267        add     ebx, 1
.text:0043226A        jo      loc_43238C
.text:00432270
.text:00432270 loc_432270:                             ; CODE XREF: .text:00432391↓j
.text:00432270        mov     byte ptr [esi+18h], 1
.text:00432274        mov     edx, offset _NTI__bc9cIRpcNby7Dj3TH0kx9cWA_
.text:00432279        mov     ds:_score__h34o6jaI3AO6iOQqLKaqhw, ebx
```

Instead of incrementing `ebx` by `1`, I modified it to `74` so after 4 moves the score would be `296`.
However although I had a score of `296`, `v15` was still `4`. That means that we had to successfully
pass `296` obstacles. However this is hard: Each obstacle has a letter (S, M, T, F, S), and according
to `README.txt`the "DUDE" needs to duck under `F` and `S` and jump over `S`, and `M`.
```
                        --- BE THE WEDNESDAY ---

                                   S
                                   M
                                   T
                                  DUDE
                                   T
                                   F
                                   S
```

My third approach was to patch the `day_index__HImZp3MMPNE3pGzeJ4pUlA` and instead of incrementing by
`1` each time to increment by `0`:
```Assembly
.text:00433D8F         mov     esi, ds:_day_index__HImZp3MMPNE3pGzeJ4pUlA
.text:00433D95         add     esi, 1
.text:00433D98         mov     edi, esi
.text:00433D9A         jo      loc_434030
.text:00433DA0
.text:00433DA0 loc_433DA0:                             ; CODE XREF: @update__Arw3f6ryHvqdibU49aaayOg@12+315↓j
.text:00433DA0         mov     eax, _obstacles__Xqz7GG9aS72pTPD9ceUjZPNg
.text:00433DA5         mov     ds:_day_index__HImZp3MMPNE3pGzeJ4pUlA, esi
```

By doing this trick, the days never change and all obstacles are 'S' and 'M'. That is, we can easily win
by ducking all the time. After holding the down arrow down for ~5 minutes, I was able to win the game and
reach the win scene. However nothing was there.


After some searching I found the `obstacles__Xqz7GG9aS72pTPD9ceUjZPNg` pointer, which points to a struct:
```assembly
.data:0043A860 _obstacles__Xqz7GG9aS72pTPD9ceUjZPNg dd offset _TM__V45tF8B8NBcxFcjfe7lhBw_5

.rdata:0043EB40 _TM__V45tF8B8NBcxFcjfe7lhBw_5 dd 128h   ; DATA XREF: .data:_obstacles__Xqz7GG9aS72pTPD9ceUjZPNg↑o
.rdata:0043EB44         dw 128h
.rdata:0043EB46         dw 4000h
.rdata:0043EB48         db    0
.rdata:0043EB49         db    0
.rdata:0043EB4A         db    1
.rdata:0043EB4B         db    1
.rdata:0043EB4C         db    0
.rdata:0043EB4D         db    0
.rdata:0043EB4E         db    0
.rdata:0043EB4F         db    1
.rdata:0043EB50         db    0
.rdata:0043EB51         db    1
.rdata:0043EB52         db    1
.rdata:0043EB53         db    1
.rdata:0043EB54         db    0
[.... TRUNCATED FOR BREVITY ....]
.rdata:0043EC6E         db    0
.rdata:0043EC6F         db    1
.rdata:0043EC70 _TM__V45tF8B8NBcxFcjfe7lhBw_4 dd 0  
```

This struct contains an array of 0s and 1s at offset 8. Every time we pass an obstacle,
the next element (bit) is read from this table:
```C
    v3 = day_index__HImZp3MMPNE3pGzeJ4pUlA + 1;
    v4 = day_index__HImZp3MMPNE3pGzeJ4pUlA + 1;
    if ( __OFADD__(1, day_index__HImZp3MMPNE3pGzeJ4pUlA) )
      raiseOverflow();
    
    ++day_index__HImZp3MMPNE3pGzeJ4pUlA;
    
    if ( obstacles__Xqz7GG9aS72pTPD9ceUjZPNg )
    {
      if ( *(_DWORD *)obstacles__Xqz7GG9aS72pTPD9ceUjZPNg > v3 )
      {
        ((void (__stdcall *)(int, int, _DWORD, int, _DWORD))reset__day_SAtOZDlchGyR6ynmbkI6aw)(
          TM__V45tF8B8NBcxFcjfe7lhBw_4,
          0x40845000,
          0,
          0x40668000,
          *((char *)obstacles__Xqz7GG9aS72pTPD9ceUjZPNg + v4 + 8));
    /* ... */
```

Before we dig into that, we collect all bits from the bit array:
```
00110001011101000101111101101001001101010101111101110111010001010110010001101110001100110111001101100100001101000111100101011111011011010101100101011111010001000111010101100100001100110111001101000000011001100110110001100001011100100110010100101101011011110110111000101110011000110110111101101101
```

And group them into bytes to see if they give something meaningfull:
```
00110001
01110100
01011111
01101001
00110101
01011111
01110111
01000101
01100100
01101110
00110011
01110011
01100100
00110100
01111001
01011111
01101101
01011001
01011111
01000100
01110101
01100100
00110011
01110011
01000000
01100110
01101100
01100001
01110010
01100101
00101101
01101111
01101110
00101110
01100011
01101111
01101101
```

These look like valid ASCII values (the 1st bit is always 0), so we feed them into a
[binary-to-ASCII converter](https://www.rapidtables.com/convert/number/binary-to-ascii.html)
and we get the flag: `1t_i5_wEdn3sd4y_mY_Dud3s@flare-on.com`

___

