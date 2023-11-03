## Flare-On 2023 - #10 kupo
___

### Description: 

*Did you know the PDP-11 and the FOURTH programming language were both released 53 years ago,*
*in 1970?*
*We like to keep our challenges fresh here at Flare-On, in-line with the latest malware trends.*

`7-zip password: flare`
___

### Solution:

This was the hardest challenge of this year's competition. Reading the instructions carefully
is crucial:
```
Kupo
====

This challenge will likely require some reading.  To begin with, it's for
2.11BSD on the PDP-11.  It's also embedded in a tape image.  And it's a Forth
interpreter.  There's a lot going on here.

Bootstrapping the emulator
--------------------------
You're welcome to try bootstrapping your own 2.11BSD installation, of course;
there's nothing particularly special needed, and the installation tapes and
instructions are readily available. But it's a long process with a lot of
pitfalls and I am not trying to give you _too_ much homework here.  So I'm
including a ready-to-go system along with a SIMH configuration file (SIMH is
a very good emulator for many systems, and it is easily available on most modern
package managers).  Just run `pdp11 mog.cfg` (or `simh-pdp11`, if your install
is prefixed) and read the config file and the manual to figure out how to boot
from the disk.  Hit enter once you're in the bootloader, then once you're at
the root prompt, hit Ctrl-D to finish booting into user mode (otherwise your
terminal will be funkier than you're used to).

Of course, if you have a real PDP-11 with 2.11 BSD, you won't need to fool with
an emulator, but you will need to get the image onto a tape.  Let me know if you
need that, I can write one out for you.

Booting
-------

The root password is `Flare-On`.

You'll also need to mount the tape to tape drive TS0 and extract the executable.
There's a welcome message in the first file on the tape; just `cat /dev/rmt12`
to read it.  Beyond that, see the man page for `mt` and branch out from there!

Other notes
-----------

The entire challenge, Forth engine and everything, is written in less than a
thousand lines of assembler (with macros, and with a significant amount of
Forth code embedded in the assembly).  I hope you enjoy pulling it apart as much
as I enjoyed writing it!

- Dave
```

First we add some instructions to the `mog.cfg`:
```
; Make it a PDP-11/44 with 2MB of RAM and an FPU (because 2.11BSD didn't have
; a working FPU emulator until 2006 (!)
set cpu 11/44 fpp 2m
set cpu idle

; Disable some of the default devices we don't use.
set tm dis
set rp dis
set rx dis
set rk dis
set hk dis

; Enable the hard drive and attach it.
set rq en
set rq0 ra80
attach rq0 mog.dsk

; Enable the TS11 tape controller and drive.
set ts en
attach ts0 forth.tap

; Boot from hard drive
boot rq0
```

Then we launch `pdp11 mog2.cfg`. To extract the tape contents, we will use the following commands:
```
mt -f /dev/rmt0 rewind
dd if=/dev/rmt0 of=README.txt
mt fsf 1
dd if=/dev/rmt0 of=forth.Z
```

To uncompress the `forth.Z` and extract it the local system we use the following commands:
```
uncompress forth.Z
uuencode forth.Z forth.Z > foo
to extract file to local system
```

Here is the output:
```
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/10_kupo$ pdp11 mog2.cfg 

PDP-11 simulator V3.8-1
Disabling XQ
mog2.cfg> set rq0 ra80
Non-existent parameter

44Boot from ra(0,0,0) at 0172150
: 
: ra(0,0,0)unix
Boot: bootdev=02400 bootcsr=0172150

2.11 BSD UNIX #115: Sat Apr 22 19:07:25 PDT 2000
    sms1@curly.2bsd.com:/usr/src/sys/GENERIC

ra0: Ver 3 mod 6
ra0: RD54  size=311200

phys mem  = 2097152
avail mem = 1873216
user mem  = 307200

hk ? csr 177440 vector 210 skipped:  No CSR.
ht ? csr 172440 vector 224 skipped:  No CSR.
ra 0 csr 172150 vector 154 vectorset attached
rl 0 csr 174400 vector 160 attached
tm ? csr 172520 vector 224 does not exist.
tms 0 csr 174500 vector 260 vectorset attached
ts 0 csr 172520 vector 224 attached
xp ? csr 176700 vector 254 skipped:  No CSR.
erase, kill ^U, intr ^C

login: root
Password:
erase, kill ^U, intr ^C
# cd /tmp
# mt -f /dev/rmt0 rewind
# dd if=/dev/rmt0 of=README.txt
3+1 records in
3+1 records out
#
# mt fsf 1
# dd if=/dev/rmt0 of=forth.Z
8+1 records in
8+1 records out
#
# ls -l
total 7
-rw-r-----  1 root         1885 Aug  5 02:09 README.txt
-rw-r-----  1 root         4591 Aug  5 02:09 forth.Z
#
# file forth.Z
forth.Z:        block compressed 12 bit code data
#
# uncompress forth.Z
#
# file forth
forth:  executable not stripped
#
# uuencode forth forth > foo
# cat foo
begin 640 forth
M!P&,"DX`@`@X!P`````!`,45V@XW":X$"@"$%0`````#`&)Y90`F"O<)B`$,
M`````P!S<$``91$'%1P````%`&%L:6=N`(T*S44!``<5*@````4`8V]U;G0`
M-PE:`;@"U@'Z`F0"I@0^````!`!T>7!E-PE"`;@"+`2<`X0`^@*X`H`"*`'&

[.....TRUNCATED FOR BREVITY .....]

M95]X=`!S<75O=&4`<V5C<F5T7WAT`'-E8W)E=`!?<V5C<F5T`%]V87)?;&%S
K='=O<F0`;&%S='=O<F1?>'0`7W5S97)?<F=N`%]D871A7W)G;@!?96YD`&%S
`
end
```

Let's now see the `README.txt`:
```
Welcome to MoogleForth!

This may be an interesting challenge for you.  The next file on this tape is an
executable Forth environment which contains a secret and the means for decoding
and decrypting that secret.  You'll need Ken Thompson's password, which I trust
you'll be able to find.  Beyond that, you'll need to figure out how the various
Forth words want their input, which will require some detective work on your
part.

You can solve this challenge with nothing but the tools available to you on a
standard 2.11BSD system, such as nm and adb (and if you're not familiar, you
should read their man pages).  You may find it easier to use a more modern
disassembler, though you'll need to be able to extract the file from the tape
for that.  And, of course, you need to know (or learn) how Forth works.  On the
bright side, I did leave all the symbols in the executable for you, I'm not a
monster.

The Forth environment is fairly stripped down, but where possible, I've tried
to conform to standard behaviors for all the standard words.  You can find much
documentation for Forth 2012 online, with an excellent reference at:

http://lars.nocrew.org/forth2012/alpha.html

Some caveats:

- There's very little error checking here.  You'll probably crash a lot if you
  provide unexpected input (or fail to provide expected input).  Sometimes,
  especially if you underflow the stack, the interpreter can get confused.
  You can always ctrl-C to quit if 'bye' isn't working for you.

- I've basically implemented just enough of the words to build this challenge.
  In particular, there's no compiler system, so you can't write your own colon
  definitions.  Sorry!  There was only so much time.

- Some of the words are defined in assembly, most are defined as more Forth.
  This may make disassembly interesting, but doable.

- It is dark.  You are likely to be eaten by a grue.
```

IDA pro supports `pdp11`, so we can load the `forth` in it. Understanding the architecture was not
easy but there are a few very useful resources:

* [PDP-11 Architecture](https://en.wikipedia.org/wiki/PDP-11_architecture)
* [Forth word manual](http://lars.nocrew.org/forth2012/alpha.html)
* [minimal FORTH compiler and tutorial](https://github.com/nornagon/jonesforth/blob/master/jonesforth.S)
* [Forth Programming Language](https://en.wikipedia.org/wiki/Forth_%28programming_language%29)

We can also play a little bit with it:
```
# ./forth
MoogleForth starting. Stack: 3802 
1 2 + .
3  ok
1 2 + 5 * .
15  ok
bye
#
```

After we read those very carefully, we can get a good understanding of how the assembly works.
We start with `nm` command to print the symbol table of the executable:
```
# nm forth
000656 t _const
005332 b _data_rgn
005230 d _digits
[.....TRUNCATED FOR BREVITY .....]
003710 t cr
003700 t cr_xt
000324 t decrypt
000306 t decrypt_xt
000662 t dict
001020 t divmod
001006 t divmod_xt
[.....TRUNCATED FOR BREVITY .....]
003120 t scan
003120 t scan
003106 t scan_xt
003106 t scan_xt
005162 t secret
005146 t secret_xt
[.....TRUNCATED FOR BREVITY .....]
002012 t zerolt_xt
002042 t zerone_xt
```

There are a few interesting functions here like `secret` and `decrypt`. To understand how to
navigate through the code, we take a look at the
[minimal FORTH compiler and tutorial](https://github.com/nornagon/jonesforth/blob/master/jonesforth.S):
```
    Words, both built-in ones and ones which the programmer defines later, are stored in a dictionary
    which is just a linked list of dictionary entries.

    <--- DICTIONARY ENTRY (HEADER) ----------------------->
    +------------------------+--------+---------- - - - - +----------- - - - -
    | LINK POINTER           | LENGTH/| NAME          | DEFINITION
    |            | FLAGS  |               |
    +--- (4 bytes) ----------+- byte -+- n bytes  - - - - +----------- - - - -

    I'll come to the definition of the word later.  For now just look at the header.  The first
    4 bytes are the link pointer.  This points back to the previous word in the dictionary, or, for
    the first word in the dictionary it is just a NULL pointer.  Then comes a length/flags byte.
    The length of the word can be up to 31 characters (5 bits used) and the top three bits are used
    for various flags which I'll come to later.  This is followed by the name itself, and in this
    implementation the name is rounded up to a multiple of 4 bytes by padding it with zero bytes.
    That's just to ensure that the definition starts on a 32 bit boundary.

    A FORTH variable called LATEST contains a pointer to the most recently defined word, in
    other words, the head of this linked list.

    DOUBLE and QUADRUPLE might look like this:

      pointer to previous word
       ^
       |
    +--|------+---+---+---+---+---+---+---+---+------------- - - - -
    | LINK    | 6 | D | O | U | B | L | E | 0 | (definition ...)
    +---------+---+---+---+---+---+---+---+---+------------- - - - -
           ^       len                         padding
       |
    +--|------+---+---+---+---+---+---+---+---+---+---+---+---+------------- - - - -
    | LINK    | 9 | Q | U | A | D | R | U | P | L | E | 0 | 0 | (definition ...)
    +---------+---+---+---+---+---+---+---+---+---+---+---+---+------------- - - - -
           ^       len                                     padding
           |
           |
      LATEST
```

Let's understand this layout first:
```assembly
ROM:000000        main:                                   ; initialize input tape
ROM:000000 012705         mov     #7332, R5
ROM:000000 007332
ROM:000004 004467         jsr     R4, abort
ROM:000004 002256
ROM:000004        ; ---------------------------------------------------------------------------
ROM:000010 000012         .word 12
ROM:000012 012604         .word 12604
ROM:000014 000000         .word 0                         ; pointer to the previous entry (0)
ROM:000016 000000         .word 0
ROM:000020 000003         .word 3                         ; len
ROM:000022 074542…        .byte 'b, 'y, 'e, 0             ; name
ROM:000026        ; ---------------------------------------------------------------------------
ROM:000026 005046         clr     -(SP)                   ; code
ROM:000030 004767         call    exit
ROM:000030 000610
ROM:000030        ; ---------------------------------------------------------------------------
ROM:000034 000014         .word 14                        ; pointer to the previous entry
ROM:000036 000000         .word 0
ROM:000040 000003         .word 3
ROM:000042 070163…        .byte 's, 'p, '@, 0
ROM:000046        ; ---------------------------------------------------------------------------
ROM:000046
ROM:000046        sp_:
ROM:000046 010545         mov     R5, -(R5)
ROM:000050 012407         mov     (R4)+, PC
ROM:000050        ; ---------------------------------------------------------------------------
ROM:000052 000034         .word 34                        ; pointer to the previous entry
ROM:000054 000000         .word 0
ROM:000056 000005 word_56:.word 5                         ; len('align')
ROM:000060 066141…        .byte 'a, 'l, 'i, 'g, 'n, 0
```

The `bye` instruction starts at `0x26`. Before that we have the **name** and the **name length**.
Before taht we have a pointer to the previous entry which is `0x0`. If we go to the next entry,
the `sp@` at `0x14`, we can see that the first word points to the previous entry in `bye`.
Similarly, `align` command at `0x52` starts with word `0x34` which is the address of the
previous instruction (`sp@`).

Now let's look at the `_docol` and the `decode` and `decrypt` commands:
```assembly
ROM:000650
ROM:000650        _docol:                                 ; CODE XREF: ROM:count↑P
ROM:000650                                                ; ROM:type↑P ...
ROM:000650 012407         mov     (R4)+, PC               ; R4 = ret. addr. ~>
ROM:000650        ; End of function _docol                ; take the next word from *R4 and jump to it
ROM:000650
ROM:000652
ROM:000652        _immed:                                 ; CODE XREF: ROM:immed↓J
ROM:000652 012445         mov     (R4)+, -(R5)
ROM:000654 012407         mov     (R4)+, PC
ROM:000656        @(Rn)+ ~~> Rn contains the address of the address of the operand, then increment Rn by 2
ROM:000656
ROM:000656        loc_656:                                ; CODE XREF: ROM:zero↓P
ROM:000656                                                ; ROM:to_in↓P ...
ROM:000656 013645         mov     @(SP)+, -(R5)
ROM:000660 012407         mov     (R4)+, PC               ; return to vm stack
```

```assembly
ROM:000214 000000         .word 0
ROM:000216 000006         .word 6                         ; len('decode')
ROM:000220 062544…        .byte 'd, 'e, 'c, 'o, 'd, 'e
ROM:000226        ; ---------------------------------------------------------------------------
ROM:000226        run first e.g., `2728 2712` to add the ?
ROM:000226        (2728 = 05250, 2712 = 05230)
ROM:000226
ROM:000226        Each number on 05250 is added with the sum of the prev
ROM:000226
ROM:000226        decode:
ROM:000226 004467         jsr     R4, _docol
ROM:000226 000416
ROM:000226        ; ---------------------------------------------------------------------------
ROM:000232 001250         .word 1250                      ; zero S = [0] = ctr
ROM:000234 003410         .word 3410                      ; >r (move last char to the return stack) (zero)
ROM:000236 001270 LOOP:   .word 1270                      ; dup (last char) ~> S = [a, a, b]
ROM:000240 001634         .word 1634                      ; if (if last char is null, then break) (a is dropped)
ROM:000242 000300         .word 300                       ; goto END_OF_LOOP
ROM:000244 001372         .word 1372                      ; swap ~> S = [b, a]
ROM:000246 001270         .word 1270                      ; dup ~> S = [b, b, a]
ROM:000250 001200         .word 1200                      ; c@ (fetch character at addr) ~> S = [*b[0], b, a]
ROM:000252 003446         .word 3446                      ; r> (Move x from the return stack to the data stack)
ROM:000254 000672         .word 672                       ; + (ctr + *b[0])
ROM:000256 001306         .word 1306                      ; 2dup ~> S = [ctr + *b, b, ctr + *b, b, ...]
ROM:000260 001372         .word 1372                      ; swap ~> S = [b, ctr + *b, ctr + *b, b, ...]
ROM:000262 001222         .word 1222                      ; c! *b = (ctr + *b) => *b += ctr
ROM:000264 003410         .word 3410                      ; >r
ROM:000266 000706         .word 706                       ; +1
ROM:000270 001372         .word 1372                      ; swap ~> S = [a, b+1]
ROM:000272 000760         .word 760                       ; -1   ~> S = [a-1, b+1]
ROM:000274 001620         .word 1620                      ; goto
ROM:000276 000236         .word 236                       ; goto LOOP
ROM:000300 003546 END_OF_LOOP:.word 3546                  ; rdrop
ROM:000302 001352         .word 1352                      ; 2drop
ROM:000304 002246         .word 2246                      ; ;
ROM:000306 000212         .word 212                       ; previous pointer
ROM:000310 000000         .word 0
ROM:000312 000007         .word 7                         ; len('decrypt')
ROM:000314 062544…        .byte 'd, 'e, 'c, 'r, 'y, 'p, 't, 0
ROM:000324
ROM:000324        ; =============== S U B R O U T I N E =======================================
ROM:000324
ROM:000324        ; run first e.g., `20 10` to add the address of the ciphertext (20)
ROM:000324        ; and the length (10) to the input tape
ROM:000324        ;
ROM:000324        ; decrypt takes a parameter as a key
ROM:000324
ROM:000324        decrypt:
ROM:000324 010246         mov     R2, -(SP)               ; push R2
ROM:000326 010346         mov     R3, -(SP)               ; push R3
ROM:000330 010446         mov     R4, -(SP)               ; push R4
ROM:000332 010546         mov     R5, -(SP)               ; push R5
ROM:000334 004467         jsr     R4, bl                  ; add a "blank" (space); 0x20 on R5 input tape
ROM:000334 003304
ROM:000334        ; ---------------------------------------------------------------------------
ROM:000340 000342         .word 342                       ; Not a `swab -(R2)`, but the next address
ROM:000342        ; ---------------------------------------------------------------------------
ROM:000342 012604         mov     (SP)+, R4
ROM:000344 004467         jsr     R4, parse               ; parse decrypt's parameter (delimiter is ' ' ?)
ROM:000344 002416
ROM:000344        ; ---------------------------------------------------------------------------
ROM:000350 000352         .word 352                       ; Not a `swab @-(R2)` but the next address
ROM:000352        ; ---------------------------------------------------------------------------
ROM:000352 012604         mov     (SP)+, R4               ; restore R4
ROM:000354 012503         mov     (R5)+, R3               ; R3 = key length (decrypt's parameter)
ROM:000356 012501         mov     (R5)+, R1               ; R1 = i = 07342 = parse result (key)
ROM:000360 011502         mov     @R5, R2                 ; R2 = cipherlen (arg2)
ROM:000362 016500         mov     2(R5), R0               ; R0 = &cipher (arg1)
ROM:000362 000002
ROM:000366 010346         mov     R3, -(SP)               ; keylen on stack
ROM:000370
ROM:000370        OUTER_LOOP:                             ; CODE XREF: decrypt+74↓j
ROM:000370 020203         cmp     R2, R3                  ; cipherlen > keylen ?
ROM:000372 003002         bgt     CIPHERLEN_BIGGER
ROM:000374 010203         mov     R2, R3                  ; cipherlen = keylen (decrypt only as much as key)
ROM:000376 001411         beq     FUNC_RETN
ROM:000400
ROM:000400        CIPHERLEN_BIGGER:                       ; CODE XREF: decrypt+46↑j
ROM:000400 160302         sub     R3, R2                  ; cipherlen -= keylen
ROM:000402
ROM:000402        INNER_LOOP:                             ; CODE XREF: decrypt+66↓j
ROM:000402 111004         movb    @R0, R4                 ; R4 = *cipher[i] (use cipher in tape as pointer!)
ROM:000404 112105         movb    (R1)+, R5               ; R5 = key[i]
ROM:000406 074405         xor     R5, R4                  ; R4 ^= R5
ROM:000410 110520         movb    R5, (R0)+               ; put xored character back to &cipher[i]
ROM:000412 077305         sob     R3, INNER_LOOP          ; SOB = Subtract One and Branch
ROM:000414 011603         mov     @SP, R3                 ; restore keylen
ROM:000416 160301         sub     R3, R1                  ; rewind key pointer
ROM:000420 000763         br      OUTER_LOOP
ROM:000422        ; ---------------------------------------------------------------------------
ROM:000422
ROM:000422        FUNC_RETN:                              ; CODE XREF: decrypt+52↑j
ROM:000422 005726         tst     (SP)+
ROM:000424 012605         mov     (SP)+, R5
ROM:000426 012604         mov     (SP)+, R4
ROM:000430 012603         mov     (SP)+, R3
ROM:000432 012602         mov     (SP)+, R2
ROM:000434 012407         mov     (R4)+, PC
ROM:000434        ; End of function decrypt
```

The `decrypt` command is simply a
[Vigenère Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).
The `decode` command is more tricky to understand as it uses VM stack. However it is fairly
simple, as it simply adds to each element the summary of all previous elements (module **256**):
```python
def decode(buf):
    s = 0
    buf2 = []
    for i, b in enumerate(buf):
        buf2.append( (buf[i] + s) & 0xFF )
        s += buf[i]

    return buf2
```

Finally, we also have `secret` command:
```assembly
ROM:005146 005122         .word 5122
ROM:005150 000000         .word 0
ROM:005152 000006         .word 6
ROM:005154 062563…        .byte 's, 'e, 'c, 'r, 'e, 't
ROM:005162        ; ---------------------------------------------------------------------------
ROM:005162        secret adds the pointer to ciphertext on stack
ROM:005162
ROM:005162        secret:                                 ;  jsr     pc,_const
ROM:005162 004767         call    loc_656
ROM:005162 173470
ROM:005162        ; ---------------------------------------------------------------------------
ROM:005166 005250         .word 5250                      ; address of secret
ROM:005170 005146         .word 5146
ROM:005172 000000         .word 0
ROM:005174 000010         .word 10
ROM:005176 060554…aLastword_0:.ascii \lastword\
ROM:005206        ; ---------------------------------------------------------------------------
ROM:005206
ROM:005206        lastword:
ROM:005206 004767         call    loc_656
ROM:005206 173444
ROM:005206        ; ---------------------------------------------------------------------------
ROM:005212 005226         .word 5226
ROM:005214 000000         .word 0
ROM:005216 000000         .word 0
ROM:005220 000012         .word 12
ROM:005222 000000         .word 0
ROM:005224 000000         .word 0
ROM:005226 005146         .word 5146
ROM:005230 030460…_0123456789abcdef:.byte '0, '1, '2, '3, '4, '5, '6, '7, '8, '9, 'a, 'b, 'c, 'd, 'e ; .
ROM:005247 000146         .byte 'f
ROM:005250 000056 SECRET_LEN:.word 56
ROM:005252 152433…SECEET: .byte 33, 325, 170, 303, 57, 174, 302, 332, 165, 56, 170, 62, 326
ROM:005267 154173…        .byte 173, 330, 43, 175, 331, 212, 61, 75, 206, 314, 54, 201, 55
ROM:005304 142174…        .byte 174, 304, 326, 164, 77, 47, 202, 366, 127, 64, 330, 140
ROM:005320 164707…        .byte 307, 351, 62, 320, 261, 7, 41, 217, 132, 17
```

Great, we know the ciphertext and we understand how `decode` and `decrypt` work. However, we
are still missing the decryption key for the `decrypt`. If we look back to the `README.txt`,
we see that *You'll need Ken Thompson's password, which I trust you'll be able to find*. So, we
search for
[Ken Thompson's UNIX Password](https://www.reddit.com/r/sysadmin/comments/dflpr5/ken_thompsons_unix_password/),
which is `p/q2-q4!`. Finally, we do not know is the that `decode` and `decrypt` are applied.
After some trial and error we find that it is `decrypt`-then-`decode`. We run them through the 
ciphertext and we get the flag.

We can also get the flag from the `adb` console:
```
# adb  forth
adb> :r
forth: running
MoogleForth starting. Stack: 3802 
2730 46
 ok
decrypt p/q2-q4!
 ok
2730 46
 ok
decode
 ok
^CInterrupt
stopped at      key+016:        add     $010,sp
adb> 05250,48?b
lastword+042:   056     0       0153    0145    0156    0137    0141    0156
                0144    0137    0144    0145    0156    0156    0151    0163
                0137    0141    0156    0144    0137    0142    0162    0151
                0141    0156    0137    0141    0156    0144    0137    0144
                0157    0165    0147    0100    0146    0154    0141    0162
                0145    055     0157    0156    056     0143    0157    0155
adb> 05252,46?c
lastword+044:   ken_and_dennis_and_brian_and_doug@flare-on.com
adb> 
adb> $q
# 
```

For more details, please refer to the [forth_crack.py](./forth_crack.py) script.

So the flag is: `ken_and_dennis_and_brian_and_doug@flare-on.com`
___
