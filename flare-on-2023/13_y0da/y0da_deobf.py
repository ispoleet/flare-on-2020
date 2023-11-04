#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 13 - y0da
#
# NOTE: This script is an enhanced version of `where_am_i_shellcode_deobf.py`
# ----------------------------------------------------------------------------------------
import capstone
import struct


# **NOTE:** To get these offsets for `func_map` run script once. Then copy-paste the
# `func_map`here and re-run the script.
#
# The reason we do that, is because when we encounter a call instruction we do not
# know the new offset because we do not know the new size of the current function.
# So we run once to compute all offsets and then we run again to build the new
# shellcode with the correct offsets.

func_map = {
    0x00031B01: 0x00031B01,
    0x0000793F: 0x00031B23,
    0x0003C2DE: 0x00031B4D,
    0x00014124: 0x00036284,
    0x0001AB46: 0x00036437,
    0x000439AD: 0x0003674B,
    0x0004EA0E: 0x000367C6,
    0x00025EEA: 0x000367EF,
    0x0002BB6C: 0x0003D7BA,
    0x0000E453: 0x0003D7F4,
    0x000517BB: 0x0003D82E,
    0x0004868C: 0x0003D861,
    0x0004D4E7: 0x0003E10D,
    0x000500AF: 0x0003E487,
    0x00047E9A: 0x0003E4A7,
    0x000577D3: 0x0003E4E1,
    0x0000D923: 0x0003E51B,
    0x00050282: 0x0003E618,
    0x00035A83: 0x0003EB1F,
    0x00024DAD: 0x0003EBCC,
    0x0003F469: 0x0003EC43,
    0x0000BF82: 0x0003EC7D,
    0x00000D23: 0x0003ECB0,
    0x0001BADC: 0x0003ED46,
    0x000368EF: 0x0003EE2D,
    0x0003B9E2: 0x0003EECB,
    0x00020AF6: 0x000409A4,
    0x00053A9D: 0x00041BB3,
    0x00034CD2: 0x00041BCD,
    0x0004043D: 0x00041D2F,
    0x0003824A: 0x00041D7E,
    0x00062454: 0x00041DDE,
    0x0004876E: 0x000420A9,
    0x0002B1DF: 0x00042111,
    0x0000C441: 0x000421D2,
    0x0001AF76: 0x00042205,
    0x0001F804: 0x0004230B,
    0x0001C761: 0x000423DC,
    0x0005A79C: 0x00043988,
    0x0002FB3D: 0x000439DE,
    0x0004DFC7: 0x00043B11,
    0x000399E1: 0x00043FD6,
    0x0005959A: 0x0004419C,
    0x0003505E: 0x0004420F,
    0x0003D9B0: 0x00044236,
    0x00042B53: 0x00044268,
    0x0003E8A8: 0x000442C0,
    0x00054DB0: 0x0004430D,
    0x00001883: 0x00044509,
    0x000376E1: 0x000445BA,
    0x0001C830: 0x00044720,
    0x0000F525: 0x0004476E,
    0x000171FA: 0x000447A1,
    0x00002A52: 0x000447D4,
    0x0000A110: 0x00044807,
    0x0004C926: 0x0004483A,
    0x00004067: 0x00044947,
    0x00011AAB: 0x00044A99,
    0x0004DEDC: 0x00044B17,
    0x00045B90: 0x00044CB7,
    0x0000EDA0: 0x0004508F,
    0x0006007F: 0x00045102,
    0x00048BBB: 0x0004514E,
    0x0004CF97: 0x0004596D,
}

# Comment this out the second time you run the script
# func_map = {0x31B01:0x31B01}
func_off = 0x31B01

entry = 0x000031B01

_NEEDS_FUNC_MAP_ = False
_MAX_FUNC_LEN_ = 0x8000  # We have larger functions now!


# ----------------------------------------------------------------------------------------
def deobf_func(entry, code, md):
    """Deobfuscates a shellcode function at address `entry`."""
    global func_off, func_map, _NEEDS_FUNC_MAP_, _MAX_FUNC_LEN_
    
    visited = set()  # Visited instructions.
    queue = [entry]

    deobf_shellcode = bytearray()
    off_map = {}
    jmp_fix_tbl = []
    func_calls = []

    while queue:  # Do a BFS to visit all conditional jumps.
        nxt_blk = queue.pop(0)
        print(f'[+] Visiting shellcode at address 0x{nxt_blk:08X} ...')
        
        chunk_base = nxt_blk

        # Follow the jmp instructions and collect all other instructions through the way.
        more_shellcode = True
        while more_shellcode:
            # Disassemble instructions from `nxt_blk` until you hit a jmp/ret.
            for insn in md.disasm(code[nxt_blk:], nxt_blk):
                new_addr = 0x180032701 - 0x000031B01 + insn.address
                print(f'[+]   .text:{new_addr:08X} ({len(deobf_shellcode):03X}h) {insn.mnemonic} {insn.op_str}')               

                if insn.address in visited:
                    print(f'[+]   Instruction is already visited.')
                    more_shellcode = False
                    
                    print(f'[+]   Adding a jump to offset {off_map[insn.address]:X}h')
                    # 5 is the new jmp insn size.
                    diff = (off_map[insn.address] - len(deobf_shellcode) - 5) & 0xFFFFFFFF
                    deobf_shellcode += b'\xe9' + struct.pack('<L', diff)
                    break
                else:
                    visited.add(insn.address)

                off_map[insn.address] = len(deobf_shellcode)

                # Special cases for CreateThread.
                #
                # The following instruction(s) must be replaced:
                #       .text:1800153AA lea r8, [rip + 0x33edb]     <~ Case #1
                #       .text:18002B91E lea r8, loc_18004E0E7       <~ Case #2
                #
                # This takes you to 0x18004928C.
                # Replace it with  49 c7 c0 44 33 22 11    mov    r8,0x11223344
                if new_addr in [0x1800153AA, 0x18002B91E]:
                    print('[+] Special case #1 found:', ' '.join(f'{x:02X}' for x in insn.bytes))
                    # we are at: 0x1800153AA + 7
                    # we go to : 0x18004928C 
                    if new_addr == 0x1800153AA:
                        func_entry = 0x18004928C - (0x180032701 - 0x000031B01)
                    else:
                        func_entry = 0x18004E0E7 - (0x180032701-0x000031B01)

                    # Treat it like a call.
                    func_calls.append(func_entry)                
                    if func_entry not in func_map:
                        func_off += _MAX_FUNC_LEN_
                        func_map[func_entry] = func_off
                        _NEEDS_FUNC_MAP_ = True
                    
                    f = func_map[func_entry]
                    g = func_map[entry]

                    diff = (f - g - len(deobf_shellcode) - 7) & 0xFFFFFFFF
                    print(f'[+] Call diff: {diff:08X}h {f:X}h, {g:X}h, {len(deobf_shellcode)}')
                    deobf_shellcode += insn.bytes[:3] + struct.pack('<L', diff)
                    continue
          
                if insn.mnemonic == 'ret':
                    # We 've reached the end of function/shellcode.
                    deobf_shellcode += insn.bytes
                    more_shellcode = False
                    break
                elif insn.mnemonic == 'jmp' and insn.op_find(capstone.CS_OP_IMM, 1):
                    # Move on to the next block
                    
                    op = insn.op_find(capstone.CS_OP_IMM, 1)
                    nxt_blk = op.imm
                    break
                elif insn.mnemonic in ['je', 'jne', 'jl', 'jle', 'jg', 'jge', 'jb', 'jbe', 'ja', 'jae']:
                    # For conditional jumps we need to relocate jump target.
                    jmp_trg = insn.op_find(capstone.CS_OP_IMM, 1).imm
                    queue.append(jmp_trg) 

                    jmp_fix_tbl.append((jmp_trg, len(deobf_shellcode), insn.size))
                    deobf_shellcode += insn.bytes

                elif insn.mnemonic == 'call':
                    if insn.op_find(capstone.CS_OP_IMM, 1) == None:
                        pass  # We have a call ot win32
                        deobf_shellcode += insn.bytes
                    else:
                        func_entry = insn.op_find(capstone.CS_OP_IMM, 1).imm
                        print(f'[+]   Calling function at 0x{func_entry:08X}')

                        func_calls.append(func_entry)

                        if func_entry not in func_map:
                            func_off += _MAX_FUNC_LEN_
                            func_map[func_entry] = func_off
                            _NEEDS_FUNC_MAP_ = True
                        
                        f = func_map[func_entry]
                        g = func_map[entry]

                        diff = (f - g - len(deobf_shellcode) - 5) & 0xFFFFFFFF
                        print(f'[+] Call diff: {diff:08X}h {f:X}h, {g:X}h, {len(deobf_shellcode)}')
                        deobf_shellcode += b'\xe8' + struct.pack('<L', diff)        
                else:
                    # For all other instructions simply append them to the new shellcode.
                    deobf_shellcode += insn.bytes
                
        deobf_shellcode += b'\x90'*4

    for trg, off, sz in jmp_fix_tbl:
        new_off = off_map[trg]
        print(f'[+] Fixing jump at 0x{trg:08X} in offset {off:03X}h. New offset: {new_off:03X}h', sz)

        diff = (new_off - off - sz) & 0xFFFFFFFF
        if sz == 2:
            if diff >= 0x100:
                raise Exception('Jump offset is not enough!', diff)
            else:
                deobf_shellcode[off + 1] = diff & 0xFF
        elif sz == 3:
            deobf_shellcode[off + 1: off + 5] = struct.pack('<H', diff)
        elif sz == 6:
            deobf_shellcode[off + 2: off + 6] = struct.pack('<L', diff)
        else:
            raise Exception(f'Unknown jump instruction size: {sz}')

    print(f'[+] ~ = ~ = ~ = DEOBFUSCATED FUNCTION 0x{entry:08X} ({func_map[entry]:08X}h) = ~ = ~ = ~')
    for insn in md.disasm(deobf_shellcode, func_map[entry]):
        print(f'[+]   .text:{insn.address:08X} {insn.mnemonic} {insn.op_str}   ')

    return deobf_shellcode, func_calls    




# ----------------------------------------------------------------------------------------
def deobf_y0da(obf_y0da):
    """Deobfuscates the whole binary starting at `base_addr`."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    print(' '.join(f'{x:02X}' for x in obf_y0da[0x31B01:0x31B01 + 20]))

    queue = [0x31B01]
    visited = set()
    funcz = {}
    while queue:
        nxt_func = queue.pop(0)
        print(f'[+] Processing function 0x{nxt_func:08X}')

        if nxt_func in visited:
            continue
        visited.add(nxt_func)

        func, nxt_funcs = deobf_func(nxt_func, obf_y0da, md)
        funcz[nxt_func] = func
        queue += nxt_funcs
    
    for v in visited:
        print(f'[+] Function at: 0x{v:08X}')

    deobf_code = b'\x90'*0x20000  # Max possible func size. It's now larger!!!
    deobf_code = bytearray(deobf_code)

    # Run once to get the map then rerun.
    print('func_map = {')
    prev = 0
    for addr, code in funcz.items():
        off = func_map[addr] - 0x31B01
        print(f'    0x{addr:08X}: 0x{0x31B01 + prev:08X},')
        prev += len(code) + 16
    print('}')

    if _NEEDS_FUNC_MAP_:
        print('[+] Now paste `func_map` into the script and re-run the code.')
        exit()
        
    for addr, code in funcz.items():
        off = func_map[addr] - 0x31B01
        print(f'[+] Fixing offset: {off:X}h, {addr:X}h, {len(code)}')
        if len(code) > _MAX_FUNC_LEN_:
            raise Exception(f'Function is too big (0x{len(code):X} bytes)')

        deobf_code[off:off + len(code)] = code

    return deobf_code


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] y0da deobfuscator started.')

    obf_y0da = open('y0da.exe', 'rb').read()
 
    deobf_code = deobf_y0da(obf_y0da)

    # Now, carefully insert the deobfuscated code back to the binary.
    #
    # 0x180001000 to 0x180065FF6
    # 
    # 0x180032701 is at 0x31B01
    # 0x180001000 is at 0x400
    # 0x180065ff6 is at 0x653FC
    #
    # First insn at: 0x400
    # Last insn at : 0x653FC
    x = bytearray(b'\xcc'*(0x653FC - 0x400))  # Fill the extra space with `int 3`.
    x[:len(deobf_code)] = deobf_code    

    clean_y0da = bytearray(obf_y0da[:0x400] + x + obf_y0da[0x653FC:])
    
    # Add a jump at start to the beginning of the code.
    diff = (0x400 - 0x31B01 - 5) & 0xFFFFFFFF
    clean_y0da[0x31B01:0x31B01+5] = b'\xe9' + struct.pack('<L', diff) 

    open('y0da_deobf.exe', 'wb').write(clean_y0da)

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/13_y0da$ ./y0da_deobf.py; md5sum y0da_deobf.exe*
[+] y0da deobfuscator started.
48 83 EC 28 E9 98 0F FE FF AA 8E 03 00 CC CC CC CC CC C6 84
[+] Processing function 0x00031B01
[+] Visiting shellcode at address 0x00031B01 ...
[+]   .text:180032701 (000h) sub rsp, 0x28
[+]   .text:180032705 (004h) jmp 0x12aa2
[+]   .text:1800136A2 (004h) call 0x793f
[+]   Calling function at 0x0000793F
[+] Call diff: 00007FF7h 39B01h, 31B01h, 4
[+]   .text:1800136A7 (009h) jmp 0x334c9
[+]   .text:1800340C9 (009h) add rsp, 0x28
[+]   .text:1800340CD (00Dh) jmp 0x16182
[+]   .text:180016D82 (00Dh) ret 
[+] ~ = ~ = ~ = DEOBFUSCATED FUNCTION 0x00031B01 (00031B01h) = ~ = ~ = ~
[+]   .text:00031B01 sub rsp, 0x28   
[+]   .text:00031B05 call 0x39b01   
[+]   .text:00031B0A add rsp, 0x28   
[+]   .text:00031B0E ret    
[+]   .text:00031B0F nop    
[+]   .text:00031B10 nop    
[+]   .text:00031B11 nop    
[+]   .text:00031B12 nop    
[+] Processing function 0x0000793F
[+] Visiting shellcode at address 0x0000793F ...
[+]   .text:18000853F (000h) push rsi
[+]   .text:180008540 (001h) jmp 0x594b8
[+]   .text:18005A0B8 (001h) mov rsi, rsp
[+]   .text:18005A0BB (004h) jmp 0x245f2
[+]   .text:1800251F2 (004h) and rsp, 0xfffffffffffffff0
[+]   .text:1800251F6 (008h) jmp 0x3424f
[+]   .text:180034E4F (008h) sub rsp, 0x20
[+]   .text:180034E53 (00Ch) jmp 0x5d3ef
[+]   .text:18005DFEF (00Ch) call 0x3c2de
[+]   Calling function at 0x0003C2DE

[.....TRUNCATED FOR BREVITY.....]
[+] Function at: 0x0004876E
[+] Function at: 0x000368EF
[+] Function at: 0x00020AF6
[+] Function at: 0x0001AF76
[+] Function at: 0x000171FA
[+] Function at: 0x0006007F
func_map = {
    0x00031B01: 0x00031B01,
    0x0000793F: 0x00031B23,
    0x0003C2DE: 0x00031B4D,
    0x00014124: 0x00036284,
    0x0001AB46: 0x00036437,
    0x000439AD: 0x0003674B,
    0x0004EA0E: 0x000367C6,
    0x00025EEA: 0x000367EF,
    0x0002BB6C: 0x0003D7BA,
    0x0000E453: 0x0003D7F4,
    0x000517BB: 0x0003D82E,
    0x0004868C: 0x0003D861,
    0x0004D4E7: 0x0003E10D,
    0x000500AF: 0x0003E487,
    0x00047E9A: 0x0003E4A7,
    0x000577D3: 0x0003E4E1,
    0x0000D923: 0x0003E51B,
    0x00050282: 0x0003E618,
    0x00035A83: 0x0003EB1F,
    0x00024DAD: 0x0003EBCC,
    0x0003F469: 0x0003EC43,
    0x0000BF82: 0x0003EC7D,
    0x00000D23: 0x0003ECB0,
    0x0001BADC: 0x0003ED46,
    0x000368EF: 0x0003EE2D,
    0x0003B9E2: 0x0003EECB,
    0x00020AF6: 0x000409A4,
    0x00053A9D: 0x00041BB3,
    0x00034CD2: 0x00041BCD,
    0x0004043D: 0x00041D2F,
    0x0003824A: 0x00041D7E,
    0x00062454: 0x00041DDE,
    0x0004876E: 0x000420A9,
    0x0002B1DF: 0x00042111,
    0x0000C441: 0x000421D2,
    0x0001AF76: 0x00042205,
    0x0001F804: 0x0004230B,
    0x0001C761: 0x000423DC,
    0x0005A79C: 0x00043988,
    0x0002FB3D: 0x000439DE,
    0x0004DFC7: 0x00043B11,
    0x000399E1: 0x00043FD6,
    0x0005959A: 0x0004419C,
    0x0003505E: 0x0004420F,
    0x0003D9B0: 0x00044236,
    0x00042B53: 0x00044268,
    0x0003E8A8: 0x000442C0,
    0x00054DB0: 0x0004430D,
    0x00001883: 0x00044509,
    0x000376E1: 0x000445BA,
    0x0001C830: 0x00044720,
    0x0000F525: 0x0004476E,
    0x000171FA: 0x000447A1,
    0x00002A52: 0x000447D4,
    0x0000A110: 0x00044807,
    0x0004C926: 0x0004483A,
    0x00004067: 0x00044947,
    0x00011AAB: 0x00044A99,
    0x0004DEDC: 0x00044B17,
    0x00045B90: 0x00044CB7,
    0x0000EDA0: 0x0004508F,
    0x0006007F: 0x00045102,
    0x00048BBB: 0x0004514E,
    0x0004CF97: 0x0004596D,
}
[+] Now paste `func_map` into the script and re-run the code.
'''
# ----------------------------------------------------------------------------------------
