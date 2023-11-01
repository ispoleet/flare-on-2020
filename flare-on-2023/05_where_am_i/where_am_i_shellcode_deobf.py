#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 5 - Where am I?
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

# For stage #1 shellcode
func_map = {
    0x02550000: 0x02550000,
    0x02551534: 0x025502A6,
    0x02552BC7: 0x02550351,
    0x0255380D: 0x02550912,
    0x0255620D: 0x0255099D,
    0x025519F0: 0x02550A46,
    0x02550A74: 0x02550C3D,
    0x025526C1: 0x02551E97,
    0x0255438F: 0x02551F60,
    0x02554DDE: 0x025520CB,
    0x025529C5: 0x02552AA3,
    0x02550E2F: 0x0255364F,
    0x025521AB: 0x025537BB,
    0x025564E7: 0x02554AFB,
    0x02552B3E: 0x02554C6F,
    0x02552CFF: 0x02554E00,
}

# For stage #2 shellcode
'''
func_map = {
    0x02550000: 0x02550000,
    0x02550639: 0x02550241,
    0x025502FF: 0x0255029A,
}
'''

# Comment this out the second time you run the script
func_map = {0x2550000:0x2550000}
func_off = 0x2550000

_NEEDS_FUNC_MAP_ = False
_MAX_FUNC_LEN_ = 0x1400


# ----------------------------------------------------------------------------------------
def deobf_func(entry, code, md):
    """Deobfuscates a shellcode function at address `entry`."""
    global func_off, func_map, _NEEDS_FUNC_MAP_, _MAX_FUNC_LEN_

    deobf_shellcode = {}    
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
            for insn in md.disasm(code[nxt_blk - 0x2550000:], nxt_blk):
                print(f'[+]   .text:{insn.address:08X} ({len(deobf_shellcode):03X}h) {insn.mnemonic} {insn.op_str}')

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

                if insn.mnemonic == 'ret':
                    # We 've reached the end of function/shellcode.
                    deobf_shellcode += insn.bytes
                    more_shellcode = False
                    break
                elif insn.mnemonic == 'jmp':
                    # Move on to the next block
                    nxt_blk = insn.op_find(capstone.CS_OP_IMM, 1).imm
                    break
                elif insn.mnemonic in ['je', 'jne', 'jl', 'jle', 'jg', 'jge', 'jb', 'jbe', 'ja', 'jae']:
                    # For conditional jumps we need to relocate jump target.
                    jmp_trg = insn.op_find(capstone.CS_OP_IMM, 1).imm
                    queue.append(jmp_trg)
                    
                    # SPECIAL CASE:
                    #   We have a `jg 0x2551c23` which is 2 bytes but we need to substitute it
                    #   with an 4 byte offset.
                    if insn.address == 0x02551C77:
                        # Reserve extra space in case you want to add long jump
                        jmp_fix_tbl.append((jmp_trg, len(deobf_shellcode), 6))
                        deobf_shellcode += b'\x0f\x8f' + struct.pack('<L', 0x1337)
                    else:
                        jmp_fix_tbl.append((jmp_trg, len(deobf_shellcode), insn.size))
                        deobf_shellcode += insn.bytes

                elif insn.mnemonic == 'call':
                    if insn.op_find(capstone.CS_OP_IMM, 1) == None:
                        pass  # We have a call to win32.
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
def deobf_shellcode(obf_shellcode, base_addr):
    """Deobfuscates a whole shellcode `base_addr`."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True

    queue = [base_addr]
    visited = set()
    funcz = {}
    while queue:
        nxt_func = queue.pop(0)
        print(f'[+] Processing function 0x{nxt_func:08X}')

        if nxt_func in visited:
            continue
        visited.add(nxt_func)

        func, nxt_funcs = deobf_func(nxt_func, obf_shellcode, md)
        funcz[nxt_func] = func
        queue += nxt_funcs
    
    for v in visited:
        print(f'[+] Function at: 0x{v:08X}')

    deobf_shellcode = b'\x90'*0x6000  # Max possible func size.
    deobf_shellcode = bytearray(deobf_shellcode)

    # Run once to get the map then rerun.
    print('func_map = {')
    prev = 0
    for addr, code in funcz.items():
        off = func_map[addr] - base_addr
        print(f'    0x{addr:08X}: 0x{base_addr + prev:08X},')
        prev += len(code) + 16
    print('}')

    if _NEEDS_FUNC_MAP_:
        print('[+] Now paste `func_map` into the script and re-run the code.')
        exit()
    
    for addr, code in funcz.items():
        off = func_map[addr] - base_addr
        print(f'[+] Fixing offset: {off:X}h, {addr:X}h, {len(code)}')
        if len(code) > _MAX_FUNC_LEN_:
            raise Exception(f'Function is too big (0x{len(code):X} bytes)')

        deobf_shellcode[off:off + len(code)] = code

    return deobf_shellcode


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Where am I? shellcode deobfuscator started.')
    
    # For stage #1
    obf_shellcode = open('shellcode.bin', 'rb').read()
    
    # For stage #2
    #obf_shellcode = open('shellcode_stage2.bin', 'rb').read()
    #obf_shellcode = obf_shellcode[0x31:]

    clean_shellcode = deobf_shellcode(obf_shellcode, 0x02550000)

    # For stage #1
    open('shellcode_deobf.bin', 'wb').write(clean_shellcode)

    # For stage #2
    # open('shellcode_stage2_deobf.bin', 'wb').write(clean_shellcode)

    print('[+] Program finished successfully. Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/05_where_am_i$ ./where_am_i_shellcode_deobf.py 
[+] Where am I? shellcode deobfuscator started.
[+] Processing function 0x02550000
[+] Visiting shellcode at address 0x02550000 ...
[+]   .text:02550000 (000h) push ebp
[+]   .text:02550001 (001h) jmp 0x25500b0
[+]   .text:025500B0 (001h) jmp 0x2550202
.....
[+]   Adding a jump to offset EDh
[+] Fixing jump at 0x0255646E in offset 0BDh. New offset: 0EBh 6
[+] Fixing jump at 0x0255667A in offset 0E5h. New offset: 0FEh 6
[+] ~ = ~ = ~ = DEOBFUSCATED FUNCTION 0x02550000 (02550000h) = ~ = ~ = ~
[+]   .text:02550000 push ebp   
[+]   .text:02550001 mov ebp, esp   
[+]   .text:02550003 sub esp, 0x10   
[+]   .text:02550006 push edx   
[+]   .text:02550007 push esi   
[+]   .text:02550008 mov esi, 0xa26e6d50   
[+]   .text:0255000D xor esi, 0xf0dec85a   
[+]   .text:02550013 xor esi, 0x1483e3fd   
[+]   .text:02550019 sub esi, 0x5cd29bea   
[+]   .text:0255001F xor esi, 0xcddaaa8a   
[+]   .text:02550025 sub esi, 0x9ce3af01   
[+]   .text:0255002B xor esi, 0x87d6d281   
[+]   .text:02550031 mov dword ptr [esp + 4], esi   
[+]   .text:02550035 pop esi   
[+]   .text:02550036 call dword ptr [0x460210]   
[+]   .text:0255003C call 0x2551400   
.....
[+] Processing function 0x02552CFF
[+] Function at: 0x02550000
[+] Function at: 0x025526C1
[+] Function at: 0x025529C5
[+] Function at: 0x02552BC7
[+] Function at: 0x025564E7
[+] Function at: 0x025521AB
[+] Function at: 0x0255620D
[+] Function at: 0x0255380D
[+] Function at: 0x0255438F
[+] Function at: 0x025519F0
[+] Function at: 0x02550E2F
[+] Function at: 0x02552B3E
[+] Function at: 0x02551534
[+] Function at: 0x02550A74
[+] Function at: 0x02554DDE
[+] Function at: 0x02552CFF
func_map = {
    0x02550000: 0x02550000,
    0x02551534: 0x025502A6,
    0x02552BC7: 0x02550351,
    0x0255380D: 0x02550912,
    0x0255620D: 0x0255099D,
    0x025519F0: 0x02550A46,
    0x02550A74: 0x02550C3D,
    0x025526C1: 0x02551E97,
    0x0255438F: 0x02551F60,
    0x02554DDE: 0x025520CB,
    0x025529C5: 0x02552AA3,
    0x02550E2F: 0x0255364F,
    0x025521AB: 0x025537BB,
    0x025564E7: 0x02554AFB,
    0x02552B3E: 0x02554C6F,
    0x02552CFF: 0x02554E00,
}
[+] Now paste `func_map` into the script and re-run the code.
'''
# ----------------------------------------------------------------------------------------
