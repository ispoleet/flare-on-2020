#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 09 - serpentine
# ----------------------------------------------------------------------------------------
import capstone
import hashlib
import struct
import unicorn
import re
import z3


# Color codes for tty.
# See: https://misc.flogisoft.com/bash/tip_colors_and_formatting
_GRAY = '\x1b[90m'
_LGRAY = '\x1b[37m'
_RED = '\x1b[91m'
_GREEN = '\x1b[92m'
_YELLOW = '\x1b[93m'
_BLUE = '\x1b[94m'
_RESET = '\x1b[39m'

# Globals for processing pad.
MUL_VAL = 0
PREV_IDX = 0
ARR_TYPE = []
CTR = 0
PAD = []

# Sample key. It is important to use a key where each character is different,
# so we can easily find the index from the chracter.
SAMPLE_KEY = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
#SAMPLE_KEY = 'ISPOLEETMORE1337ISPOLEETMORE1337'
#SAMPLE_KEY = '$$_4lway5_k3ep_mov1ng_and_m0ving'


# --------------------------------------------------------------------------------------------------
def disassemble(code, start_addr):
    """Disassembles an instruction from the `code`."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for insn in md.disasm(code, start_addr):
        return f'{insn.mnemonic:6s} {insn.op_str}'


# ----------------------------------------------------------------------------------------
def reg_map(reg): 
    """Maps a register string to a unicorn register."""
    return {    
        'rax': unicorn.x86_const.UC_X86_REG_RAX,
        'rcx': unicorn.x86_const.UC_X86_REG_RCX,
        'rdx': unicorn.x86_const.UC_X86_REG_RDX,
        'rbx': unicorn.x86_const.UC_X86_REG_RBX,
        'rsp': unicorn.x86_const.UC_X86_REG_RSP,
        'rbp': unicorn.x86_const.UC_X86_REG_RBP,
        'rsi': unicorn.x86_const.UC_X86_REG_RSI,
        'rdi': unicorn.x86_const.UC_X86_REG_RDI,
        'r8' : unicorn.x86_const.UC_X86_REG_R8,
        'r9' : unicorn.x86_const.UC_X86_REG_R9,
        'r10': unicorn.x86_const.UC_X86_REG_R10,
        'r11': unicorn.x86_const.UC_X86_REG_R11,
        'r12': unicorn.x86_const.UC_X86_REG_R12,
        'r13': unicorn.x86_const.UC_X86_REG_R13,
        'r14': unicorn.x86_const.UC_X86_REG_R14,
        'r15': unicorn.x86_const.UC_X86_REG_R15,
    }[reg]


# ----------------------------------------------------------------------------------------
def read_regs(uc):
    """Reads a register from unicorn."""
    return {
        'rax': uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX),
        'rcx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX),
        'rdx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX),
        'rbx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX),
        'rsp': uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP),
        'rbp': uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP),
        'rsi': uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI),
        'rdi': uc.reg_read(unicorn.x86_const.UC_X86_REG_RDI),
        'r8' : uc.reg_read(unicorn.x86_const.UC_X86_REG_R8),
        'r9' : uc.reg_read(unicorn.x86_const.UC_X86_REG_R9),
        'r10': uc.reg_read(unicorn.x86_const.UC_X86_REG_R10),
        'r11': uc.reg_read(unicorn.x86_const.UC_X86_REG_R11),
        'r12': uc.reg_read(unicorn.x86_const.UC_X86_REG_R12),
        'r13': uc.reg_read(unicorn.x86_const.UC_X86_REG_R13),
        'r14': uc.reg_read(unicorn.x86_const.UC_X86_REG_R14),
        'r15': uc.reg_read(unicorn.x86_const.UC_X86_REG_R15),
    }


# ----------------------------------------------------------------------------------------
def is_01_array(uc, address):
    """Checks if an array is carry (0/1) array."""
    global PAD

    arr = mu.mem_read(address, 256)
    lst = list(set(arr))

    # Special cases.
    if len(lst) == 1 and lst[0] == 0:
        return 0, '0'

    if len(lst) == 1 and lst[0] == 1:
        return 256, '1'

    if len(lst) == 2 and 0 in lst and 1 in lst:
        if arr[0] == 0:
            one = arr.find(b'\1')  # We know there is at least an 1.
            if arr[one:].find(b'\0') != -1:
                return None, None
            print(f'{_YELLOW}[+] Normal 0/1 carry array (add){_RESET}')
            PAD.append(('ty', 'normal'))
            return one, '0'

        if arr[1] == 1:
            zero = arr.find(b'\0')  # We know there is at least an 1.
            if arr[zero:].find(b'\1') != -1:
                return None, None
            print(f'{_YELLOW}[+] Inverted 0/1 carry array (sub){_RESET}')
            PAD.append(('ty', 'inverted'))
            return zero, '1'
        
    return None, None


# ----------------------------------------------------------------------------------------
def is_cyclic_array(uc, address):
    """Checks if an array is a cyclic array (add/sub)."""
    arr = mu.mem_read(address, 256)
    for i, a in enumerate(arr):
        if (arr[0] + i) & 0xFF != a:
            return None

    return arr[0]


# ----------------------------------------------------------------------------------------
def is_xor_array(uc, address):
    """Checks if an array is a XOR array."""
    arr = mu.mem_read(address, 256)

    for i, a in enumerate(arr):
        if arr[0] ^ i != a:
            return False, None

    return True, arr[0]


# ----------------------------------------------------------------------------------------
def hook_code(uc, address, size, user_data):
    """Callback for every emulated instruction. Highlights the equations."""
    if 0x140097AF2 <= address and address <= 0x140097B48:
        return  # Ignore tracing inside `save_ctx`.

    global MUL_VAL, PAD, PAD_LINE, PREV_IDX, ARR_TYPE, CTR

    # Read instruction bytes from emulated memory and disassemble them.
    insn_bytes = mu.mem_read(address, size)
    asm = disassemble(insn_bytes, address)
    regs = read_regs(uc)

#    print(f'{_YELLOW}{address:X}h: {_LGRAY}{asm}{_RESET}')
   
    regs = read_regs(uc)
    if asm == 'mul    qword ptr [rsp]':
        # Grab result on `mul`.
        #
        # Check on add/sub/xor if one operand has the result:
        #       140098784h: mul    qword ptr [rsp]
        #       ...
        #       1400987A8h: sub    rdi, qword ptr [rsi + 0xb0]
        #
        # `mul` and `sub/add/xor` are always 7 instructions apart.
        val = regs['rax']
        top = regs['rsp']
        C   = int.from_bytes(mu.mem_read(top, 8), 'little')
        idx = SAMPLE_KEY.index(chr(val))

        print(f'{_RED}[+] key[{_GREEN}{idx}{_RED}] = {_GREEN}0x{val:X}{_RED} * {_GREEN}0x{C:X} = 0x{val*C:X}{_RESET}')
        MUL_VAL = val*C
        PREV_IDX = 0
        PAD.append(('key', {'idx':idx, 'val':C}))

    if match := re.match(r'(add|sub|xor)[ ]+(r.*), qword ptr \[(r.*) \+ 0x([0-9A-Fa-f]*)\]', asm):
        op = match.group(1)
        reg = match.group(2)
        r2 = match.group(3)
        off = int(match.group(4), 16)

        v1 = read_regs(uc)[reg]       
        v2 = int.from_bytes(uc.mem_read(read_regs(uc)[r2] + off, 8), 'little')
        if v1 == MUL_VAL:    
            if op == 'add':
                res = v1 + v2
                PAD.append(('big_op', '+'))
            elif op == 'sub':
                res = (v1 - v2) & 0xFFFFFFFFFFFFFFFF
                PAD.append(('big_op', '-'))
            elif op == 'xor':
                res = v1 ^ v2
                PAD.append(('big_op', '^'))

            print(f'[+] Match: {op}, {reg}, {r2}, {off:X}')
            print(f'[+] Match: 0x{MUL_VAL:X}, 0x{v1:X}, 0x{v2:X}')
            print(f'[+] op found in reg: {op} ~> 0x{v2:X} ~> 0x{res:X}')

        if v2 == MUL_VAL:
            if op == 'add':
                res = v1 + v2
                PAD.append(('big_op', '+'))
            elif op == 'sub':
                res = (v1 - v2) & 0xFFFFFFFFFFFFFFFF
                PAD.append(('big_op', '-'))
            elif op == 'xor':
                res = v1 ^ v2
                PAD.append(('big_op', '^'))        

            print(f'[+] Match: {op}, {reg}, {r2}, {off:X}')
            print(f'[+] Match: 0x{MUL_VAL:X}, 0x{v1:X}, 0x{v2:X}')
            print(f'[+] op found in mem: {op} ~> 0x{v2:X} ~> 0x{res:X}')

    # These adds tell us which byte to access from key * $CONST:
    #   `add qword ptr [r9+98h], 6`
    # 
    # We never read 1 byte; we add offset and read 8 bytes.
    #   => 1 byte memory reads are only from the tables.
    #
    # Example:
    #   add     qword ptr [r9+98h], 3 ; rsp ~> +3 of 0x489FBF1D
    #   mov     rax, [r9+98h]
    #   mov     rax, [rax]            ; rax = 0x19BF1D0000000048
    if match := re.match(r'add[ ]+qword ptr \[r.* \+ 0x98\], ([1234567])', asm):
        idx = int(match.group(1))
        print(f'[+] Accessing array index: {idx}')
        
        # Indices are in order, so we're good :)
        # However, we may skip some!!!
        if idx > PREV_IDX:
            PAD.append(('index', idx))        
        PREV_IDX = idx
    
    if match := re.match(r'add[ ]+(r.*), qword ptr \[r.* \+ 0x([0-9A-Fa-f]*)\]', asm):
        # Array access: Addition IS followed by an 1-byte mov. For example:
        # Example:
        #   1400990BEh: add    rsi, qword ptr [r10 + 0xf0]
        #   1400990C5h: mov    bpl, byte ptr [rsi]
        #
        # $rsi either has the offset or the base.
        # [r10 + 0xf0] either has offset or base.
        reg = match.group(1)
        off = int(match.group(2), 16)
        idx  = int.from_bytes(mu.mem_read(0x14089B910 - 0x78 + off, 8), 'little')
        base = read_regs(uc)[reg]

        if base < 0x100:
            idx, base = base, idx

            a, d = is_01_array(uc, base)
            b = is_cyclic_array(uc, base)
            c, e = is_xor_array(uc, base)
            ARR_TYPE.append((a, d, b, c, e))
            PAD.append(('array', {'a':a, 'b':b, 'c':c, 'd':d, 'e':e}))

            a = hex(a) if a is not None else '-'
            b = hex(b) if b is not None else '-'
            e = hex(e) if e is not None else '-'

            print(f'{_RED}[+] offset:{idx:2X}h, array:{base:X}h ~> 0/1:{a:4} Cyclic:{b:4} XOR:{e}{_RESET}')
       
        elif idx < 0x100:
            a, d = is_01_array(uc, base)
            b = is_cyclic_array(uc, base)
            c, e = is_xor_array(uc, base)
            ARR_TYPE.append((a, d, b, c, e))
            PAD.append(('array', {'a':a, 'b':b, 'c':c, 'd':d, 'e':e}))

            a = hex(a) if a is not None else '-'
            b = hex(b) if b is not None else '-'
            e = hex(e) if e is not None else '-'

            print(f'{_RED}[+] offset:{idx:2X}h, array:{base:X}h ~> 0/1:{a:4} Cyclic:{b:4} XOR:{e}{_RESET}')

    if match := re.match(r'test[ ]+(r..), (r..)', asm):    
        reg1 = match.group(1)
        reg2 = match.group(2)
        val1 = read_regs(uc)[reg1]
        val2 = read_regs(uc)[reg2]
        print(f'{_BLUE}[+] VALUEZ ON test: {reg1} = {val1:X} | {reg2} = {val2:X} {_RESET}')
 
    if match := re.match(r'cmovne[ ]+(r..), (r..)', asm):    
        # Hit the cmonvz. (attempt) to extract all equations:
        process_pad(PAD)        

        PAD = []

        # swap values in order to continue (we don't know the password yet).
        reg1 = match.group(1)
        reg2 = match.group(2)
        
        val1 = uc.reg_read(reg_map(reg1))
        val2 = uc.reg_read(reg_map(reg2))

        mu.reg_write(reg_map(reg1), val2) # swap vals
        mu.reg_write(reg_map(reg2), val1)

        print('='*50 + f' {CTR} ' + '='*50)
        CTR += 1
        

# ----------------------------------------------------------------------------------------
def process_pad(PAD):
    """A failed attempt to print the equations. It's a good reference but don't trust it."""
    print(f'[+] Attempting to print the equations (THIS MAY HAVE MISTAKES!)')
    arr_ty = None
    num = ''
    eq = 0
    run_once = True
    arr_op = ''
    final_ty = None
    FINAL_OPZ = []

    for i, p in enumerate(PAD):
        op, valz = p
        if op == 'key':
            if num != 0 and arr_ty is not None:
                if arr_ty == 'normal':
                    arr_op = '+'
                elif arr_ty == 'inverted':
                    arr_op = '-'
                else:
                    arr_op = '^'

                print(f'{_GREEN}FULL LINE = ({line}) {arr_op} 0x{num}{_RESET}')
                arr_ty = None

            line = f"key[{valz['idx']}] * 0x{valz['val']:X}"
            arr_ty = None
            index = 0
            num = ''
            eq += 1

        elif op == 'big_op':
            print(f'{_GREEN}bigop = {valz}{_RESET}')
            x = f'{valz}'
            FINAL_OPZ.append(x)

        elif op == 'ty':
            arr_ty = valz  
            if eq == 8 and run_once:
                run_once = False
                final_ty = arr_ty
                line = f'(({line}) {arr_op} 0x{num})'
                print(f'{_GREEN}CONT LINE = {line}{_RESET}')
                num = ''
                op = ''
                index = 0
                arr_ty = None

        elif op == 'index':
            index = valz

        elif op == 'array':            
            if PAD[i-1][0] != 'array':
                if arr_ty == 'inverted':
                    if valz['a']:
                        num = f"{valz['a']:02X}" + num
                    elif index > 6:
                        num = f"FF" + num

                if i+1 < len(PAD) and PAD[i+1][0] != 'array': # Only one entry.
                    if index < 7:
                        # Index #7 has always 1 entry so we mistakenly think it's XOR.
                        num = f"{valz['e']:02X}" + num                        
                        arr_ty = 'xor'
            else:
                # Previous entry was an array too.
                # +, - have 2 entries, ^ has one.
                if arr_ty == 'normal':
                    num = f"{valz['b']:02X}" + num

    if num != 0 and final_ty is not None:
        if final_ty == 'normal':
            arr_op = '+'
        elif final_ty == 'inverted':
            arr_op = '-'
        else:
            arr_op = '^'

        print(f'{_GREEN}FINAL LINE = ({line}) {arr_op} 0x{num}{_RESET}')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print(f'{_LGRAY}[+] Serpentine crack started.{_RESET}')
    
    # Load deobfuscated shellcode.
    sc = open('sc.bin', 'rb').read()
    #sc = open('serpentine_deobf_new3.exe', 'rb').read()

    print(f'[+] MD5 of shellcode: {hashlib.md5(sc).hexdigest()}')    
    # pos = sc.find(b'\xEB\x57\x49\xB9\x10\xB9\x89@\x01\x00\x00\x00I\x89\x01I\x89I\bI')
    # sc = sc[pos:]

    # Load data section.    
    data_section = open('data_section', 'rb').read()
    print(f'[+] Data section size: 0x{len(data_section):X}')

    # Set the memory address where emulation starts.
    ADDRESS = 0x140097AF0
    STACK   = 0x67FF000
    
    try:
        # Initialize emulator.
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

        # Initialize the memory.
        mu.mem_map(STACK, 2 * 1024 * 1024)          # 2MB for stack.
        mu.mem_map(0x140022000, 32 * 1024 * 1024)   # 32MB for data.

        mu.mem_write(0x140022000, data_section)
        # IMPORTNAT: I wasted 1 day of my life for this bullshit.
        # Write shellocde **after** the to data section, because data_section is
        # too big and overwrites part of the shellcode.
        mu.mem_write(ADDRESS, sc)

        # Write `lpAddress` and the sample key into memory.
        mu.mem_write(0x14089B8E0, struct.pack('<Q', ADDRESS))
        mu.mem_write(0x14089B8E8, SAMPLE_KEY.encode('utf-8'))

        # Initialize registers.
        mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, STACK+0x40000)

        # Add hooks.
        mu.hook_add(
            unicorn.UC_HOOK_CODE, hook_code, None, ADDRESS, ADDRESS+0x500000)
        #mu.hook_add(
        #    unicorn.UC_HOOK_MEM_READ, hook_mem_read, begin=0x140000000, end=0x1400F0000)

        # Start the actual emulation:
        # 0x14009E710 = First `jmp r12` after the `cmovnz`
        # 0x1400011B0 = u_print_flag (goodboy)
        mu.emu_start(ADDRESS, 0x1400011B0)

    except unicorn.UcError as e:
        raise Exception('Emulation error', e)

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
─[01:21:40]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/09_serpentine]
└──> time ./serpentine_crack.py 
[+] Serpentine crack started.
[+] MD5 of shellcode: 30cc9d79ba3f19a610bd086b5a9d76a4
[+] Data section size: 0x885000
[+] Accessing array index: 4
[+] key[4] = 0x45 * 0xEF7A8C = 0x408C07BC
[+] Normal 0/1 carry array (add)
[+] offset:BCh, array:1400621C0h ~> 0/1:0x73 Cyclic:-    XOR:-
[+] offset:BCh, array:1400620C0h ~> 0/1:-    Cyclic:0x8d XOR:-
[+] Accessing array index: 1
[+] Normal 0/1 carry array (add)
[+] offset: 8h, array:14004D1C0h ~> 0/1:0xa3 Cyclic:-    XOR:-
[+] offset: 8h, array:14004D0C0h ~> 0/1:-    Cyclic:0x5d XOR:-
[+] Accessing array index: 2
[+] Normal 0/1 carry array (add)
[+] offset:8Ch, array:14005F0C0h ~> 0/1:0x7a Cyclic:-    XOR:-
[+] offset:8Ch, array:14005EFC0h ~> 0/1:-    Cyclic:0x86 XOR:-
[+] Accessing array index: 3
[+] Normal 0/1 carry array (add)
[+] offset:41h, array:1400691C0h ~> 0/1:0x63 Cyclic:-    XOR:-
[+] offset:41h, array:1400690C0h ~> 0/1:-    Cyclic:0x9d XOR:-
[+] Accessing array index: 4
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[24] = 0x59 * 0x45B53C = 0x183C01DC
[+] Match: sub, rdi, rsi, B0
[+] Match: 0x183C01DC, 0xDE126549, 0x183C01DC
[+] op found in mem: sub ~> 0x183C01DC ~> 0xC5D6636D
[+] Normal 0/1 carry array (add)
[+] offset:6Dh, array:14004A7C0h ~> 0/1:0xa9 Cyclic:-    XOR:-
[+] offset:6Dh, array:14004A6C0h ~> 0/1:-    Cyclic:0x57 XOR:-
[+] Accessing array index: 1
[+] Normal 0/1 carry array (add)
[+] offset:63h, array:14008C8C0h ~> 0/1:0x12 Cyclic:-    XOR:-
[+] offset:63h, array:14008C7C0h ~> 0/1:-    Cyclic:0xee XOR:-
[+] Accessing array index: 2
[+] Normal 0/1 carry array (add)
[+] offset:D7h, array:140075CC0h ~> 0/1:0x46 Cyclic:-    XOR:-
[+] offset:D7h, array:140075BC0h ~> 0/1:-    Cyclic:0xba XOR:-
[+] Accessing array index: 3
[+] Normal 0/1 carry array (add)
[+] offset:C6h, array:14002EEC0h ~> 0/1:0xe8 Cyclic:-    XOR:-
[+] offset:C6h, array:14002EDC0h ~> 0/1:-    Cyclic:0x18 XOR:-
[+] Accessing array index: 4
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 5
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[0] = 0x41 * 0xE4CF8B = 0x3A18B24B
[+] Match: sub, rdi, rsi, F0
[+] Match: 0x3A18B24B, 0xDE9151C4, 0x3A18B24B
[+] op found in mem: sub ~> 0x3A18B24B ~> 0xA4789F79
[+] Inverted 0/1 carry array (sub)
[+] offset:79h, array:140085AC0h ~> 0/1:0xde Cyclic:-    XOR:-
[+] offset:79h, array:1400859C0h ~> 0/1:-    Cyclic:0x22 XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset:9Eh, array:1400765C0h ~> 0/1:0xbb Cyclic:-    XOR:-
[+] offset:9Eh, array:1400764C0h ~> 0/1:-    Cyclic:0x45 XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset:77h, array:1400401C0h ~> 0/1:0x3f Cyclic:-    XOR:-
[+] offset:77h, array:1400400C0h ~> 0/1:-    Cyclic:0xc1 XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:A4h, array:140063FC0h ~> 0/1:0x91 Cyclic:-    XOR:-
[+] offset:A4h, array:140063EC0h ~> 0/1:-    Cyclic:0x6f XOR:-
[+] Accessing array index: 5
[+] offset: 0h, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset: 0h, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[8] = 0x49 * 0xF5C990 = 0x46167A10
[+] Match: sub, rsi, rdx, A0
[+] Match: 0x46167A10, 0x1338E39B, 0x46167A10
[+] op found in mem: sub ~> 0x46167A10 ~> 0xFFFFFFFFCD22698B
[+] Normal 0/1 carry array (add)
[+] offset:8Bh, array:14004A0C0h ~> 0/1:0xaa Cyclic:-    XOR:-
[+] offset:8Bh, array:140049FC0h ~> 0/1:-    Cyclic:0x56 XOR:-
[+] Accessing array index: 1
[+] Normal 0/1 carry array (add)
[+] offset:69h, array:14006D0C0h ~> 0/1:0x5a Cyclic:-    XOR:-
[+] offset:69h, array:14006CFC0h ~> 0/1:-    Cyclic:0xa6 XOR:-
[+] Accessing array index: 2
[+] Normal 0/1 carry array (add)
[+] offset:23h, array:140091CC0h ~> 0/1:0x6  Cyclic:-    XOR:-
[+] offset:23h, array:140091BC0h ~> 0/1:-    Cyclic:0xfa XOR:-
[+] Accessing array index: 3
[+] Normal 0/1 carry array (add)
[+] offset:CEh, array:1400533C0h ~> 0/1:0x95 Cyclic:-    XOR:-
[+] offset:CEh, array:1400532C0h ~> 0/1:-    Cyclic:0x6b XOR:-
[+] Accessing array index: 4
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset: 0h, array:140898770h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset: 0h, array:1400247C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[20] = 0x55 * 0x733178 = 0x263F6CD8
[+] Match: xor, r13, rcx, E0
[+] Match: 0x263F6CD8, 0x391D0FE1, 0x263F6CD8
[+] op found in mem: xor ~> 0x263F6CD8 ~> 0x1F226339
[+] offset:39h, array:14003E0C0h ~> 0/1:-    Cyclic:-    XOR:0x3b
[+] Accessing array index: 1
[+] offset:63h, array:1400840C0h ~> 0/1:-    Cyclic:-    XOR:0xdb
[+] Accessing array index: 2
[+] offset:22h, array:1400878C0h ~> 0/1:-    Cyclic:-    XOR:0xe3
[+] Accessing array index: 3
[+] offset:1Fh, array:14004EAC0h ~> 0/1:-    Cyclic:-    XOR:0x61
[+] Accessing array index: 4
[+] offset: 0h, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 7
[+] offset: 0h, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[16] = 0x51 * 0x9A17B8 = 0x30C18138
[+] Match: xor, r12, r11, A8
[+] Match: 0x30C18138, 0x7EC1B802, 0x30C18138
[+] op found in mem: xor ~> 0x30C18138 ~> 0x4E00393A
[+] Inverted 0/1 carry array (sub)
[+] offset:3Ah, array:140071FC0h ~> 0/1:0xb1 Cyclic:-    XOR:-
[+] offset:3Ah, array:140071EC0h ~> 0/1:-    Cyclic:0x4f XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset:38h, array:1400264C0h ~> 0/1:0x4  Cyclic:-    XOR:-
[+] offset:38h, array:1400263C0h ~> 0/1:-    Cyclic:0xfc XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset: 0h, array:1400360C0h ~> 0/1:0x28 Cyclic:-    XOR:-
[+] offset: 0h, array:140035FC0h ~> 0/1:-    Cyclic:0xd8 XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:4Dh, array:14007CEC0h ~> 0/1:0xca Cyclic:-    XOR:-
[+] offset:4Dh, array:14007CDC0h ~> 0/1:-    Cyclic:0x36 XOR:-
[+] Accessing array index: 4
[+] offset:FFh, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset:FFh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 5
[+] offset:FFh, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset:FFh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[12] = 0x4D * 0x773850 = 0x23DBF010
[+] Match: xor, rdi, r12, E8
[+] Match: 0x23DBF010, 0xFFFFFFFF83D83489, 0x23DBF010
[+] op found in mem: xor ~> 0x23DBF010 ~> 0xFFFFFFFFA003C499
[+] offset:99h, array:1400775C0h ~> 0/1:-    Cyclic:-    XOR:0xbe
[+] Accessing array index: 1
[+] offset:C4h, array:140051BC0h ~> 0/1:-    Cyclic:-    XOR:0x68
[+] Accessing array index: 2
[+] offset: 3h, array:140054CC0h ~> 0/1:-    Cyclic:-    XOR:0x6f
[+] Accessing array index: 3
[+] offset:A0h, array:14004B9C0h ~> 0/1:-    Cyclic:-    XOR:0x5a
[+] Accessing array index: 4
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 5
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[28] = 0x32 * 0xE21D3D = 0x2C29B5EA
[+] Match: xor, r12, rdi, D8
[+] Match: 0x2C29B5EA, 0xFFFFFFFFFA6CAC27, 0x2C29B5EA
[+] op found in mem: xor ~> 0x2C29B5EA ~> 0xFFFFFFFFD64519CD
[+] offset:CDh, array:1400338C0h ~> 0/1:-    Cyclic:-    XOR:0x23
[+] Accessing array index: 1
[+] offset:19h, array:140030EC0h ~> 0/1:-    Cyclic:-    XOR:0x1d
[+] Accessing array index: 2
[+] offset:45h, array:140063AC0h ~> 0/1:-    Cyclic:-    XOR:0x91
[+] Accessing array index: 3
[+] offset:D6h, array:14004C7C0h ~> 0/1:-    Cyclic:-    XOR:0x5c
[+] Accessing array index: 4
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 5
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Inverted 0/1 carry array (sub)
[+] offset:EEh, array:1400597C0h ~> 0/1:0x79 Cyclic:-    XOR:-
[+] offset:EEh, array:1400596C0h ~> 0/1:-    Cyclic:0x87 XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset: 4h, array:140059EC0h ~> 0/1:0x7a Cyclic:-    XOR:-
[+] offset: 4h, array:140059DC0h ~> 0/1:-    Cyclic:0x86 XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset:D3h, array:1400504C0h ~> 0/1:0x64 Cyclic:-    XOR:-
[+] offset:D3h, array:1400503C0h ~> 0/1:-    Cyclic:0x9c XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:8Ah, array:14005CFC0h ~> 0/1:0x81 Cyclic:-    XOR:-
[+] offset:8Ah, array:14005CEC0h ~> 0/1:-    Cyclic:0x7f XOR:-
[+] Accessing array index: 4
[+] Inverted 0/1 carry array (sub)
[+] offset:FFh, array:1400941C0h ~> 0/1:0xff Cyclic:-    XOR:-
[+] offset:FFh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 5
[+] Inverted 0/1 carry array (sub)
[+] offset:FFh, array:1400941C0h ~> 0/1:0xff Cyclic:-    XOR:-
[+] offset:FFh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 6
[+] Inverted 0/1 carry array (sub)
[+] offset:FFh, array:1400941C0h ~> 0/1:0xff Cyclic:-    XOR:-
[+] offset:FFh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 7
[+] offset:FFh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 1
[+] offset:8Ah, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 4
[+] offset: 0h, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset: 0h, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] VALUEZ ON test: r14 = 96F8A75 | r14 = 96F8A75 
[+] Attempting to print equations (THIS MAY HAVE MISTAKES!)
FULL LINE = (key[4] * 0xEF7A8C) + 0x00009D865D8D
bigop = -
FULL LINE = (key[24] * 0x45B53C) + 0x000018BAEE57
bigop = -
FULL LINE = (key[0] * 0xE4CF8B) - 0x913FBBDE
bigop = -
FULL LINE = (key[8] * 0xF5C990) + 0x00006BFAA656
bigop = ^
FULL LINE = (key[20] * 0x733178) ^ 0x000061E3DB3B
bigop = ^
FULL LINE = (key[16] * 0x9A17B8) - 0xCA2804B1
bigop = ^
FULL LINE = (key[12] * 0x773850) ^ 0x0000005A6F68BE
bigop = ^
CONT LINE = ((key[28] * 0xE21D3D) ^ 0x00005C911D23)
FINAL LINE = (((key[28] * 0xE21D3D) ^ 0x00005C911D23)) - 0x00FFFFFFFF81647A79
================================================== 0 ==================================================
[+] key[17] = 0x52 * 0x99AA81 = 0x31389D52
[+] Inverted 0/1 carry array (sub)
[+] offset:52h, array:140047FC0h ~> 0/1:0x51 Cyclic:-    XOR:-
[+] offset:52h, array:140047EC0h ~> 0/1:-    Cyclic:0xaf XOR:-
[+] Accessing array index: 1

[..... TRUNCATED FOR BREVITY .....]

[+] key[7] = 0x48 * 0x995144 = 0x2B1EDB20
[+] Match: xor, rbp, rdx, D8
[+] Match: 0x2B1EDB20, 0xFFFFFFFDFE2F0EF3, 0x2B1EDB20
[+] op found in mem: xor ~> 0x2B1EDB20 ~> 0xFFFFFFFDD531D5D3
[+] Inverted 0/1 carry array (sub)
[+] offset:D3h, array:1400416C0h ~> 0/1:0x42 Cyclic:-    XOR:-
[+] offset:D3h, array:1400415C0h ~> 0/1:-    Cyclic:0xbe XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset:D5h, array:140056DC0h ~> 0/1:0x73 Cyclic:-    XOR:-
[+] offset:D5h, array:140056CC0h ~> 0/1:-    Cyclic:0x8d XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset:31h, array:1400899C0h ~> 0/1:0xe7 Cyclic:-    XOR:-
[+] offset:31h, array:1400898C0h ~> 0/1:-    Cyclic:0x19 XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:D4h, array:1400806C0h ~> 0/1:0xd2 Cyclic:-    XOR:-
[+] offset:D4h, array:1400805C0h ~> 0/1:-    Cyclic:0x2e XOR:-
[+] Accessing array index: 4
[+] offset:FDh, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset:FDh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 6
[+] offset:FFh, array:140898870h ~> 0/1:0x0  Cyclic:-    XOR:-
[+] offset:FFh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 7
[+] offset:FFh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] key[11] = 0x4C * 0x811C39 = 0x265460EC
[+] Match: xor, rdi, rbp, D8
[+] Match: 0x265460EC, 0xFFFFFFFD024A6291, 0x265460EC
[+] op found in mem: xor ~> 0x265460EC ~> 0xFFFFFFFD241E027D
[+] Inverted 0/1 carry array (sub)
[+] offset:7Dh, array:140050BC0h ~> 0/1:0x65 Cyclic:-    XOR:-
[+] offset:7Dh, array:140050AC0h ~> 0/1:-    Cyclic:0x9b XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset: 2h, array:14003BBC0h ~> 0/1:0x35 Cyclic:-    XOR:-
[+] offset: 2h, array:14003BAC0h ~> 0/1:-    Cyclic:0xcb XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset:1Dh, array:14007F8C0h ~> 0/1:0xd0 Cyclic:-    XOR:-
[+] offset:1Dh, array:14007F7C0h ~> 0/1:-    Cyclic:0x30 XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:23h, array:1400383C0h ~> 0/1:0x2d Cyclic:-    XOR:-
[+] offset:23h, array:1400382C0h ~> 0/1:-    Cyclic:0xd3 XOR:-
[+] Accessing array index: 7
[+] offset:FFh, array:1400248C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 3
[+] key[3] = 0x44 * 0x9953D7 = 0x28BA451C
[+] Match: xor, rsi, r9, E8
[+] Match: 0x28BA451C, 0xFFFFFFFCF64DCD18, 0x28BA451C
[+] op found in mem: xor ~> 0x28BA451C ~> 0xFFFFFFFCDEF78804
[+] offset: 4h, array:1400522C0h ~> 0/1:-    Cyclic:-    XOR:0x69
[+] Accessing array index: 1
[+] offset:88h, array:140057DC0h ~> 0/1:-    Cyclic:-    XOR:0x76
[+] Accessing array index: 2
[+] offset:F7h, array:14005F4C0h ~> 0/1:-    Cyclic:-    XOR:0x87
[+] Accessing array index: 3
[+] offset:DEh, array:14005C3C0h ~> 0/1:-    Cyclic:0x80 XOR:0x80
[+] Accessing array index: 5
[+] offset:FFh, array:1400245C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Inverted 0/1 carry array (sub)
[+] offset:6Dh, array:1400590C0h ~> 0/1:0x78 Cyclic:-    XOR:-
[+] offset:6Dh, array:140058FC0h ~> 0/1:-    Cyclic:0x88 XOR:-
[+] Accessing array index: 1
[+] Inverted 0/1 carry array (sub)
[+] offset:FDh, array:1400344C0h ~> 0/1:0x24 Cyclic:-    XOR:-
[+] offset:FDh, array:1400343C0h ~> 0/1:-    Cyclic:0xdc XOR:-
[+] Accessing array index: 2
[+] Inverted 0/1 carry array (sub)
[+] offset:70h, array:1400416C0h ~> 0/1:0x42 Cyclic:-    XOR:-
[+] offset:70h, array:1400415C0h ~> 0/1:-    Cyclic:0xbe XOR:-
[+] Accessing array index: 3
[+] Inverted 0/1 carry array (sub)
[+] offset:5Eh, array:1400917C0h ~> 0/1:0xf9 Cyclic:-    XOR:-
[+] offset:5Eh, array:1400916C0h ~> 0/1:-    Cyclic:0x7  XOR:-
[+] Accessing array index: 4
[+] Inverted 0/1 carry array (sub)
[+] offset:FBh, array:1400933C0h ~> 0/1:0xfd Cyclic:-    XOR:-
[+] offset:FBh, array:1400932C0h ~> 0/1:-    Cyclic:0x3  XOR:-
[+] Accessing array index: 5
[+] Inverted 0/1 carry array (sub)
[+] offset:FEh, array:1400941C0h ~> 0/1:0xff Cyclic:-    XOR:-
[+] offset:FEh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 6
[+] Inverted 0/1 carry array (sub)
[+] offset:FEh, array:1400941C0h ~> 0/1:0xff Cyclic:-    XOR:-
[+] offset:FEh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] Accessing array index: 7
[+] offset:FEh, array:1400940C0h ~> 0/1:-    Cyclic:0x1  XOR:-
[+] offset:F5h, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 1
[+] offset:D9h, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 4
[+] offset:FEh, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 5
[+] offset:FFh, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] Accessing array index: 7
[+] offset:FFh, array:1400246C0h ~> 0/1:-    Cyclic:0x0  XOR:0x0
[+] VALUEZ ON test: rbx = FFFFFFFE652ED9F5 | rbx = FFFFFFFE652ED9F5 
[+] Attempting to print the equations (THIS MAY HAVE MISTAKES!)
FULL LINE = (key[19] * 0x390B78) + 0x00007D5DEEA4
bigop = -
FULL LINE = (key[15] * 0x70E6C8) - 0x6EA339E2
bigop = ^
FULL LINE = (key[27] * 0xD8A292) - 0x288D6EC5
bigop = -
FULL LINE = (key[23] * 0x978C71) - 0xFFE5D85ED8
bigop = +
FULL LINE = (key[31] * 0x9A14D4) - 0xB69670CC
bigop = ^
FULL LINE = (key[7] * 0x995144) - 0xFFD2E77342
bigop = ^
FULL LINE = (key[11] * 0x811C39) - 0xFF2DD03565
bigop = ^
CONT LINE = ((key[3] * 0x9953D7) - 0x0080877669)
FINAL LINE = (((key[3] * 0x9953D7) - 0x0080877669)) - 0x0000FFFFFFFDF94224
================================================== 31 ==================================================
[+] Program finished successfully. Bye bye :)

real    0m13.543s
user    0m13.231s
sys 0m0.312s
"""
# ----------------------------------------------------------------------------------------
