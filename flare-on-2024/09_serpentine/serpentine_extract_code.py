#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 09 - serpentine
# ----------------------------------------------------------------------------------------
import ida_dbg
import ida_name
import idaapi
import keystone
import re


# The emulated program (e.g., the real instructions of the) program is stored here.
EMULATED_PROG = []

# The register offsets from `CONTEXT` struct:
# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
REG_MAP = {
        0x34: 'csr',
        0x78: 'rax',
        0x80: 'rcx', 
        0x88: 'rdx',
        0x90: 'rbx',
        0x98: 'rsp', 
        0xA0: 'rbp',
        0xA8: 'rsi',
        0xB0: 'rdi',
        0xB8: 'r8 ',
        0xC0: 'r9 ',
        0xC8: 'r10',
        0xD0: 'r11',
        0xD8: 'r12',
        0xE0: 'r13',
        0xE8: 'r14',
        0xF0: 'r15',
        0xF8: 'rip'
}

# An address for a "scratch pad", i.e., a temporary storage for our meta-variables.
# This should be somewhere in .data; We place it after the `key`.
# (we cannot use stack because `rsp` is used by the program).
SCRATCH_ADDR = 0x14089B910 

# Our `save_ctx` function.
SAVE_CTX_FUNC="""
    mov r9, 0x%X
    mov [r9], rax
    mov [r9 + 0x8], rcx
    mov [r9 + 0x10], rdx
    mov [r9 + 0x18], rbx
    mov [r9 + 0x20], rsp
    add qword ptr [r9 + 0x20], 8  ; $rsp is already -8 for the `save_ctx` call.
    mov [r9 + 0x28], rbp
    mov [r9 + 0x30], rsi
    mov [r9 + 0x38], rdi
    mov [r9 + 0x40], r8
    ; $r9 is not used at all so don't save it.
    mov [r9 + 0x50], r10  ; increment offset (50h) so it matches directly with `OpInfo`.
    mov [r9 + 0x58], r11
    mov [r9 + 0x60], r12
    mov [r9 + 0x68], r13
    mov [r9 + 0x70], r14
    mov [r9 + 0x78], r15
    stmxcsr  [r9 + 0x80]
    sub r9, 0x78
    ret
""" % SCRATCH_ADDR

# The total number of `cmovnz` instructions (we have 32 in total).
CMOVNZ_CTR = 0

def ADDTO_EMULATED_PROG(insn):
    EMULATED_PROG.append((insn, assemble(insn)))


# ----------------------------------------------------------------------------------------
def assemble(asm):
    """Assembles (converts from assembly to opcodes) an instruction."""
    if ';' in asm:  # Drop comment if exists.
        asm = asm[:asm.find(';')]
    
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    asm_tuple = ks.asm(asm)
    asm_code  = bytes([x for x in asm_tuple[0]])
    print(f'[+] Compiling: {asm!r} ~> {asm_code!r}')

    return asm_code


# ----------------------------------------------------------------------------------------
def load_UnwindInfo(ea):
    """Parses an `_UNWIND_INFO` struct from memory.

    The struct(s) are defined here:
        https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170

        typedef struct _UNWIND_INFO {
            UBYTE Version       : 3;
            UBYTE Flags         : 5;
            UBYTE SizeOfProlog;
            UBYTE CountOfCodes;
            UBYTE FrameRegister : 4;
            UBYTE FrameOffset   : 4;
            UNWIND_CODE UnwindCode[1];
        } UNWIND_INFO, *PUNWIND_INFO;

        typedef union _UNWIND_CODE {
            struct {
                UCHAR CodeOffset;
                UCHAR UnwindOp : 4;
                UCHAR OpInfo : 4;
            };

            USHORT FrameOffset;
        } UNWIND_CODE, *PUNWIND_CODE;

    Based on the `CountOfCodes` the `UnwindCode` can have >1 elements.    
    """
    Version       = ida_bytes.get_byte(ea)
    SizeOfProlog  = ida_bytes.get_byte(ea + 1)
    CountOfCodes  = ida_bytes.get_byte(ea + 2)
    FrameRegister = ida_bytes.get_byte(ea + 3)
    UnwindCodesArray = []
    for i in range(CountOfCodes):
        ida_bytes.get_byte(ea + 4 + i*2)
        UnwindCodesArray.append({
            'CodeOffset' : ida_bytes.get_byte(ea + 4 + i*2),
            'UnwindOp'   : ida_bytes.get_byte(ea + 4 + i*2 + 1) & 0xF,
            'OpInfo'     : ida_bytes.get_byte(ea + 4 + i*2 + 1) >> 4,
            'FrameOffset': ida_bytes.get_word(ea + 4 + i*2 + 0)
        })

    n = CountOfCodes if CountOfCodes % 2 == 0 else CountOfCodes + 1
    FunctionStartAddress = ida_bytes.get_dword(ea + 4 + n*2)
    return {
        'Version': Version,
        'SizeOfProlog': SizeOfProlog,
        'CountOfCodes': CountOfCodes,
        'FrameRegister': FrameRegister,
        'UnwindCodesArray': UnwindCodesArray,
        'FunctionStartAddress': FunctionStartAddress
    }


# ----------------------------------------------------------------------------------------
def _step(curr_ea):
    """Runs a single instruction on the debugger (step into)."""
    ida_dbg.request_step_into()
    ida_dbg.run_requests()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

    return ida_dbg.get_reg_val('RIP')


# ----------------------------------------------------------------------------------------
def _extract_reencrypted_insn(curr_ea):
    """Extracts the decrypted instruction from a function call.

    During the execution of the handler (before the next `hlt` is triggered) there are
    some `call` instructions that decrypt, execute and re-encrypt an single instruction.
    For example, we have a `call u_set_r11_to_10ADD7F49` which takes us to the following
    function:

        u_set_r11_to_10ADD7F49:
            ...
            mov     rax, 0
            mov     ah, cs:byte_6974D26
            lea     eax, [eax+7F497049h]
            mov     dword ptr cs:loc_6974D49, eax ; decrypt single insn
            pop     rax                           ; restore rax

        loc_6974D49:
            mov     r11, 10ADD7F49h               ; real insn
            mov     dword ptr cs:loc_6974D49, 676742DDh ; re-encrypt insn
            ...
            retn

    This function extracts the decrypted instruction in a nice and simple way:
    We monitor the function opcodes looking for any changes. After we execute an
    instruction, we read function memory to check if any opcodes have been modified.
    If yes, we store the offset of the first modified byte as this is the decrypted
    instruction. When execution reaches this offset, we log the instruction and we
    return it.

    There are some special cases however, when the decrypted instruction is a `retn`
    or a `jmp`, which we handle accordingly.
    """
    start = curr_ea         # Set function boundaries.
    end   = curr_ea + 0x30  # These functions are small, 48-bytes are enough.
    # Copy all opcodes from the function. 
    mem_orig = [ida_bytes.get_byte(i) for i in range(start, end)]

    decr_asm, decr_ops = '', b''
    off = -1
    while True:
        # Disassemble the current instruction.
        asm = generate_disasm_line(curr_ea, GENDSM_FORCE_CODE)
        asm += ' ; decr'
       
        insn = idaapi.insn_t();
        idaapi.decode_insn(insn, curr_ea)

        # Because the code is messed up, it is possible that the current instruction cannot be
        # disassembled b/c IDA doesn't mark it as code. In that case, just undefine the 
        # instruction and define it as code.
        if print_insn_mnem(curr_ea) not in asm:
            del_items(curr_ea)
            create_insn(curr_ea)
            insn = idaapi.insn_t();
            idaapi.decode_insn(insn, curr_ea)            
        
        # Get the opcodes of the current instruction.
        ops = bytes([ida_bytes.get_byte(curr_ea + i) for i in range(insn.size)])

        # Special handling for return and jump instructions.
        if asm.startswith('retn'):
            if curr_ea <= start + off and curr_ea + insn.size > start + off:
                # We hit the decrypted instruction and it's a `ret`.
                print(f'[+]    Hit decrypted instruction (ret): {asm}')
                decr_asm = asm
                decr_ops = ops

            # We have reached the end of the function.
            return 'ret', decr_asm, decr_ops

        elif asm.startswith('jmp'):
            if curr_ea <= start + off and curr_ea + insn.size > start + off:
                # We hit the decrypted instruction and it's a `jmp`.
                print(f'[+]    Hit decrypted instruction (jmp): {asm}')
                decr_asm = asm
                decr_ops = ops

            # We have reached the end of the function.
            return 'jmp', decr_asm, decr_ops

        # Copy all opcodes from the function again.
        mem = [ida_bytes.get_byte(i) for i in range(start, end)]
        
        # Check if the function has been modified for first time.
        if off == -1 and mem != mem_orig:
            # The instruction has been decrypted, but not executed yet. Find its offset.
            for i, (a, b) in enumerate(zip(mem, mem_orig)):
                if a != b:
                    off = i  # Offset found.
                    break
   
        if curr_ea <= start + off and curr_ea + insn.size > start + off:
            # We hit the decrypted instruction.
            # Log it and continue execution until return.
            print(f'[+]    Hit decrypted instruction: {asm}')
            decr_asm = asm
            decr_ops = ops

        curr_ea = _step(curr_ea)  # Advance to the next instruction.

    raise Exception(f'Could not find re-encrypted instruction in: 0x{curr_ea:X}')


# ----------------------------------------------------------------------------------------
def run_till_next_hlt(curr_ea):
    """Runs the program until the next `hlt` and builds the deobfuscated shellcode."""
    global CMOVNZ_CTR
    
    assert print_insn_mnem(curr_ea) == 'hlt'  # We always start from a `hlt`.

    # Do what `u_handler_IMPORTANT()` does.
    UnwindInfo_offset = curr_ea + 1 + ida_bytes.get_byte(curr_ea + 1) + 1
    if UnwindInfo_offset & 1 == 1:
        UnwindInfo_offset += 1    

    print(f'[+] UnwindInfo offset: 0x{UnwindInfo_offset:X}')
    UnwindInfo = load_UnwindInfo(UnwindInfo_offset)

    # We are at a `hlt`.
    ida_dbg.continue_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

    # Now we are at `u_handler_IMPORTANT`.
    ida_dbg.continue_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    
    # Now we are are at `call qword ptr [r9+30h]`.
    # $r9 points to _DISPATCHER_CONTEXT. For more details, see:
    #   https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
    curr_ea = _step(curr_ea)

    # At this point we must be at the 1st instruction of UnwindInfo handler
    assert ida_dbg.get_reg_val('RIP') == lpAddress + UnwindInfo['FunctionStartAddress'], ('%X != %X' % (ida_dbg.get_reg_val('RIP'), lpAddress + UnwindInfo['FunctionStartAddress']))

    # Call `save_ctx`.
    ADDTO_EMULATED_PROG('mov rax, 0x%x' % 0x14089B8E0) # =lpAddress
    ADDTO_EMULATED_PROG('call [rax]')

    # Emulate the Unwind VM and add all instruction to the emulated program.
    for ins in emulate_vm(UnwindInfo):
        for i in ins:
            ADDTO_EMULATED_PROG(i)

    # Now the hard part: Execute the instructions from the handler and figure out
    # which ones should be added to our shellcode.
    ctx_reg = ''
    while True:
        asm = generate_disasm_line(curr_ea, GENDSM_FORCE_CODE)
        asm += '  ; hdl'

        insn = idaapi.insn_t();
        idaapi.decode_insn(insn, curr_ea)

        # If current instruction is not defined as code, redefine it.
        if print_insn_mnem(curr_ea) not in asm:
            del_items(curr_ea)
            create_insn(curr_ea)
            insn = idaapi.insn_t();
            idaapi.decode_insn(insn, curr_ea)

        ops = bytes([ida_bytes.get_byte(curr_ea + i) for i in range(insn.size)])


        # Some instructions require special care.
        #
        # TODO: Use `insn_t` to check opcodes, instead of regexes.
        if print_insn_mnem(curr_ea) == 'cmovnz':
            print(f'[+] Conditional mov found: {asm}')
            
            # We found a final key check. 
            # Because our key is random, this check will fail and we won't be
            # able to condition. Swap the values, so the other path is taken.
            # (Or just simply set Z flag).
            r1 = print_operand(curr_ea, 0)
            r2 = print_operand(curr_ea, 1)
            v1 = idc.get_reg_value(r1)
            v2 = idc.get_reg_value(r2)
            idc.set_reg_value(v1, r2)
            idc.set_reg_value(v2, r1)

            CMOVNZ_CTR += 1
            #if CMOVNZ_CTR == 6:
            #   return

        if match := re.match(r'lea[ ]+(.*), .*', asm):
            # lea instruction takes the offset of next unrolled iteration, if
            # the key check is correct. For example:
            #
            #   Stack[0000399C]:00000000069B378C         test    r12, r12
            #   Stack[0000399C]:00000000069B378F         lea     r13, unk_66A3F24
            #   Stack[0000399C]:00000000069B3796         cmovnz  r13, rsi
            #   Stack[0000399C]:00000000069B379A         jmp     r13
            #   
            # Or:
            #   Stack[0000399C]:00000000069A66EC         test    r14, r14
            #   Stack[0000399C]:00000000069A66EF         lea     r12, unk_66B3D4E
            #   Stack[0000399C]:00000000069A66F6         cmovnz  r12, r15
            #   Stack[0000399C]:00000000069A66FA         jmp     r12
            # 
            # This offset is fixed and will be invalid in our shellcode, so we
            # replace it with a relative address. For example:
            #
            # Replace;
            #       lea     r13, unk_66A3F24
            # With:
            #       lea    r13, [rip + 0x10]            
            reg = match.group(1)

            print(f'[+] lea found with: {reg}')             
            asm = f'lea {reg}, [rip + 0x7] ; patch' # len(cmovnz) + len(jmp)
            ops = assemble(asm)
        
        if match := re.match(r'jmp[ ]+r(.*)', asm):                        
            reg = match.group(1)        
            print(f'[+] jmp reg found: {reg}')
            ADDTO_EMULATED_PROG(asm)

            # `jmp rsp` is 2-bytes, but `jmp r12` is 3-bytes.
            # Add an extra nop and always jump to +3 (so you execute the NOP if jmp is 2 bytes).
            asm = f'nop' 
            ops = assemble(asm)

        # We know context is always [r9+28h]. Find the register that holds the context.
        if match := re.match(r'mov[ ]+(.*), \[r9\+28h\]', asm):
            ctx_reg = match.group(1)
            print(f'[+] Context register found: {ctx_reg}')     
            curr_ea = _step(curr_ea)  # Move to the next instruction.
            
            ADDTO_EMULATED_PROG(f'mov {ctx_reg}, 0x{SCRATCH_ADDR - 0x78:x} ; ctx')

            # Do not add these instructions to final output; they mess up the results.
            # For example:            
            #       mov     r15, rbp                      ; decr ; rpl
            #       movzx   rbx, bl                       ; hdl
            #       ; hlt ~> jmp     near ptr unk_69805FC ; decr
            #       mov     r15, [r9+28h]                 ; hdl
            #       ...
            #       add     r15, rsi                      ; decr ; rpl
            #       
            # Here $r15 should not be set; it should contain the value of $rbp.            
            continue 

        elif match := re.match(r'ldmxcsr dword ptr \[%s\+([0-9A-F]*)h\].*' % ctx_reg, asm):
            # This instruction is tricky. First load register to xcsr.
            # Then replace it with:
            #       mov [$SCRATCH_ADDR], $REG
            #       ldmxcsr dword ptr [$SCRATCH_ADDR]            
            #
            # NOTE: `mov dword ptr [0x6910000], ebx`  is assembled as
            #       `mov  dword ptr [rip + 0x690fffa], ebx`.
            #       So we use $r9 which we know it's never used as it points to DISPATCHER_CONTEXT:
            # 
            #   mov r9, $SCRATCH_ADDR
            #   mov [r9], $REG
            #   ldmxcsr dword ptr [r9] 
            if ctx_reg:                
                off = int(match.group(1), 16)

                if off != 0x34:
                    pass  # Exclude xcsr.
                else:
                    # No need to reload it; it's already there.
                    curr_ea = _step(curr_ea)  # Just move on.
                    continue

        elif match := re.match(r'(.*)[ ]+(.*), \[%s\+34h\](.*)' % ctx_reg, asm):
            mnm = match.group(1)                
            reg = match.group(2)
            aft = match.group(3)
        
            # xcsr register. This is equivalent of `stmxcsr` instruction.
            # For example the:
            #       mov r11d, [rbx+34h]
            #
            # is equivalent to:
            #       mov $REG, $SCRATCH_ADDR
            #       stmxcsr dword ptr [$REG]
            #       mov $REG, [$REG]
            #
            # UPDATE: We already did `stmxcsr [r9 + 0x80]` in `save_ctx`, so just use it:
            #       mov r11d, [r9+80h]

            # If r9 is already used as `ctx_reg` we can't reuse it for our saved context.
            # We do a little assembly hack to use another register.
            if ctx_reg != 'r9':
                asm2 = f'{mnm} {reg}, [r9 + 0xf8] {aft}'  # Simply change the offset.
                print(f'[+] Replace instruction {asm} ~> {asm2}')
                asm = asm2 + ' ; rpl'
                ops = assemble(asm2)
            else:
                print(f'[+] FOUND $r9 in context register: DO YOUR MAGIC #1: {reg} ~> {asm}')
                if reg != 'eax':
                    ADDTO_EMULATED_PROG(f'push rax')
                    ADDTO_EMULATED_PROG('mov rax, 0x%X' % (SCRATCH_ADDR - 0x78))                
                    ADDTO_EMULATED_PROG(f'{mnm} {reg}, [rax + 0xf8] {aft}') # Just change the offset.

                    asm2 = f'pop rax'
                    print(f'[+] Replace instruction {asm} ~> {asm2}')
                    asm = asm2 + ' ; rpl'
                    ops = assemble(asm2)
                else:
                    # If $eax is used, don't use it for something else.
                    print(f'[+] Use $rbx!!!')
                    ADDTO_EMULATED_PROG(f'push rbx')
                    ADDTO_EMULATED_PROG('mov rbx, 0x%X' % (SCRATCH_ADDR - 0x78))
                    ADDTO_EMULATED_PROG(f'{mnm} {reg}, [rbx + 0xf8] {aft}') # Just change the offset.
                    asm2 = f'pop rbx'
                    print(f'[+] Replace instruction {asm} ~> {asm2}')
                    asm = asm2 + '  ; rpl'
                    ops = assemble(asm2)   

        elif match := re.match(r'(.*)\[%s\+([0-9A-F]*)h\](.*)' % ctx_reg, asm):        
            if ctx_reg:
                bef = match.group(1)                
                off = int(match.group(2), 16)
                aft = match.group(3)

                if off != 0x34:
                    pass  # Exclude xcsr.
                else:
                    raise Exception(f'You fucked up: {asm}')                    

        print(f'[+] Executing: {curr_ea:X}h ~> {asm} | {print_insn_mnem(curr_ea)}')

        if asm.startswith('call '):
            curr_ea = _step(curr_ea)
            r, i, o = _extract_reencrypted_insn(curr_ea)

            # Do all the above checks for the decrypted instruction.
            # TODO: Remove the duplication.
            if match := re.match(r'mov[ ]+(.*), \[r9\+28h\]', i):
                raise Exception('This should never happen!')

            elif match := re.match(r'ldmxcsr dword ptr \[%s\+([0-9A-F]*)h\].*' % ctx_reg, i):
                if ctx_reg:                    
                    off = int(match.group(1), 16)
                    if off != 0x34:
                        pass
                    else:
                        # We don't have to reload xcsr. It's already there.
                        curr_ea = _step(curr_ea)
                        continue

            elif match := re.match(r'(.*)[ ]+(.*), \[%s\+34h\](.*)' % ctx_reg, i):                        
                mnm = match.group(1)                
                reg = match.group(2)

                if ctx_reg != 'r9':
                    asm2 = f'{mnm} {reg}, [r9 + 0xf8] {aft}'                    
                    print(f'[+] Replace instruction {i} ~> {asm2}')
                    i = asm2 + ' ; rpl'
                    o = assemble(asm2)
                else:
                    print(f'[+] FOUND $r9 in context register: DO YOUR MAGIC #2: {reg} ~> {i}')
                    if reg != 'eax':
                        ADDTO_EMULATED_PROG(f'push rax')
                        ADDTO_EMULATED_PROG('mov rax, 0x%X' % (SCRATCH_ADDR - 0x78))
                        ADDTO_EMULATED_PROG(f'{mnm} {reg}, [rax + 0xf8] {aft}')

                        asm2 = f'pop rax'
                        print(f'[+] Replace instruction {i} ~> {asm2}')
                        i = asm2 + '  ; rpl'
                        o = assemble(asm2)
                    else:
                        print(f'[+] Use $rbx (#2)!!!')
                        ADDTO_EMULATED_PROG(f'push rbx')
                        ADDTO_EMULATED_PROG('mov rbx, 0x%X' % (SCRATCH_ADDR - 0x78))
                        ADDTO_EMULATED_PROG(f'{mnm} {reg}, [rbx + 0xf8] {aft}')

                        asm2 = f'pop rbx'
                        print(f'[+] Replace instruction {i} ~> {asm2}')
                        i = asm2 + '  ; rpl'
                        o = assemble(asm2)                        

            if match := re.match(r'lea[ ]+(.*), .*', i):
                # lea handling is the same as above.
                reg = match.group(1)
                print(f'[+] lea found with: {reg}')
                i = f'lea {reg}, [rip + 0x7] ; patch'  # len(cmovnz)+len(jmp)
                o = assemble(i)

            elif match := re.match(r'jmp[ ]+r.*', i):
                print(f'[+] jmp reg found')
                ADDTO_EMULATED_PROG(i)

                # `jmp rsp` is 2-bytes, but `jmp r12` is 3-bytes.
                # Add an extra nop and always jump to +3 (so you execute the NOP if jmp is 2 bytes).
                i = f'nop'
                o = assemble(asm2)
                
            elif match := re.match(r'(.*)\[%s\+([0-9A-F]*)h\](.*)' % ctx_reg, i):
                if ctx_reg:
                    bef = match.group(1)                
                    off = int(match.group(2), 16)
                    aft = match.group(3)

                    if off != 0x34:
                        pass # Exclude xcsr.
                    else:
                        raise Exception(f'You fucked up #2: {i}')

            EMULATED_PROG.append((i, o))

            if r == 'ret':
                pass
            elif r == 'jmp':
                curr_ea = _step(curr_ea)
                if print_insn_mnem(curr_ea) == 'hlt':
                    # Drop the last instruction
                    last = EMULATED_PROG[-1]
                    EMULATED_PROG.pop()
                    EMULATED_PROG.append((f'; hlt ~> {last[0]}', b''))
                    break  # We have reached the end.
                else:
                    raise Exception('wtf!?', print_insn_mnem(curr_ea))
        else:
            EMULATED_PROG.append((asm, ops))

        curr_ea = _step(curr_ea)

        if (curr_ea == 0x1400011B0 or # u_print_flag (goodboy)
            curr_ea == 0x1400011F0):  # u_wrong_key  (badboy)          
                print('[+] Reached the end: 0x{curr_ea:X}')
                break        

    return curr_ea


# ----------------------------------------------------------------------------------------
def emulate_vm(UnwindInfo):
    """Emulates `RtlpUnwindPrologue()` and extracts the VM instructions.

    serpenine.exe uses `RtlpUnwindPrologue()` as a mini VM to execute additional
    instruction. Based on the `UnwindInfo`, we add the appropriate instructions to
    our shellcode.

    The source code of `RtlpUnwindPrologue()` can be found here:
        https://github.com/wisny101/Windows-Server-2003-Source/blob/master/base/ntos/rtl/amd64/exdsptch.c#L949
    """
    regs = [
        'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
        'r8',  'r9',  'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
    ]

    ins_all = []
    
    Index         = 0
    UnwindCode    = UnwindInfo['UnwindCodesArray']
    CountOfCodes  = UnwindInfo['CountOfCodes']
    FrameRegister = UnwindInfo['FrameRegister']

    while Index < CountOfCodes:
        UnwindOp = UnwindCode[Index]['UnwindOp']
        OpInfo   = UnwindCode[Index]['OpInfo']

        # NOTE: $r9 is always valid, as `save_ctx` sets it every time.

        # TODO: Check this?
        #   if (PrologOffset >= UnwindInfo->UnwindCode[Index].CodeOffset)

        if UnwindOp == 0:  # UWOP_PUSH_NONVOL
            # IntegerAddress = (PULONG64)(ContextRecord->Rsp);
            # IntegerRegister[OpInfo] = *IntegerAddress;
            # ContextRecord->Rsp += 8;
            ins = [
                'mov rax, [r9 + 0x98]  ; vm',
                'mov rax, [rax]  ; vm', 
                'mov [r9 + 0x%x], rax  ; vm' % (0x78+OpInfo*8),
                'add qword ptr [r9 + 0x98], 8  ; vm',
            ]
            print(f'[+] UWOP_PUSH_NONVOL: {UnwindOp} ~> {ins}')

        elif UnwindOp == 1:  # UWOP_ALLOC_LARGE            
            # Index += 1;
            # FrameOffset = UnwindInfo->UnwindCode[Index].FrameOffset;
            # if (OpInfo != 0) {
            #       Index += 1;
            #       FrameOffset += (UnwindInfo->UnwindCode[Index].FrameOffset << 16);
            # } else {
            #       FrameOffset *= 8;
            # }
            # ContextRecord->Rsp += FrameOffset;
            Index += 1
            FrameOffset = UnwindCode[Index]['FrameOffset']
            if OpInfo != 0:
                Index += 1
                FrameOffset += UnwindCode[Index]['FrameOffset'] << 16
            else:
                FrameOffset *= 8

            ins = [
                'add qword ptr [r9 + 0x98], 0x%x  ; vm' % FrameOffset
            ]
            print(f'[+] UWOP_ALLOC_LARGE: {UnwindOp} ~> {ins}')

        elif UnwindOp == 2:  # UWOP_ALLOC_SMALL
            ins = [
                'add qword ptr [r9 + 0x98], 0x%x  ; vm' % ((OpInfo * 8) + 8)
            ]
            print(f'[+] UWOP_ALLOC_SMALL: {UnwindOp} ~> {ins}')

        elif UnwindOp == 3:  # UWOP_SET_FPREG
            # ContextRecord->Rsp = IntegerRegister[UnwindInfo->FrameRegister];
            # ContextRecord->Rsp -= UnwindInfo->FrameOffset * 16;

            # TODO: Verify this.
            FrameOffset = OpInfo # UnwindCode[Index]['FrameOffset']
            ins = [
                'mov rax, [r9 + 0x%x]  ; vm' % (0x78+FrameRegister*8),
                'mov [r9 + 0x98], rax  ; vm',
                'sub qword ptr [r9 + 0x98], 0x%x  ; vm' % (FrameOffset*16),
            ]
            print(f'[+] UWOP_SET_FPREG: {UnwindOp} ~> {ins}')

        # Implement things on demand.
        elif UnwindOp == 4:  # UWOP_SAVE_NONVOL
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 5:  # UWOP_SAVE_NONVOL_FAR
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 6:  # UWOP_SAVE_XMM
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 7:  # UWOP_SAVE_XMM_FAR
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 8:  # UWOP_SAVE_XMM128
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 9:  # UWOP_SAVE_XMM128_FAR
            raise Exception(f'Unwind opcode not implemented #:{UnwindOp}')

        elif UnwindOp == 10:  # UWOP_PUSH_MACHFRAME
            # ReturnAddress = (PULONG64)(ContextRecord->Rsp);
            # StackAddress = (PULONG64)(ContextRecord->Rsp + (3 * 8));
            # if (OpInfo != 0) {
            #    ReturnAddress += 1;
            #    StackAddress +=  1;
            # }
            #
            # ContextRecord->Rip = *ReturnAddress;
            # ContextRecord->Rsp = *StackAddress;
            if OpInfo != 0:
                ins = [      
                    'mov rax, [r9 + 0x98]  ; vm', # load stack
                    'add rax, 0x20  ; vm',
                    'mov rax, [rax]',
                    'mov [r9 + 0x98], rax  ; vm',
                ]
            else:
                ins = [      
                    'mov rax, [r9 + 0x98]  ; vm', # load stack
                    'add rax, 0x18  ; vm',
                    'mov rax, [rax]',
                    'mov [r9 + 0x98], rax  ; vm',
                ]

            # Although Rip is modified, we don't use it, as we have a new exception.
            print(f'[+] UWOP_PUSH_MACHFRAME: {UnwindOp} ~> {ins}')

        Index += 1
        ins_all.append(ins)

    return ins_all


# ----------------------------------------------------------------------------------------
def save_emulated_program(filename_serpentine, filename_shellcode):
    """Saves the emulated program into a file and patches it into serpentine binary."""    
    prog_bytes = b''
    for insn in EMULATED_PROG:
        print(insn[0])  
        prog_bytes += insn[1]

    open(filename_shellcode, 'wb').write(prog_bytes)

    # Find where the shellcode starts.
    with open(filename_serpentine, 'rb') as f:
        pos = f.read().find(b'\xF4\x46\x54\x3C\xFF\x36\x3F\x88')

    print(f'[+] Shellcode starts at: 0x{pos:X}')
    if pos != -1:
        # Patch shellcode in `filename_serpentine`.
        with open(filename_serpentine, 'r+b') as f:
            f.seek(pos)
            f.write(prog_bytes)
    else:
        raise Exception(f'Cannot find shellcode in {filename_serpentine}')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Serpentine code extractor started.')

    print('[!] WARNING: ENSURE BREAKPOINTS ARE SET PROPERLY BEFORE EXECUTING THIS.')
    print('[!] WARNING: RUN THIS SCRIPT WHEN EXECUTION IS AT THE FIRST hlt.')
    # To make this script work, you need 2  breakpoints:    
    #   1. At 0x1400010B0 (`u_handler_IMPORTANT`)
    #   2. Inside `ntdll_RtlFindCharInUnicodeString` just before handler is executed
    #      (address varies each time):
    #
    #       ntdll.dll:00007FFD66FD5170 sub_7FFD66FD5170 proc near:
    #       ntdll.dll:00007FFD66FD5170        sub     rsp, 28h
    #       ntdll.dll:00007FFD66FD5174        mov     [rsp+20h], r9 ; r9 = _DISPATCHER_CONTEXT
    #       ntdll.dll:00007FFD66FD5179        mov     rax, [r9+30h]
    #       ntdll.dll:00007FFD66FD517D        call    rax           ; BREAKPOINT HERE
    #       ntdll.dll:00007FFD66FD517F        nop
    #       ntdll.dll:00007FFD66FD5180        add     rsp, 28h
    #       ntdll.dll:00007FFD66FD5184        retn
    #
    # Set a breakpoint at 0x00007FFD66FD517D (at the call instruction,
    # so step into goes into the next chunk that ends with a `hlt`)
    #
    # If you follow instructions after 0x1400010B0, eventually you'll hit the above address.


    # WARNING: If you make changes to `save_ctx`, don't forget to update the jump offset!
    EMULATED_PROG.append(('jmp START', b'\xeb\x57')) # jump after save_ctx (0x57 bytes)
    for insn in SAVE_CTX_FUNC.splitlines():
        insn = insn.lstrip()
        if insn == '' or insn.startswith(';'):
            continue  # Ignore empty lines/comments.

        ADDTO_EMULATED_PROG(insn)

    # The address of our shellcode is unknown at runtime. We know that `lpAddress` points
    # at the beginning of our shellcode which is a `jmp START` 2-byte instruction. Right
    # after that, we have the `save_ctx` function.
    #
    # We patch `lpAddress` with +2, so it points to `save_ctx` and every time we want
    # to call `save_ctx` we simply do execute a `call [lpAddress]` ;)
    ADDTO_EMULATED_PROG('mov rax, 0x%x' % 0x14089B8E0) # =lpAddress
    ADDTO_EMULATED_PROG('add byte ptr [rax], 2')

    # NOTE: We may crash inside `printf()` due to the following instruction:
    #       movdqa  xmmword ptr [rbp+3B0h+Block], xmm0
    #
    # This is because $rsp (and hence $rbp) are not 16-byte align at the time of the
    # $xmm0 mov. To fix that, we align $rsp beforehand.
    ADDTO_EMULATED_PROG('and rsp, 0xfffffffffffffff0')

    # Start execution from the first `hlt` instruction.
    lpAddress = ida_bytes.get_qword(ida_name.get_name_ea(idaapi.BADADDR, 'lpAddress'))
    print(f'[+] lpAddress is: 0x{lpAddress:X}')
    
    curr_ea = lpAddress
    for i in range(30000):
        # Continue execution until you hit the next `hlt`.
        curr_ea = run_till_next_hlt(curr_ea)  

        #if curr_ea == 0x1400011C4:
        if (curr_ea == 0x1400011B0 or # u_print_flag (goodboy)
            curr_ea == 0x1400011F0):  # u_wrong_key  (badboy)          
                print('[+] Reached the end: 0x{curr_ea:X}')
                break

    print(f'[+] EMULATED_PROG length: {len(EMULATED_PROG)}')
    
    save_emulated_program('serpentine_deobf_new5.exe', 'sc53.bin')

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
NOTE: Run this inside IDA console window. It takes ~1:30 hr to complete.
"""
# ----------------------------------------------------------------------------------------
