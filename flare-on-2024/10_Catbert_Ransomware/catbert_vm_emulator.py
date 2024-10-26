#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 10 - Catbert Ransomware
# ----------------------------------------------------------------------------------------
import struct

_GREEN = '\x1b[92m'
_RESET = '\x1b[39m'


# ----------------------------------------------------------------------------------------
# Helper lambdas for rotation.
rol8 = lambda a, b: ((a << b) | (a >> (8 - b))) & 0xFF
ror8 = lambda a, b: ((a >> b) | (a << (8 - b))) & 0xFF

rol16 = lambda a, b: ((a << b) | (a >> (16 - b))) & 0xFFFF
ror16 = lambda a, b: ((a >> b) | (a << (16 - b))) & 0xFFFF

rol32 = lambda a, b: ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF
ror32 = lambda a, b: ((a >> b) | (a << (32 - b))) & 0xFFFFFFFF


# ----------------------------------------------------------------------------------------
def parse_img(filename):
    """Extracts the encrypted part of an image."""
    data = open(filename, 'rb').read()
    assert data[0:4] == b'C4TB'

    print(f'[+] Loading image `{filename}` of {len(data)} bytes')

    encr_img_len = struct.unpack('<L', data[4:8])[0]
    print(f'[+] Encrypted image (0x{encr_img_len:X} bytes):')

    encr_img = bytearray(data[0x10:0x10 + encr_img_len])
    print('[+]  ', ' '.join(f'{b:02X}' for i, b in enumerate(encr_img[:16])),
          ' ... ', ' '.join(f'{b:02X}' for i, b in enumerate(encr_img[-16:])))

    # VM program is at the end of the image.
    vm_prog_off = struct.unpack('<L', data[8:12])[0]
    vm_prog_len = struct.unpack('<L', data[12:16])[0]

    print(f'[+] VM program at 0x{vm_prog_off:X}, of 0x{vm_prog_len} bytes:')

    vm_prog = bytearray(data[vm_prog_off:vm_prog_off + vm_prog_len])
    print('[+]  ', ' '.join(f'{b:02X}' for i, b in enumerate(vm_prog[:16])),
          ' ... ', ' '.join(f'{b:02X}' for i, b in enumerate(vm_prog[-16:])))

    return encr_img, vm_prog

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Catbert Ransomware crack started.')

#    _, vm_prog = parse_img('disk_files/catmeme1.jpg.c4tb')
#    _, vm_prog = parse_img('disk_files/catmeme2.jpg.c4tb')
    _, vm_prog = parse_img('disk_files/catmeme3.jpg.c4tb')

    # Set a decryption key to run the VM program
    key = b'ABCDEFGHIJKLMNOP'
    key = b'DaCubicleLife101'   # Key for catmeme1.
    key = b'G3tDaJ0bD0neM4te'   # Key for catmeme2.
    key = b'VerYDumBpassword'   # Key for catmeme3.
    
    # Patch key into VM program.
    for i in range(8):
        vm_prog[5 + 7*i], vm_prog[4 + 7*i] = key[2*i], key[2*i + 1]

    print('[+] ==================================================')
    print('[+] Emulation stared.')

    lineno = 1
    
    # This is an "increment-after/decrement-before" stack:
    #   sp points to the free element, not at the top of the stack.
    pc = 0
    sp = 0  # sp is for decoration, we just do append/pop.
    VM_stack = []
    heap = [0]*256
    vmret = False

    while vmret == False:
        op = vm_prog[pc] # opcode
        pc += 1
        important = False
        # print(f'op: {op:x} | (pc:{pc:x})')

        if op == 0:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 1:
            # Push 2-byte imm to stack (stack is 8 byte aligned).
            pc += 2
            imm = struct.unpack('>H', vm_prog[pc-2:pc])[0]
            sp += 1  # (8 bytes in VM)
            VM_stack.append(imm)
            asm = f'PUSH 0x{imm:04X}'

        elif op == 2:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 3:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 4:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 5:
            # Pop register ID from stack, load register and put its contents back to stack.
            sp -= 1
            addr = VM_stack.pop()
            VM_stack.append(heap[addr])
            asm = f'LDR         ; #{addr:X}h ~> 0x{heap[addr]:04X}'

        elif op == 6:
            # Pop value from stack, then pop address from stack, then write value to address ~> STR.
            sp -= 1
            val = VM_stack.pop()
            sp -= 1
            addr = VM_stack.pop()
            heap[addr] = val
            asm = f'STR         ; [0x{addr:04X}] <~ 0x{val:04X}'

        elif op == 7:
            raise Exception(f'Opcode not implemented: 0x{op:x}')

        elif op == 9:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(a + b)
            asm = f'ADD'

        elif op == 0xa:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 0xb:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 0xc:
            raise Exception(f'Opcode not implemented: 0x{op:x}')
        elif op == 0xd:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(a * b)
            asm = f'MUL'

        elif op == 0xe:                      
            pc += 2
            off = struct.unpack('>H', vm_prog[pc-2:pc])[0]
            asm = f'JMP 0x{off:X}'
            print(f'~> CHANGING PC TO: 0x{off:X}')
            pc = off  

        elif op == 0xf:
            raise Exception(f'Opcode not implemented: 0x{op:x}')

        elif op == 0x10:
            # Conditional jump based on the result on top of stack.
            pc += 2
            off = struct.unpack('>H', vm_prog[pc-2:pc])[0]
            asm = f'JNZ 0x{off:X}   ; {VM_stack[-1] == 0}'
            resl = VM_stack.pop()
            if resl == 0:
                print(f'~> CHANGING PC TO: 0x{off:X}')
                pc = off
                # TODO: update pc after print of asm

        elif op == 0x11:
            # Compare the 2 top elements and store result (1 = equal, 0 = not equal)
            # back to the stack.
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(a == b)
            asm = f'CMP EQ      ; 0x{a:X} == 0x{b:X} ?'

            # TODO(ispo): After we change PC in a JMP/JNZ, the new PC is shown when
            # instruction is printed:
            #
            #    0390 | 01B4: (#11) CMP EQ      ; 0x9 == 0x2 ?               | S:[0h]
            #    ~> CHANGING PC TO: 0x1C3
            #    0391 | 01C3: (#10) JNZ 0x1C3   ; True                       | S:[]
            #
            # PC for JNZ is not 0x1C3 but 0x1B5

        elif op == 0x12:
            # compare 2 top elements and store result (1 = a < b, 0 = otherwise
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(b < a)
            asm = f'CMP B      ; 0x{b:X} < 0x{a:X} ?'

        elif op == 0x13:
            raise Exception(f'Opcode not implemented: 0x{op:x}')

        elif op == 0x14:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(b > a)
            asm = f'CMP NBE      ; 0x{b:X} > 0x{a:X} ?'

        elif op == 0x15:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(b >= a)
            asm = f'CMP NB      ; 0x{b:X} >= 0x{a:X} ?'            
        
        elif op == 0x18:
            asm = f'VMRET'
            vmret = True
        
        elif op == 0x19:
            a = VM_stack.pop()
            asm = f'DECRYPTION_RESULT_#1 = {a}'

        elif op == 0x1A:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(a ^ b)
            asm = f'XOR'
            important = True

        elif op == 0x1B:
            a = VM_stack.pop()
            b = VM_stack.pop() # VM_stack[-1] |= a
            VM_stack.append(a | b)
            asm = f'OR'

        elif op == 0x1C:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(a & b)
            asm = f'AND'

        elif op == 0x1D:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append((b % a) & 0xFFFFFFFF)
            asm = f'MOD'

        elif op == 0x1E:
            # Pop shift amount from stack, then shift left top of stack by that.
            sp -= 1
            a = VM_stack.pop()
            asm = f'SHL         ; 0x{VM_stack[-1]:X} << 0x{a:X}'
            VM_stack[-1] <<= (a % 64)

        elif op == 0x1F:
            # Pop shift amount from stack, then shift right top of stack by that.
            sp -= 1
            a = VM_stack.pop()
            asm = f'SHR         ; 0x{VM_stack[-1]:X} >> 0x{a:X}'      
            VM_stack[-1] >>= (a % 64)

        elif op == 0x20:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(rol32(b, a))
            asm = f'ROL32         ; rol32(0x{b:X}, 0x{a:X})'
            important = True

        elif op == 0x21:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(ror32(b, a))
            asm = f'ROR32         ; ror32(0x{b:X}, 0x{a:X})'
            important = True

        elif op == 0x24:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(rol8(b, a))
            asm = f'ROL8         ; rol8(0x{b:X}, 0x{a:X})'
            important = True

        elif op == 0x25:
            a = VM_stack.pop()
            b = VM_stack.pop()
            VM_stack.append(ror8(b, a))
            asm = f'ROR8         ; ror8(0x{b:X}, 0x{a:X})'
            important = True
        else:
            raise Exception(f'Opcode not implemented: 0x{op:x}')


        stack = ', '.join(f'{VM_stack[i]:X}h' for i in range(len(VM_stack)))
        line = f'{lineno:04} | {pc:04X}: (#{op:02x}) {asm:40s} | S:[{stack}]'

        if important:  # Highlight "important" instructions.
            line = f'{_GREEN}{line}{_RESET}'

        print(line)
        lineno += 1

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
time ./catbert_vm_emulator.py 
[+] Catbert Ransomware crack started.
[+] Loading image `disk_files/catmeme3.jpg.c4tb` of 97946 bytes
[+] Encrypted image (0x17AB3 bytes):
[+]   F4 0C 72 0B AC 40 16 2C A8 F0 61 A8 E5 6F D2 F8  ...  58 7A 9F 3F 61 E3 C5 41 38 F1 37 59 62 3B 6A C4
[+] VM program at 0x17AD0, of 0x970 bytes:
[+]   01 00 00 01 BB AA 06 01 00 01 01 DD CC 06 01 00  ...  10 03 C4 01 00 20 01 00 01 06 01 00 20 05 19 18
[+] ==================================================
[+] Emulation stared.
0001 | 0003: (#01) PUSH 0x0000                              | S:[0h]
0002 | 0006: (#01) PUSH 0x6556                              | S:[0h, 6556h]
0003 | 0007: (#06) STR         ; [0x0000] <~ 0x6556         | S:[]
0004 | 000A: (#01) PUSH 0x0001                              | S:[1h]
0005 | 000D: (#01) PUSH 0x5972                              | S:[1h, 5972h]
0006 | 000E: (#06) STR         ; [0x0001] <~ 0x5972         | S:[]
0007 | 0011: (#01) PUSH 0x0002                              | S:[2h]
0008 | 0014: (#01) PUSH 0x7544                              | S:[2h, 7544h]
0009 | 0015: (#06) STR         ; [0x0002] <~ 0x7544         | S:[]
0010 | 0018: (#01) PUSH 0x0003                              | S:[3h]
0011 | 001B: (#01) PUSH 0x426D                              | S:[3h, 426Dh]
0012 | 001C: (#06) STR         ; [0x0003] <~ 0x426D         | S:[]

.....

1859 | 03C4: (#06) STR         ; [0x0020] <~ 0x0001         | S:[]
1860 | 03C7: (#01) PUSH 0x0020                              | S:[20h]
1861 | 03C8: (#05) LDR         ; #20h ~> 0x0001             | S:[1h]
1862 | 03C9: (#19) DECRYPTION_RESULT_#1 = 1                 | S:[]
1863 | 03CA: (#18) VMRET                                    | S:[]
[+] Program finished successfully. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
