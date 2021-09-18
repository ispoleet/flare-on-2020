#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 8 - Aardvark
# --------------------------------------------------------------------------------------------------
import os


# --------------------------------------------------------------------------------------------------
def crack_flag(cpufreq=True, proc=True):
    flag = [0x4A, 0x82, 0x43, 0xAB, 0x95, 0xED, 0x8F, 0x7E,
            0x9C, 0xBC, 0xAD, 0x84, 0x17, 0x91, 0x06, 0x15]

    for i in xrange(len(flag)):
        flag[i] ^= ord('O')
    i += 1

    if cpufreq:
        for cpufreq in ['cpufreq_powersave', 'cpufreq_userspace', 'cpufreq_conservative']:
            for ch in cpufreq:
                flag[i % 16] ^= ord(ch)
                i += 1        

    # XOR with filesystem (start from the first 'f')
    filesystem = 'wslfs'
    if filesystem.find('f') != -1:
     for ch in filesystem[filesystem.find('f'):]:
            flag[i % 16] ^= ord(ch)
            i += 1
    
    # Kernel version (/proc/version_signature)
    version_signature = 'Microsoft 4.4.0-18362.1049-Microsoft 4.4.35'
    for ch in version_signature[:9]:
        flag[i % 16] ^= ord(ch)
        i += 1
    
    # vDSO check: Get the 6 MSB of `p_vaddr` for each program header (elf64_hdr->e_phoff).
    #     0xffffffffff7003c8
    N = [0x70, 0xff, 0xff, 0xff, 0xff, 0xff]
    for x in range(4):
        for n in N:
            flag[i % 16] ^= n
            i += 1

    # Get the 2 MSB from each inode for each regular file under /proc.
    if proc:
        for ff in os.listdir('/proc'):
            if ff.isdigit():
                # Skip directories from processes.
                continue

            stat = os.lstat(os.path.join('/proc', ff))

            if stat.st_mode & 0xD000 == 0x8000:     # S_IFREG
                flag[i % 16] ^= (stat.st_ino >> 16) & 0xFF
                i += 1
                flag[i % 16] ^= (stat.st_ino >> 24) & 0xFF
                i += 1

                print ' '.join('%02X' % x for x in flag), ''.join(chr(x) for x in flag)

    # Final check: All bytes from the flag as non-negative.

    if sum(1 for f in flag if f <= 0x7F) == 16:
        return flag
    else: return 'WRONG!'


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Flare-On 2020: 8 - Aardvark'
    
    flag = crack_flag(cpufreq=False, proc=False)

    print ' '.join('%02X' % x for x in flag), ''.join(chr(x) for x in flag)

    print '[+] Program finished! Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare_on/8_Aardvark$ ./ttt2_crack.py 
[+] Flare-On 2020: 8 - Aardvark
63 31 41 72 46 2F 50 32 43 6A 69 44 58 51 49 5A c1ArF/P2CjiDXQIZ
[+] Program finished! Bye bye :)
'''
# --------------------------------------------------------------------------------------------------
