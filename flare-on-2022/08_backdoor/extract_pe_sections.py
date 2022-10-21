#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2022: 8 - backdoor
# ----------------------------------------------------------------------------------------
import os
import re
import pefile


# ----------------------------------------------------------------------------------------
if __name__ == '__main__':
    print(f'[+] Extracting PE sections from `FlareOn.Backdoor.exe` into `sections/` ...')

    pe = pefile.PE("FlareOn.Backdoor.exe")
    
    try:
        os.mkdir("pe_sections")        
    except FileExistsError:
        pass

    # Scan every section from Sections Header.
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')

        # We are interested in sections that are named with 8 hex digits.
        if not re.match(r"[0-9a-f]{8}", name):
            continue
        
        print(f"[+] Section Found: '{name}' of size {section.Misc_VirtualSize:3X}h bytes"
              f"located at {section.VirtualAddress:X}h")

        # Extract section data.
        section_data = pe.get_data(section.VirtualAddress, section.Misc_VirtualSize)        
        with open(os.path.join("pe_sections", name), 'wb') as fp:
            fp.write(section_data)

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
[+] Extracting PE sections from `FlareOn.Backdoor.exe` into `sections/` ...
[+] Section Found: '5aeb2b97' of size AE475Bh byteslocated at 22000h
[+] Section Found: '8de5507b' of size  67h byteslocated at B08000h
[+] Section Found: '0651f80b' of size  2Bh byteslocated at B0A000h
[+] Section Found: '7135726c' of size  55h byteslocated at B0C000h
[+] Section Found: '77c01ab2' of size  19h byteslocated at B0E000h
[+] Section Found: '4f0f2ca3' of size  49h byteslocated at B10000h
[+] Section Found: '30b905e5' of size  5Bh byteslocated at B12000h
[+] Section Found: 'f8a2493f' of size  4Ah byteslocated at B14000h
[+] Section Found: '846fcbb2' of size  16h byteslocated at B16000h
[+] Section Found: '5ca8a517' of size  66h byteslocated at B18000h
[+] Section Found: '80761762' of size  3Ch byteslocated at B1A000h
[+] Section Found: '305a002f' of size  30h byteslocated at B1C000h
[+] Section Found: '1b8e2238' of size  4Ch byteslocated at B1E000h
[+] Section Found: '310d4de0' of size  33h byteslocated at B20000h
[+] Section Found: '31d82380' of size  55h byteslocated at B22000h
[+] Section Found: 'db08afea' of size  42h byteslocated at B24000h
[+] Section Found: '977deaed' of size   Eh byteslocated at B26000h
[+] Section Found: '96c576e4' of size 15Ah byteslocated at B28000h
[+] Section Found: '69991a3e' of size  12h byteslocated at B2A000h
[+] Section Found: '94957fff' of size  63h byteslocated at B2C000h
[+] Section Found: 'ffc58f78' of size  F8h byteslocated at B2E000h
[+] Section Found: 'ee6d9a21' of size  8Dh byteslocated at B30000h
[+] Section Found: 'b1c8119c' of size  13h byteslocated at B32000h
[+] Section Found: '30752c49' of size  20h byteslocated at B34000h
[+] Section Found: '74fbaf68' of size  84h byteslocated at B36000h
[+] Section Found: '326aa956' of size   Bh byteslocated at B38000h
[+] Section Found: '719ee568' of size  80h byteslocated at B3A000h
[+] Section Found: 'becb82d3' of size   Bh byteslocated at B3C000h
[+] Section Found: 'a4691056' of size  5Fh byteslocated at B3E000h
[+] Section Found: 'b3650258' of size 112h byteslocated at B40000h
[+] Section Found: '689d7525' of size  37h byteslocated at B42000h
[+] Section Found: 'f9a758d3' of size  4Eh byteslocated at B44000h
[+] Section Found: '1aa22d63' of size  1Fh byteslocated at B46000h
[+] Section Found: 'd787bb6b' of size  9Bh byteslocated at B48000h
[+] Section Found: '33d51cd2' of size  57h byteslocated at B4A000h
[+] Section Found: '794ac846' of size  1Dh byteslocated at B4C000h
[+] Section Found: '7cddb7c1' of size  17h byteslocated at B4E000h
[+] Section Found: '27086010' of size  AEh byteslocated at B50000h
[+] Section Found: '344f2938' of size  ACh byteslocated at B52000h
[+] Section Found: '89b957e3' of size  F9h byteslocated at B54000h
[+] Section Found: 'cc80b00c' of size  54h byteslocated at B56000h
[+] Section Found: '4a0fb136' of size  59h byteslocated at B58000h
[+] Section Found: '85b3a7dd' of size 126h byteslocated at B5A000h
[+] Section Found: '892fac73' of size  29h byteslocated at B5C000h
[+] Section Found: 'ede0bad0' of size  1Ah byteslocated at B5E000h
[+] Section Found: '3460378b' of size  5Ch byteslocated at B60000h
[+] Section Found: '81e1a476' of size  34h byteslocated at B62000h
[+] Section Found: '710b11bc' of size  3Dh byteslocated at B64000h
[+] Section Found: 'f965be73' of size  33h byteslocated at B66000h
[+] Section Found: '0686a47b' of size  F0h byteslocated at B68000h
[+] Section Found: '4ea4cf8d' of size 27Fh byteslocated at B6A000h
[+] Section Found: '699fdcf2' of size  81h byteslocated at B6C000h
[+] Section Found: 'a537f738' of size  37h byteslocated at B6E000h
[+] Section Found: '9181748d' of size  49h byteslocated at B70000h
[+] Section Found: '2fad6d86' of size   Ch byteslocated at B72000h
[+] Section Found: 'c4493ff5' of size  A6h byteslocated at B74000h
[+] Section Found: '520c2390' of size  CCh byteslocated at B76000h
[+] Section Found: '8d3a199f' of size  71h byteslocated at B78000h
[+] Section Found: 'e530c010' of size  A1h byteslocated at B7A000h
[+] Section Found: '7c5ccd91' of size  16h byteslocated at B7C000h
[+] Section Found: '82b8dfa1' of size  FAh byteslocated at B7E000h
[+] Section Found: '8a966e19' of size DDCh byteslocated at B80000h
[+] Section Found: '538fcc69' of size  2Fh byteslocated at B82000h
[+] Section Found: '0e5cf5d9' of size  3Ch byteslocated at B84000h
[+] Section Found: 'edd1976b' of size  BFh byteslocated at B86000h
[+] Section Found: '4951e547' of size  67h byteslocated at B88000h
[+] Section Found: '11d539d6' of size  66h byteslocated at B8A000h
[+] Section Found: '37875be2' of size 20Ch byteslocated at B8C000h
[+] Section Found: 'c61192c7' of size  21h byteslocated at B8E000h
[+] Section Found: 'e712183a' of size  11h byteslocated at B90000h
[+] Program finished! Bye bye :)
'''
# ----------------------------------------------------------------------------------------
