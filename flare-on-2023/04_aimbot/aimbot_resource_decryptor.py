#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 04 - Aim Bot
# ----------------------------------------------------------------------------------------
from Crypto.Cipher import AES
 
# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Aimbot resource decryptor started.')
 
    for res_name, decr_file in {
        'res1.bin': 'miner.exe',
        'res2.bin': 'config.json',
        'res3.bin': 'aimbot.dll'
    }.items():
        ciphertext = open(res_name, 'rb').read()
        decryptor = AES.new(key=b'yummyvitamincjoy', mode=AES.MODE_ECB)
        decrypted_data = decryptor.decrypt(ciphertext)

        header = b'the decryption of this blob was successful'
        if not decrypted_data.startswith(header):
            print(f'[!] Decryption error for {res_name} :(')
        else:
            print(f'[+] File {decr_file} decrypted successfully :D')
            open(decr_file, 'wb').write(decrypted_data[len(header):])

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/04_aimbot$ ./aimbot_resource_decryptor.py 
[+] Aimbot resource decryptor started.
[+] File miner.exe decrypted successfully :D
[+] File config.json decrypted successfully :D
[+] File aimbot.dll decrypted successfully :D
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------
