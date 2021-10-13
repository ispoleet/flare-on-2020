#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 5 - FLARE Linux VM
# ----------------------------------------------------------------------------------------
import os

# ----------------------------------------------------------------------------------------
def decrypt(filepath):

    with open(filepath, 'rb') as fp: #'Documents/backberries.txt.broken', 'rb') as fp:
         bufin = fp.read()

    key = b"A secret is no longer a secret once someone knows it"

    S = [i for i in range(256)]
  
    j = 0
    for i in range(256):
        j = (S[i] + j + key[i % 52]) % 256;
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    v7 = 0
    bufout = []

    for k in range(1024):
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        S[i], S[j] = S[j], S[i]
        K = S[(S[j] + S[i]) % 256]
        bufout.append(bufin[k] ^ K ^ v7)  # almost like RC4
        v7 = K
    
    return bytes(bufout)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] FLARE Linux VM decryptor started.')
     
    os.mkdir('Documents_decrypted')
    for subdir, _, files in os.walk('Documents'):
        for f in sorted(files):
            print('[+] Decrypting:', os.path.join(subdir, f))
            bufout = decrypt(os.path.join(subdir, f))

            open(os.path.join('Documents_decrypted', f.replace('.broken', '')), 'wb').write(bufout)

 
# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-2021/05_FLARE_Linux_VM$ ./flare_linux_vm_decryptor.py 
[+] FLARE Linux VM decryptor started.
[+] Decrypting: Documents/backberries.txt.broken
[+] Decrypting: Documents/banana_chips.txt.broken
[+] Decrypting: Documents/blue_cheese.txt.broken
[+] Decrypting: Documents/daiquiris.txt.broken
[+] Decrypting: Documents/donuts.txt.broken
[+] Decrypting: Documents/dumplings.txt.broken
[+] Decrypting: Documents/ice_cream.txt.broken
[+] Decrypting: Documents/iced_coffee.txt.broken
[+] Decrypting: Documents/instant_noodles.txt.broken
[+] Decrypting: Documents/nachos.txt.broken
[+] Decrypting: Documents/natillas.txt.broken
[+] Decrypting: Documents/nutella.txt.broken
[+] Decrypting: Documents/oats.txt.broken
[+] Decrypting: Documents/omelettes.txt.broken
[+] Decrypting: Documents/oranges.txt.broken
[+] Decrypting: Documents/raisins.txt.broken
[+] Decrypting: Documents/rasberries.txt.broken
[+] Decrypting: Documents/reeses.txt.broken
[+] Decrypting: Documents/sausages.txt.broken
[+] Decrypting: Documents/shopping_list.txt.broken
[+] Decrypting: Documents/spaghetti.txt.broken
[+] Decrypting: Documents/strawberries.txt.broken
[+] Decrypting: Documents/tacos.txt.broken
[+] Decrypting: Documents/tiramisu.txt.broken
[+] Decrypting: Documents/tomatoes.txt.broken
[+] Decrypting: Documents/udon_noddles.txt.broken
[+] Decrypting: Documents/ugali.txt.broken
[+] Decrypting: Documents/unagi.txt.broken

'''
# ----------------------------------------------------------------------------------------
