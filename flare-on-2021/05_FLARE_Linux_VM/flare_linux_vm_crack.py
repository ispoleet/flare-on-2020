#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2021: 5 - FLARE Linux VM
# ----------------------------------------------------------------------------------------
import os
import hashlib
import base64
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES


ingredients = {
    'U': ['udon_noddles.txt',   'ugali.txt',        'unagi.txt'],
    'S': ['sausages.txt',       'spaghetti.txt',    'strawberries.txt'],
    'R': ['raisins.txt',        'rasberries.txt',   'reeses.txt'],
    'B': ['backberries.txt',    'banana_chips.txt', 'blue_cheese.txt'],
    'I': ['ice_cream.txt',      'iced_coffee.txt',  'instant_noodles.txt'],
    'N': ['nachos.txt',         'natillas.txt',     'nutella.txt'],
    'D': ['daiquiris.txt',      'donuts.txt',       'dumplings.txt'],
    'O': ['oats.txt',           'omelettes.txt',    'oranges.txt'],
    'T': ['tacos.txt',          'tiramisu.txt',     'tomatoes.txt'],    
}


# ----------------------------------------------------------------------------------------
def crack_U_ingrs(ingrs):
    # U ingredients are already decrypted. Just strip and print them.
    for ingr, data in ingrs.items():
        plain = data.decode('utf-8').rstrip('\0\n')

        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
def crack_S_ingrs(ingrs):
    # S ingredients are right rotated (ROR) by 7 bits.
    for ingr, data in ingrs.items():   
        for k in range(1,8): 
            k = 7 # 7: The correct rotation
            plain = [((d >> k) | (d << (8-k))) & 0xFF for d in data]
            break

        plain = ''.join('%c' % x for x in plain).rstrip('\0\n')
        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
def crack_R_ingrs(ingrs):
    # R ingredients are base64 encoded (too obvious).
    for ingr, data in ingrs.items():
        plain = base64.b64decode(data).decode('utf-8').rstrip('\0\n')
        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
def crack_B_ingrs(ingrs):
    # B ingredients are XORed with a `Reese's` key.
    for ingr, data in ingrs.items():
        data = data.decode('utf-8').rstrip('\0\n')  # stip NULL bytes
        plain = [ord(d) ^ ord("Reese's"[i % 7]) for i, d in enumerate(data)]
        plain = ''.join('%c' % x for x in plain).rstrip('\0\n')
        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
def crack_I_ingrs(ingrs):
    # I ingredients are encrypted with a custom encryption:
    #       ENCODED_BYTE + 27 + NUMBER1 * NUMBER2 - NUMBER3
    for ingr, data in ingrs.items():
        data = data.decode('utf-8').rstrip('\0\n')  # stip NULL bytes
        plain = [(ord(d) + 27 + 2 * 3 - 37 + 256) % 256 for d in data]
        plain = ''.join('%c' % x for x in plain).rstrip('\0\n')
        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
def crack_N_ingrs(ingrs):
    # N ingredients are encrypted RC4. Key:493513.
    for ingr, data in ingrs.items():
        cipher = ARC4.new("493513".encode('utf-8'))        
        plain = cipher.decrypt(bytes(data))            
        plain = ''.join('%c' % x for x in plain)
        print(f"[+] {ingr:>24} ~> {plain}")  # It prints beyond decrypted data, but we dont care.


# ----------------------------------------------------------------------------------------
def crack_D_ingrs(ingrs):
    # D ingredients are encrypted using Bifid Cipher. See README.
    pass


# ----------------------------------------------------------------------------------------
def crack_O_ingrs(ingrs):
    # O ingredients are encrypted using Vigenere Cipher. See README.
    pass


# ----------------------------------------------------------------------------------------
def crack_T_ingrs(ingrs):
    # T ingredients are encrypted AES-CBC.
    for ingr, data in ingrs.items():
        key = ("Sheep should sleep in a shed" + "15.2").encode('utf-8')

        data = bytes.fromhex(data.decode('utf-8').rstrip('\0\n'))
        crypto = AES.new(key=key, IV=('PIZZA' + '0'*11).encode('utf-8'),  mode=AES.MODE_CBC)

        plain = crypto.decrypt(data)
        plain = ''.join('%c' % x for x in plain).rstrip('\0\n')

        print(f"[+] {ingr:>24} ~> {plain}")


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] FLARE Linux VM crack started.')
     
    for let, ingrs in ingredients.items():
        print('[+] Decrypting %c ingredients: %s' % (let, ', '.join(ingrs)))

        {   'U': crack_U_ingrs,
            'S': crack_S_ingrs,   
            'R': crack_R_ingrs,   
            'B': crack_B_ingrs,
            'I': crack_I_ingrs,
            'N': crack_N_ingrs,
            'D': crack_D_ingrs,
            'O': crack_O_ingrs,
            'T': crack_T_ingrs,
        }[let]({ingr:open(f'Documents_decrypted/{ingr}', 'rb').read() for ingr in ingrs})

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/flare-on-2021/05_FLARE_Linux_VM$ ./flare_linux_vm_crack.py 
[+] FLARE Linux VM crack started.
[+] Decrypting U ingredients: udon_noddles.txt, ugali.txt, unagi.txt
[+]         udon_noddles.txt ~> "ugali", "unagi" and "udon noodles" are delicious. What a coincidence that all of them start by "u"!
[+]                ugali.txt ~> Ugali with Sausages or Spaghetti is tasty. It doesn’t matter if you rotate it left or right, it is still tasty! You should try to come up with a great recipe using CyberChef.
[+]                unagi.txt ~> The 1st byte of the password is 0x45
[+] Decrypting S ingredients: sausages.txt, spaghetti.txt, strawberries.txt
[+]             sausages.txt ~> The 2st byte of the password is 0x34
[+]            spaghetti.txt ~> In the FLARE language "spaghetti" is "c3BhZ2hldHRp".
[+]         strawberries.txt ~> In the FLARE team we like to speak in code. You should learn our language, otherwise you want be able to speak with us when you escape (if you manage to escape!). For example, instead of "strawberries" we say "c3RyYXdiZXJyaWVz".
[+] Decrypting R ingredients: raisins.txt, rasberries.txt, reeses.txt
[+]              raisins.txt ~> The 3rd byte of the password is.. it is a joke, we don't like raisins!
[+]           rasberries.txt ~> The 3rd byte of the password is: 0x51
[+]               reeses.txt ~> We LOVE "Reese's", they are great for everything! They are amazing in ice-cream and they even work as a key for XOR encoding.
[+] Decrypting B ingredients: backberries.txt, banana_chips.txt, blue_cheese.txt
[+]          backberries.txt ~> If you are not good in maths, the only thing that can save you is to be a bash expert. Otherwise you will be locked here forever HA HA HA!
[+]         banana_chips.txt ~> Are you good at maths? We love maths at FLARE! We use this formula a lot to decode bytes: "ENCODED_BYTE + 27 + NUMBER1 * NUMBER2 - NUMBER3"
[+]          blue_cheese.txt ~> The 4th byte of the password is: 0x35
[+] Decrypting I ingredients: ice_cream.txt, iced_coffee.txt, instant_noodles.txt
[+]            ice_cream.txt ~> If this challenge is too difficult and you want to give up or just in case you got hungry, what about baking some muffins? Try this recipe:
                                0 - Cinnamon
                                1 - Butter 150gr
                                2 - Lemon 1/2
                                3 - Eggs 3
                                4 - Sugar 150gr
                                5 - Flour 250gr
                                6 - Milk 30gr
                                7 - Icing sugar 10gr
                                8 - Apple 100gr
                                9 - Raspberries 100gr

                                Mix 0 to 9 and bake for 30 minutes at 180°C.
[+]          iced_coffee.txt ~> The only problem with RC4 is that you need a key. The FLARE team normally uses this number: "SREFBE" (as an UTF-8 string). If you have no idea what that means, you should give up and bake some muffins.
[+]      instant_noodles.txt ~> The 5th byte of the password is: 0xMS
[+] Decrypting N ingredients: nachos.txt, natillas.txt, nutella.txt
[+]               nachos.txt ~> In the FLARE team we really like Felix Delastelle algorithms, specially the one which combines the Polybius square with transposition, and uses fractionation to achieve diffusion.
[+]             natillas.txt ~> Do you know natillas? In Spain, this term refers to a custard dish made with milk and KEYWORD, similar to other European creams as crème anglaise. In Colombia, the delicacy does not include KEYWORD, and is called natilla.
[+]              nutella.txt ~> The 6th byte of the password is: 0x36
[+] Decrypting D ingredients: daiquiris.txt, donuts.txt, dumplings.txt
[+] Decrypting O ingredients: oats.txt, omelettes.txt, oranges.txt
[+] Decrypting T ingredients: tacos.txt, tiramisu.txt, tomatoes.txt
[+]                tacos.txt ~> Woow! It seems you are very very close to get the flag! Be careful when converting decimal and hexadecimal values to ASCII and hurry up before we run out of tacos!
[+]             tiramisu.txt ~> The 9th byte of the password is the atomic number of the element moscovium
                                The 10th byte of the password is the bell number preceding 203
                                The 12th byte of the password is the largest known number to be the sum of two primes in exactly two different ways
                                The 14th (and last byte) of the password is the sum of the number of participants from Spain, Singapore and Indonesia that finished the FLARE-ON 7, FLARE-ON 6 or FLARE-ON 5
[+]             tomatoes.txt ~> It seems you are close to escape... We are preparing the tomatoes to throw at you when you open the door! It is only a joke...
                                The 11th byte of the password is the number of unique words in /etc/Quijote.txt
                                The 13th byte of the password is revealed by the FLARE alias
'''
# ----------------------------------------------------------------------------------------
