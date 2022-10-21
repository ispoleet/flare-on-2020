#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2022: 10 - Nur geträumt
# ----------------------------------------------------------------------------------------
ciphertext = [
   # 0x2D ~> Flag size 
   0x0C, 0x00, 0x1D, 0x1A, 0x7F, 0x17, 0x1C, 0x4E, 0x02, 0x11,
   0x28, 0x08, 0x10, 0x48, 0x05, 0x00, 0x00, 0x1A, 0x7F, 0x2A,
   0xF6, 0x17, 0x44, 0x32, 0x0F, 0xFC, 0x1A, 0x60, 0x2C, 0x08,
   0x10, 0x1C, 0x60, 0x02, 0x19, 0x41, 0x17, 0x11, 0x5A, 0x0E,
   0x1D, 0x0E, 0x39, 0x0A, 0x04,
   # 0x27, 0x18 ~> We do not need these guys
]

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
   print('[+] Nur geträumt crack started.')

   known_plain = [ord(p) for p in '@flare-on.com']
   plain_pos = len(ciphertext) - len(known_plain)
   partial_key = [a ^ b for a, b in zip(ciphertext[plain_pos:], known_plain)]

   print("[+] Recovering partial key: "
         f"{'-'.join('%02X' % k for k in partial_key)}"
         " ~> "
         f"'{''.join(chr(k) for k in partial_key)}'")


   # Try that key to decrypt other parts of the ciphertext:
   for keypos in range(plain_pos):
      plain = [a ^ b for a, b in zip(ciphertext[keypos:], partial_key)]

      if any([c < 0x20 or c > 0x7e for c in plain]):         
         continue  # Ignore plaintexts with non ASCII characters.

      print(f"[+] Plaintext at index {keypos:02d}: "
            f"{'-'.join('%02X' % k for k in plain)}"
            " ~> "
            f"{repr(''.join(chr(k) for k in plain))}")

   # We found "_singe_ich_ei" at index 4, so the flag so far is:
   # ****_singe_ich_ei***************@flare-on.com   
   key_guess = 'Hast du etwas Zeit fur mich'
   key = [ord(k) for k in key_guess]
   plain = [a ^ b for a, b in zip(ciphertext, key*2)]
   print(f"[+] Plaintext using key '{key_guess}': "
         f"{repr(''.join(chr(p) for p in plain))}")

   # Okay we got "Dann_singe_ich_ein_L\x83ed_f\x9fr(M{d<\x04w9$cf;}=T\\cp"
   # Key length incorrect (key has more characters).
   # Go back and use plaintext found to find more characters from the key:
   plain_guess = 'Dann_singe_ich_ein_Lied_fur_dich'
   known_plain = [ord(p) for p in plain_guess]
   key = [a ^ b for a, b in zip(ciphertext, known_plain)]
   print(f"[+] Key using plaintext '{plain_guess}': "
         f"{repr(''.join(chr(k) for k in key))}")

   # Now we got "Hast du etwas Zeit f\x9fr mi\x89h?Hast".
   # "Hast" is repeated, so the key is: "Hast du etwas Zeit f\x9fr mi\x89h?"
   final_key = "Hast du etwas Zeit f\x9fr mi\x89h?"
   print(f"[+] Final Key found: {final_key}")

   plain = [a ^ ord(b) for a, b in zip(ciphertext, final_key*2)]
   print(f"[+] Plaintext: {repr(''.join(chr(p) for p in plain))}")


   print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
[+] Nur geträumt crack started.
[+] Recovering partial key: 20-64-75-20-65-74-77-61-73-20-5A-65-69 ~> ' du etwas Zei'
[+] Plaintext at index 04: 5F-73-69-6E-67-65-5F-69-63-68-5F-65-69 ~> '_singe_ich_ei'
[+] Plaintext at index 29: 28-74-69-40-67-6D-36-76-62-7A-54-78-67 ~> '(ti@gm6vbzTxg'
[+] Plaintext using key 'Hast du etwas Zeit fur mich': 'Dann_singe_ich_ein_L\x83ed_f\x9fr(M{d<\x04w9$cf;}=T\\cp'
[+] Key using plaintext 'Dann_singe_ich_ein_Lied_fur_dich': 'Hast du etwas Zeit f\x9fr mi\x89h?Hast'
[+] Final Key found: Hast du etwas Zeit f h?
[+] Plaintext: 'Dann_singe_ich_ein_Lied_fur_dich@flare-on.com'
[+] Program finished! Bye bye :)
'''
# ----------------------------------------------------------------------------------------