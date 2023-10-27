#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 02 - It's On Fire
# ----------------------------------------------------------------------------------------
import zlib
from Crypto.Cipher import AES


# ----------------------------------------------------------------------------------------
def decrypt_png(png_name):
    """Decrypts an image using AES-CBC."""
    iv = b'abcdefghijklmnop'

    key = str(zlib.crc32(b's://fldne'))
    key = key + key
    key = key[0:16]
    key = key.encode('utf-8')

    print(f'[+] Decrypting image: {png_name}.png ...')
    print(f'[+] IV is: {iv}')
    print(f'[+] Key is: {key}')

    with open(f'{png_name}.png', 'rb') as fp:
        encrypted_image = fp.read()

    decryptor = AES.new(key=key, IV=iv, mode=AES.MODE_CBC)
    decrypted_image = decryptor.decrypt(encrypted_image)

    print(f'[+] Decrypted image contents: {repr(decrypted_image[0:32])}')
    print(f'[+] Writing decrypted image to: {png_name}.dec.png')

    with open(f'{png_name}.dec.png', 'wb') as fp:
        fp.write(decrypted_image)

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print("[+] It's On Fire crack started.")
    decrypt_png('iv')
    decrypt_png('ps')
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
"""
[+] It's On Fire crack started.
[+] Decrypting image: iv.png ...
[+] IV is: b'abcdefghijklmnop'
[+] Key is: b'4508305374508305'
[+] Decrypted image contents: b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x0f\xf3\x00\x00\x07n\x08\x06\x00\x00\x00\xa4Q\xef'
[+] Writing decrypted image to: iv.dec.png
[+] Decrypting image: ps.png ...
[+] IV is: b'abcdefghijklmnop'
[+] Key is: b'4508305374508305'
[+] Decrypted image contents: b'\xff\xd8\xff\xe1/\xfeExif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x06\x01\x12\x00\x03\x00\x00\x00\x01\x00\x01'
[+] Writing decrypted image to: ps.dec.png
[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
