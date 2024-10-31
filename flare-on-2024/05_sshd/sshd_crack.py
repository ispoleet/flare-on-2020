#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 05 - sshd
# ----------------------------------------------------------------------------------------
import struct
import socket


nonce3 = [0x11]*12

key3 = [
    0x8d, 0xec, 0x91, 0x12, 0xeb, 0x76, 0x0e, 0xda,
    0x7c, 0x7d, 0x87, 0xa4, 0x43, 0x27, 0x1c, 0x35,
    0xd9, 0xe0, 0xcb, 0x87, 0x89, 0x93, 0xb4, 0xd9,
    0x04, 0xae, 0xf9, 0x34, 0xfa, 0x21, 0x66, 0xd7,
]

ciphertext3 = [
    0xa9, 0xf6, 0x34, 0x08, 0x42, 0x2a, 0x9e, 0x1c,
    0x0c, 0x03, 0xa8, 0x08, 0x94, 0x70, 0xbb, 0x8d,
    0xaa, 0xdc, 0x6d, 0x7b, 0x24, 0xff, 0x7f, 0x24,
    0x7c, 0xda, 0x83, 0x9e, 0x92, 0xf7, 0x07, 0x1d,
]


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] sshd crack started.')

    # It's a stream cipher, so we can encrypt the encrypted file and get the plaintext.
    open('ciphertext3', 'wb').write(bytes(ciphertext3))

    filename = "/root/certificate_authority_signing_key.txt"
    filename = './ciphertext3\0'

    # Bind the server and then run the shellcode:
    #   `qiling/qltool code --os linux --arch x8664 --format hex -f shellcode_hex --rootfs=.`
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 1337))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                conn.sendall(bytes(key3))
                conn.sendall(bytes(nonce3))
                conn.sendall(struct.pack('<L', len(filename)))
                conn.sendall(filename.encode('utf-8'))

                data = conn.recv(1024)
                assert len(data) == 4
                print(f'[+] Received filesize: {struct.unpack("<L", data)[0]}')
                data = conn.recv(1024)
                print(f'[+] Received file: {data!r}')
                break

    print('[+] Program finished successfully. Bye bye :)')


# ----------------------------------------------------------------------------------------
r"""
┌─[01:15:02]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd]
└──> ./sshd_crack.py 
[+] sshd crack started.
Connected by ('127.0.0.1', 56928)
[+] Received filesize: 32
[+] Received file: b'supp1y_cha1n_sund4y@flare-on.com'
[+] Program finished successfully. Bye bye :)

┌─[01:15:10]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/05_sshd]
└──> qiling/qltool code --os linux --arch x8664 --format hex -f shellcode_hex --rootfs=.
"""
# ----------------------------------------------------------------------------------------
