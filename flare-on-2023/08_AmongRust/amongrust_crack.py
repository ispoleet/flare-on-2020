#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2023: 8 - AmongRust
# ----------------------------------------------------------------------------------------
import socket


key = [
    0x65, 0x74, 0x21, 0x2c, 0x9b, 0x4d, 0x93, 0x34,
    0xd8, 0x93, 0xbe, 0xc2, 0x47, 0x7c, 0xb8, 0x6a,
    0x70, 0x98, 0x3b, 0x3c, 0x33, 0x95, 0x2d, 0x68,
    0xa8, 0xcc, 0x5c, 0x02, 0x26, 0x07, 0x0a, 0xbf
]

nonce = [
    0x0e, 0x02, 0xf4, 0xa9, 0xa8, 0xb5, 0xbe, 0xea,
    0xba, 0x83, 0x48, 0xd6, 0xd2, 0xf8, 0x7c, 0x60,
    0x68, 0x49, 0xdf, 0x9a, 0x5e, 0xef, 0x49, 0xa6,
    0x5c, 0x98, 0xcf, 0x07, 0xd4, 0xc2, 0x38, 0xa6
]


# ----------------------------------------------------------------------------------------
def send_command(cmd, txt):
    print(f'[+] Sending {txt} ...')
    sock.send(cmd)
    resp = sock.recv(128)
    print(f'[+] Received: {repr(resp)}')
    return resp


# ----------------------------------------------------------------------------------------
def upload_file(file, size):
    print(f'[+] Sending `upload {file}` command ...')
    sock.send(f'upload {file} {size}\r\n'.encode('utf-8'))
    resp = sock.recv(128)
    print(f'[+] Received: {repr(resp)}')

    buf = open(f'{file}.encr', 'rb').read()
    sock.send(buf)
    resp = sock.recv(128)
    print(f'[+] Received: {repr(resp)}')

    print(f'[+] Done. Decrypted file saved as: {file}')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] AmongRust crack started.')

    try:
        sock = socket.create_connection(('0.0.0.0', 8345))

        send_command(bytes(key),   'key')
        send_command(bytes(nonce), 'nonce')
        send_command(b'exec whoami\r\n', '`whoami` test command')
 
        upload_file('wallpaper.PNG', 122218)
        upload_file('wallpaper.ps1', 708)

        send_command(b'exit\r\n', '`exit` command')

        sock.close()
    except ConnectionRefusedError:
        print('[!] Error. Connection refused.')
        print('[+] Make sure that `payload_2.exe` is up and running.')
        exit()
     
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r'''
ispo@ispo-glaptop2:~/ctf/flare-on-challenges/flare-on-2023/08_AmongRust$ ./amongrust_crack.py 
[+] AmongRust crack started.
[+] Sending key ...
[+] Received: b'ACK_K\r'
[+] Sending nonce ...
[+] Received: b'ACK_N\r'
[+] Sending `whoami` test command ...
[+] Received: b'ISPO-GLAPTOP2\\ispo\n\r'
[+] Sending `upload wallpaper.PNG` command ...
[+] Received: b'ACK_UPLOAD\r'
[+] Received: b'ACK_UPLOAD_FIN\r'
[+] Done. Decrypted file saved as: wallpaper.PNG
[+] Sending `upload wallpaper.ps1` command ...
[+] Received: b'ACK_UPLOAD\r'
[+] Received: b'ACK_UPLOAD_FIN\r'
[+] Done. Decrypted file saved as: wallpaper.ps1
[+] Sending `exit` command ...
[+] Received: b''
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------
