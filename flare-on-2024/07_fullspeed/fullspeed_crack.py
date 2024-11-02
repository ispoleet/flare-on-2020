#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 07 - fullspeed
# ----------------------------------------------------------------------------------------
import scapy.all
import binascii
import hashlib
from Crypto.Cipher import Salsa20
from Crypto.Cipher import ChaCha20


# Shared key (x, y) from ECDH:
shared_x = 9285933189458587360370996409965684516994278319709076885861327850062567211786910941012004843231232528920376385508032
shared_y = 380692327439186423832217831462830789200626503899948375582964334293932372864029888872966411054442434800585116270210

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] fullspeed crack started.')
    
    print('[+] Loading encrypted packets from pcapng')
    pcap_flow = scapy.all.rdpcap('capture.pcapng')
    encr_packets = []
    for j, packet in enumerate(pcap_flow):
        try:   
            # PUSH flag is set, so we have data             
            if 'P' in packet[scapy.all.TCP].flags:
                payload = bytes(packet[scapy.all.TCP].payload)
                pkt_hex = ' '.join(f'{p:02X}' for p in payload[:32])
                print(f"[+] #{j+1:<2d}: {len(payload):2d} bytes ~> {pkt_hex}")
                
                encr_packets.append(payload.rstrip(b'\x00'))
        except Exception as e:
            print(f'[!] Error. Cannot process packet: {packet!r}')

    
    print('[+] Building symmetric key from `shared_x`')

    shared_x_hex = hex(shared_x)[2:]
    shared_x_bin = binascii.unhexlify(shared_x_hex)
    print(f'[+] shared_x (hex): {shared_x_hex}')

    key = hashlib.sha512(shared_x_bin).hexdigest()
    # b48f8fa4c856d496acdecd16d9c94cc6b01aa1c0065b023be97afdd12156f3dc3fd480978485d8183c090203b6d384c20e853e1f20f88d1c5e0f86f16e6ca5b2
    print(f'[+] Symmetric key: {key}')
    key = hashlib.sha512(shared_x_bin).digest()

    
    print('[+] Decrypting communication ...')

    # The first 4 packets are the Diffie-Hellman key exhange coordinates (48-bytes each).
    # The 4th packet is 55 bytes (the last 7 bytes are encrypted data).
    encr_packets = [encr_packets[3][48:]] + encr_packets[4:] # Discard ECDH numbers

    # The first 32 bytes of the SHA512 are the key and the next 8 the nonce.
    cipher = ChaCha20.new(key=key[:32], nonce=key[32:40])

    for encr_packet in encr_packets:
        pkt_hex = ' '.join(f'{p:02X}' for p in encr_packet[:10])
        plaintext = cipher.decrypt(encr_packet)
        
        print(f'[+] Decrypted: ({len(encr_packet):2} B): {pkt_hex:30s} ~> {plaintext}')

    print('[+] Program finished successfully. Bye bye :)')


# ----------------------------------------------------------------------------------------
r"""
┌─[:(]─[10:31:45]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/07_fullspeed]
└──> ./fullspeed_crack.py 
[+] fullspeed crack started.
[+] Loading encrypted packets from pcapng
[+] #4 : 48 bytes ~> 0A 6C 55 90 73 DA 49 75 4E 9A D9 84 6A 72 95 47 45 E4 F2 92 12 13 EC CD A4 B1 42 2E 2F DD 64 6F
[+] #6 : 48 bytes ~> 26 40 22 DA F8 C7 67 6A 1B 27 20 91 7B 82 99 9D 42 CD 18 78 D3 1B C5 7B 6D B1 7B 97 05 C7 FF 24
[+] #8 : 48 bytes ~> A0 D2 EB A8 17 E3 8B 03 CD 06 32 27 BD 32 E3 53 88 08 18 89 3A B0 23 78 D7 DB 3C 71 C5 C7 25 C6
[+] #10: 55 bytes ~> 96 A3 5E AF 2A 5E 0B 43 00 21 DE 36 1A A5 8F 80 15 98 1F FD 0D 98 24 B5 0A F2 3B 5C CF 16 FA 4E
[+] #11:  7 bytes ~> 3F BD 43 DA 3E E3 25
[+] #13:  6 bytes ~> 86 DF D7 00 00 00
[+] #14: 54 bytes ~> C5 0C EA 1C 4A A0 64 C3 5A 7F 6E 3A B0 25 84 41 AC 15 85 C3 62 56 DE A8 3C AC 93 00 7A 0C 3A 29
[+] #16: 11 bytes ~> FC B1 D2 CD BB A9 79 C9 89 99 8C
[+] #17:  3 bytes ~> 61 49 0B
[+] #19:  6 bytes ~> CE 39 DA 00 00 00
[+] #20: 45 bytes ~> 57 70 11 E0 D7 6E C8 EB 0B 82 59 33 1D EF 13 EE 6D 86 72 3E AC 9F 04 28 92 4E E7 F8 41 1D 4C 70
[+] #22: 17 bytes ~> 2C AE 60 0B 5F 32 CE A1 93 E0 DE 63 D7 09 83 8B D6
[+] #23:  3 bytes ~> A7 FD 35
[+] #25:  6 bytes ~> ED F0 FC 00 00 00
[+] #26: 39 bytes ~> 80 2B 15 18 6C 7A 1B 1A 47 5D AF 94 AE 40 F6 BB 81 AF CE DC 4A FB 15 8A 51 28 C2 8C 91 CD 7A 88
[+] #27: 11 bytes ~> AE C8 D2 7A 7C F2 6A 17 27 36 85
[+] #28:  3 bytes ~> 35 A4 4E
[+] #29:  6 bytes ~> 2F 39 17 00 00 00
[+] #30: 74 bytes ~> ED 09 44 7D ED 79 72 19 C9 66 EF 3D D5 70 5A 3C 32 BD B1 71 0A E3 B8 7F E6 66 69 E0 B4 64 6F C4
[+] #31: 46 bytes ~> F5 98 1F 71 C7 EA 1B 5D 8B 1E 5F 06 FC 83 B1 DE F3 8C 6F 4E 69 4E 37 06 41 2E AB F5 4E 3B 6F 4D
[+] #32:  3 bytes ~> 40 08 BC
[+] #33:  6 bytes ~> 54 E4 1E 00 00 00
[+] #34: 40 bytes ~> F7 01 FE E7 4E 80 E8 DF B5 4B 48 7F 9B 2E 3A 27 7F A2 89 CF 6C B8 DF 98 6C DD 38 7E 34 2A C9 F5
[+] #35: 13 bytes ~> 5C A6 8D 13 94 BE 2A 4D 3D 4D 7C 82 E5
[+] #36: 53 bytes ~> 31 B6 DA C6 2E F1 AD 8D C1 F6 0B 79 26 5E D0 DE AA 31 DD D2 D5 3A A9 FD 93 43 46 38 10 F3 E2 23
[+] #37:  6 bytes ~> 0D 1E C0 6F 36 00
[+] Building symmetric key from `shared_x`
[+] shared_x (hex): 3c54f90f4d2cc9c0b62df2866c2b4f0c5afae8136d2a1e76d2694999624325f5609c50b4677efa21a37664b50cec92c0
[+] Symmetric key: b48f8fa4c856d496acdecd16d9c94cc6b01aa1c0065b023be97afdd12156f3dc3fd480978485d8183c090203b6d384c20e853e1f20f88d1c5e0f86f16e6ca5b2
[+] Decrypting communication ...
[+] Decrypted: ( 7 B): F2 72 D5 4C 31 86 0F           ~> b'verify\x00'
[+] Decrypted: ( 7 B): 3F BD 43 DA 3E E3 25           ~> b'verify\x00'
[+] Decrypted: ( 3 B): 86 DF D7                       ~> b'ls\x00'
[+] Decrypted: (54 B): C5 0C EA 1C 4A A0 64 C3 5A 7F  ~> b'=== dirs ===\r\nsecrets\r\n=== files ===\r\nfullspeed.exe\r\n\x00'
[+] Decrypted: (11 B): FC B1 D2 CD BB A9 79 C9 89 99  ~> b'cd|secrets\x00'
[+] Decrypted: ( 3 B): 61 49 0B                       ~> b'ok\x00'
[+] Decrypted: ( 3 B): CE 39 DA                       ~> b'ls\x00'
[+] Decrypted: (45 B): 57 70 11 E0 D7 6E C8 EB 0B 82  ~> b'=== dirs ===\r\nsuper secrets\r\n=== files ===\r\n\x00'
[+] Decrypted: (17 B): 2C AE 60 0B 5F 32 CE A1 93 E0  ~> b'cd|super secrets\x00'
[+] Decrypted: ( 3 B): A7 FD 35                       ~> b'ok\x00'
[+] Decrypted: ( 3 B): ED F0 FC                       ~> b'ls\x00'
[+] Decrypted: (39 B): 80 2B 15 18 6C 7A 1B 1A 47 5D  ~> b'=== dirs ===\r\n.hidden\r\n=== files ===\r\n\x00'
[+] Decrypted: (11 B): AE C8 D2 7A 7C F2 6A 17 27 36  ~> b'cd|.hidden\x00'
[+] Decrypted: ( 3 B): 35 A4 4E                       ~> b'ok\x00'
[+] Decrypted: ( 3 B): 2F 39 17                       ~> b'ls\x00'
[+] Decrypted: (74 B): ED 09 44 7D ED 79 72 19 C9 66  ~> b"=== dirs ===\r\nwait, dot folders aren't hidden on windows\r\n=== files ===\r\n\x00"
[+] Decrypted: (46 B): F5 98 1F 71 C7 EA 1B 5D 8B 1E  ~> b"cd|wait, dot folders aren't hidden on windows\x00"
[+] Decrypted: ( 3 B): 40 08 BC                       ~> b'ok\x00'
[+] Decrypted: ( 3 B): 54 E4 1E                       ~> b'ls\x00'
[+] Decrypted: (40 B): F7 01 FE E7 4E 80 E8 DF B5 4B  ~> b'=== dirs ===\r\n=== files ===\r\nflag.txt\r\n\x00'
[+] Decrypted: (13 B): 5C A6 8D 13 94 BE 2A 4D 3D 4D  ~> b'cat|flag.txt\x00'
[+] Decrypted: (53 B): 31 B6 DA C6 2E F1 AD 8D C1 F6  ~> b'RDBudF9VNWVfeTB1cl9Pd25fQ3VSdjNzQGZsYXJlLW9uLmNvbQ==\x00'
[+] Decrypted: ( 5 B): 0D 1E C0 6F 36                 ~> b'exit\x00'
[+] Program finished successfully. Bye bye :)

┌─[10:31:49]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/07_fullspeed]
└──> echo RDBudF9VNWVfeTB1cl9Pd25fQ3VSdjNzQGZsYXJlLW9uLmNvbQ== | base64 -d
D0nt_U5e_y0ur_Own_CuRv3s@flare-on.com
"""
# ----------------------------------------------------------------------------------------
