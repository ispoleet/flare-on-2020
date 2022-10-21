#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# FLARE-ON 2022: 8 - backdoor
# ----------------------------------------------------------------------------------------
import os
import re
import base64
import hashlib


base64_cmds = [
    "JChwaW5nIC1uIDEgMTAuNjUuNDUuMyB8IGZpbmRzdHIgL2kgdHRsKSAtZXEgJG51bGw7JChwaW5nIC1uIDEgMTAuNjUuNC41MiB8IGZpbmRzdHIgL2kgdHRsKSAtZXEgJG51bGw7JChwaW5nIC1uIDEgMTAuNjUuMzEuMTU1IHwgZmluZHN0ciAvaSB0dGwpIC1lcSAkbnVsbDskKHBpbmcgLW4gMSBmbGFyZS1vbi5jb20gfCBmaW5kc3RyIC9pIHR0bCkgLWVxICRudWxs",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4AMgAyAC4ANAAyACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgAxADAALgAyADMALgAyADAAMAAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4ANAA1AC4AMQA5ACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgAxADAALgAxADkALgA1ADAAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA=",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANQAxAC4AMQAxACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgA2ADUALgA2AC4AMQAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANQAyAC4AMgAwADAAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADYANQAuADYALgAzACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwA",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4AMQAwAC4ANAAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4ANQAwAC4AMQAwACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgAxADAALgAyADIALgA1ADAAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADEAMAAuADQANQAuADEAOQAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsAA==",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4AMgAxAC4AMgAwADEAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADEAMAAuADEAOQAuADIAMAAxACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgAxADAALgAxADkALgAyADAAMgAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4AMQAwAC4AMgA0AC4AMgAwADAAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA=",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANAA1AC4AMQA4ACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgA2ADUALgAyADgALgA0ADEAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADYANQAuADMANgAuADEAMwAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANQAxAC4AMQAwACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwA",
    "bnNsb29rdXAgZmxhcmUtb24uY29tIHwgZmluZHN0ciAvaSBBZGRyZXNzO25zbG9va3VwIHdlYm1haWwuZmxhcmUtb24uY29tIHwgZmluZHN0ciAvaSBBZGRyZXNz",
    "JAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANAAuADUAMAAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANAAuADUAMQAgAHwAIABmAGkAbgBkAHMAdAByACAALwBpACAAdAB0AGwAKQAgAC0AZQBxACAAJABuAHUAbABsADsAJAAoAHAAaQBuAGcAIAAtAG4AIAAxACAAMQAwAC4ANgA1AC4ANgA1AC4ANgA1ACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwAOwAkACgAcABpAG4AZwAgAC0AbgAgADEAIAAxADAALgA2ADUALgA1ADMALgA1ADMAIAB8ACAAZgBpAG4AZABzAHQAcgAgAC8AaQAgAHQAdABsACkAIAAtAGUAcQAgACQAbgB1AGwAbAA7ACQAKABwAGkAbgBnACAALQBuACAAMQAgADEAMAAuADYANQAuADIAMQAuADIAMAAwACAAfAAgAGYAaQBuAGQAcwB0AHIAIAAvAGkAIAB0AHQAbAApACAALQBlAHEAIAAkAG4AdQBsAGwA",
    "RwBlAHQALQBOAGUAdABUAEMAUABDAG8AbgBuAGUAYwB0AGkAbwBuACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBTAHQAYQB0AGUAIAAtAGUAcQAgACIARQBzAHQAYQBiAGwAaQBzAGgAZQBkACIAfQAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAAIgBMAG8AYwBhAGwAQQBkAGQAcgBlAHMAcwAiACwAIAAiAEwAbwBjAGEAbABQAG8AcgB0ACIALAAgACIAUgBlAG0AbwB0AGUAQQBkAGQAcgBlAHMAcwAiACwAIAAiAFIAZQBtAG8AdABlAFAAbwByAHQAIgA=",
    "WwBTAHkAcwB0AGUAbQAuAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AUwB0AHIAaQBuAGcA",
    "RwBlAHQALQBOAGUAdABJAFAAQQBkAGQAcgBlAHMAcwAgAC0AQQBkAGQAcgBlAHMAcwBGAGEAbQBpAGwAeQAgAEkAUAB2ADQAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAEkAUABBAGQAZAByAGUAcwBzAA==",
    "RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgACIAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwAiACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABOAGEAbQBlAA==",
    "RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgACcAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwAgACgAeAA4ADYAKQAnACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABOAGEAbQBlAA==",
    "RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUABhAHQAaAAgACcAQwA6ACcAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAE4AYQBtAGUA",
    "RwBlAHQALQBOAGUAdABOAGUAaQBnAGgAYgBvAHIAIAAtAEEAZABkAHIAZQBzAHMARgBhAG0AaQBsAHkAIABJAFAAdgA0ACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAiAEkAUABBAEQARAByAGUAcwBzACIA",
    "RwBlAHQALQBOAGUAdABJAFAAQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgAgAHwAIABGAG8AcgBlAGEAYwBoACAASQBQAHYANABEAGUAZgBhAHUAbAB0AEcAYQB0AGUAdwBhAHkAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAE4AZQB4AHQASABvAHAA",
    "RwBlAHQALQBEAG4AcwBDAGwAaQBlAG4AdABTAGUAcgB2AGUAcgBBAGQAZAByAGUAcwBzACAALQBBAGQAZAByAGUAcwBzAEYAYQBtAGkAbAB5ACAASQBQAHYANAAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUAYwB0ACAAUwBFAFIAVgBFAFIAQQBkAGQAcgBlAHMAcwBlAHMA",
]


def powershell(c):
    return "powershell -exec bypass -enc \"" + c + "\"";


# Key: command order
# Value: (text appened to SHA, command that is executed on victim)
cmd_table = {
    "19": ("146",    powershell(base64_cmds[0])),
    "18": ("939",    powershell(base64_cmds[1])),
    "16": ("e87",    powershell(base64_cmds[2])),
    "15": ("197",    powershell(base64_cmds[3])),
    "14": ("3a7",    powershell(base64_cmds[4])),
    "10": ("f38",    "hostname"),
    "17": ("2e4",    powershell(base64_cmds[5])),
    "13": ("e38",    powershell(base64_cmds[6])),
    "12": ("570",    powershell(base64_cmds[7])),
    "11": ("818",    powershell(base64_cmds[8])),
    "4":  ("ea5",    powershell(base64_cmds[9])),
    "5":  ("bfb",    "net user"),
    "3":  ("113",    "whoami"),
    "1":  ("c2e",    powershell(base64_cmds[10])),
    "7":  ("b",      powershell(base64_cmds[11])),
    "8":  ("2b7",    powershell(base64_cmds[12])),
    "9":  ("9b2",    powershell(base64_cmds[13])),
    "2":  ("d7d",    powershell(base64_cmds[14])),
    "22": ("709",    "systeminfo | findstr /i \"Domain\""),
    "20": ("3c9974", powershell(base64_cmds[15])),
    "21": ("8e6",    powershell(base64_cmds[16])),
}


# ----------------------------------------------------------------------------------------
def rc4_decrypt(key, ciphertext):
    S = [i for i in range(256)]
    j = 0
    for i in range(256):
        j = (S[i] + j + (key[i % len(key)])) % 256;
        S[i], S[j] = S[j], S[i]

    i, j = 0, 0
    plaintext = []

    for c in range(len(ciphertext)):
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        S[i], S[j] = S[j], S[i]
        k = S[(S[j] + S[i]) % 256]
        plaintext.append(ciphertext[c] ^ k)

    return plaintext


# ----------------------------------------------------------------------------------------
if __name__ == '__main__':
    print('[+] Backdoor crack started.')

    # s = 5489
    # f = 1812433253
    # state = [0]*624
    # state[0] = s
    # for i in range(1, 624):
    #     state[i] = (f * (state[i - 1] ^ (state[i - 1] >> 30)) + i) & 0xFFFFFFFF
    #
    # print(', '.join('%08X' % a for a in state))

    print('[+] Decoding base64 commands ...')
    for cmd in base64_cmds:
        try:
            print(f"[+]    {base64.b64decode(cmd).decode('utf-16')}")
        except UnicodeDecodeError:
            print(f"[+]    {base64.b64decode(cmd).decode('utf-8')}")

    # Decrypt command order.
    cmd_order = [
        250, 242, 240, 235, 243, 249, 247, 245, 238, 232,
        253, 244, 237, 251, 234, 233, 236, 246, 241, 255,
        252
    ]
    
    cmd_order = [c ^ 248 for c in cmd_order]
    print(f"[+] C&C Command Order: {'-'.join('%d' % c for c in cmd_order)}")

    print(f'[+] Calculating SHA256 key ...')
    m = hashlib.sha256()
    sha256 = ''
    key = ''
    
    for nxt_cmd in cmd_order:
        sha_chunk, shell_cmd = cmd_table[str(nxt_cmd)]

        print(f'[+] Adding {sha_chunk} to SHA256 ...')
        sha256 += sha_chunk

        if nxt_cmd == 4:
            print('[+] Skipping command #4 ...')
            continue  # Command No.4 does not contribute its text to SHA.

        # Add calls from reflection (they're for .NET framework 4.7.2).
        key  = 'System.Object InvokeMethod(System.Object, System.Object[], System.Signature, Boolean)'
        key += 'System.Object Invoke(System.Object, System.Reflection.BindingFlags, System.Reflection.Binder, System.Object[], System.Globalization.CultureInfo)'
        key += shell_cmd
        
        m.update(key.encode('utf-8'))

    decr_key = m.digest()
    pe_section_file = sha256[::-1][:8]

    print(f"[+] Final SHA256: {sha256}")
    print(f"[+] Final decryption key: {'-'.join('%02X' % x for x in decr_key)}")
    print(f"[+] PE section file name: {pe_section_file}")

    # Load secret PE section.
    with open(os.path.join("pe_sections", pe_section_file), 'rb') as fp:
        secret_section = fp.read()

    print(f'[+] Secret PE section size: {len(secret_section)}')
    print('[+] Secret PE section (first 32 bytes):',
          '-'.join('%02X' % x for x in secret_section[:32]))

    # Decrypt file extension and secret file.    
    ext = rc4_decrypt(decr_key, [31, 29, 40, 72])
    ext = ''.join('%c' % e for e in ext)

    print(f'[+] Secret file extension decrypted: `{ext}`')

    plaintext = rc4_decrypt(decr_key, secret_section)

    print('[+] Decrypted file (first 32 bytes):',
          '-'.join('%02X' % x for x in plaintext[:32]))

    with open(f'secret_file{ext}', 'wb') as fp:
        fp.write(bytes(plaintext))

    print(f'[+] File `secret_file{ext}` decrypted successfully')

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
[+] Decoding base64 commands ...
[+]    $(ping -n 1 10.65.45.3 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.4.52 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.31.155 | findstr /i ttl) -eq $null;$(ping -n 1 flare-on.com | findstr /i ttl) -eq $null
[+]    $(ping -n 1 10.10.22.42 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.23.200 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.45.19 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.19.50 | findstr /i ttl) -eq $null
[+]    $(ping -n 1 10.65.51.11 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.6.1 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.52.200 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.6.3 | findstr /i ttl) -eq $null
[+]    $(ping -n 1 10.10.10.4 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.50.10 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.22.50 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.45.19 | findstr /i ttl) -eq $null
[+]    $(ping -n 1 10.10.21.201 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.19.201 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.19.202 | findstr /i ttl) -eq $null;$(ping -n 1 10.10.24.200 | findstr /i ttl) -eq $null
[+]    $(ping -n 1 10.65.45.18 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.28.41 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.36.13 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.51.10 | findstr /i ttl) -eq $null
[+]    nslookup flare-on.com | findstr /i Address;nslookup webmail.flare-on.com | findstr /i Address
[+]    $(ping -n 1 10.65.4.50 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.4.51 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.65.65 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.53.53 | findstr /i ttl) -eq $null;$(ping -n 1 10.65.21.200 | findstr /i ttl) -eq $null
[+]    Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object "LocalAddress", "LocalPort", "RemoteAddress", "RemotePort"
[+]    [System.Environment]::OSVersion.VersionString
[+]    Get-NetIPAddress -AddressFamily IPv4 | Select-Object IPAddress
[+]    Get-ChildItem -Path "C:\Program Files" | Select-Object Name
[+]    Get-ChildItem -Path 'C:\Program Files (x86)' | Select-Object Name
[+]    Get-ChildItem -Path 'C:' | Select-Object Name
[+]    Get-NetNeighbor -AddressFamily IPv4 | Select-Object "IPADDress"
[+]    Get-NetIPConfiguration | Foreach IPv4DefaultGateway | Select-Object NextHop
[+]    Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object SERVERAddresses
[+] C&C Command Order: 2-10-8-19-11-1-15-13-22-16-5-12-21-3-18-17-20-14-9-7-4
[+] Calculating SHA256 key ...
[+] Adding d7d to SHA256 ...
[+] Adding f38 to SHA256 ...
[+] Adding 2b7 to SHA256 ...
[+] Adding 146 to SHA256 ...
[+] Adding 818 to SHA256 ...
[+] Adding c2e to SHA256 ...
[+] Adding 197 to SHA256 ...
[+] Adding e38 to SHA256 ...
[+] Adding 709 to SHA256 ...
[+] Adding e87 to SHA256 ...
[+] Adding bfb to SHA256 ...
[+] Adding 570 to SHA256 ...
[+] Adding 8e6 to SHA256 ...
[+] Adding 113 to SHA256 ...
[+] Adding 939 to SHA256 ...
[+] Adding 2e4 to SHA256 ...
[+] Adding 3c9974 to SHA256 ...
[+] Adding 3a7 to SHA256 ...
[+] Adding 9b2 to SHA256 ...
[+] Adding b to SHA256 ...
[+] Adding ea5 to SHA256 ...
[+] Skipping command #4 ...
[+] Final SHA256: d7df382b7146818c2e197e38709e87bfb5708e61139392e43c99743a79b2bea5
[+] Final decryption key: 94-4C-EE-4D-42-58-3A-53-E8-1A-7E-A5-C9-DC-2B-B6-B9-01-21-3A-0E-B3-28-6C-A6-9D-3F-01-EF-84-AC-BB
[+] PE section file name: 5aeb2b97
[+] Secret PE section size: 11421531
[+] Secret PE section (first 32 bytes): 76-33-07-16-8B-B1-9F-C2-30-30-11-23-4F-17-E4-33-72-5C-FA-7A-6A-28-F7-F3-D2-A1-34-9B-F9-44-1B-CD
[+] Secret file extension decrypted: `.gif`
[+] Decrypted file (first 32 bytes): 47-49-46-38-39-61-BF-03-0B-02-F7-1F-31-00-00-00-24-00-00-48-00-00-6C-00-00-90-00-00-B4-00-00-D8
[+] File `secret_file.gif` decrypted successfully
[+] Program finished! Bye bye :)
'''
# ----------------------------------------------------------------------------------------
