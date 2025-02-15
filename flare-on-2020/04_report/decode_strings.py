#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Flare-On 2020: 4 - Report 
# --------------------------------------------------------------------------------------------------
import magic

str_tbl = [
    '9655B040B64667238524D15D6201',
    'B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38',
    'C555AC40A7469C234424',
    '853FA85C470699477D3851249A4B9C4E',
    'A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254',
    '853FA85C470699477D3851249A4B9C4E',
    '9A55B240B84692239624',
    'CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806',
    'A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421',
    'CB55A240B5469B23',
    'AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D',
    'D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64'
]


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Flare-On 2020: 4 - Report'

    # --------------------------------------------------------------------------    
    # Decode all constant strings.
    #
    # The decoded strings are:
    #    1: AppData
    #    2: \Microsoft\stomp.mp3
    #    3: play 
    #    4: FLARE-ON
    #    5: Sorry, this machine is not supported.
    #    6: FLARE-ON
    #    7: Error
    #    8: winmgmts:\\.\root\CIMV2
    #    9: SELECT Name FROM Win32_Process
    #   10: vbox
    #   11: WScript.Network
    #   12: \Microsoft\v.png
    # --------------------------------------------------------------------------
    print '[+] Decoding constant strings ...'
    idx = 0
    for enc_str in str_tbl:
        dec_str = ''
        # Split encoded string into groups of 4.
        for grp in [enc_str[i:i+4] for i in range(0, len(enc_str), 4)]:
            dec_str += chr(int(grp[:2], 16) - int(grp[2:], 16))

        idx += 1
        print "[+]    %2d: %s --> '%s'" % (idx, enc_str, dec_str)

# --------------------------------------------------------------------------------------------------

