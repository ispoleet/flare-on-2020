
## Flare-On 2020 - #4 report
___

### Description: 

*Nobody likes analysing infected documents, but it pays the bills. Reverse this macro thrill-ride to discover how to get it to show you the key.*

`*7zip password: flare`
___

### Solution:

In this challenge we have MACRO virus. The first step is to install 
[oletools](https://github.com/decalage2/oletools) and extract the source code:


```vbscript
ispo@ispo-glaptop:~/ctf/flare_on/4_report$ python oletools/oletools/olevba.py report.xls 
olevba 0.56dev10 on Python 2.7.18 - http://decalage.info/python/oletools
===============================================================================
FILE: report.xls
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: report.xls - OLE stream: u'_VBA_PROJECT_CUR/VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Sub Workbook_Open()
Sheet1.folderol
End Sub

Sub Auto_Open()
Sheet1.folderol
End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: report.xls - OLE stream: u'_VBA_PROJECT_CUR/VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
Private Declare Function InternetGetConnectedState Lib "wininet.dll" _
(ByRef dwflags As Long, ByVal dwReserved As Long) As Long

Private Declare PtrSafe Function mciSendString Lib "winmm.dll" Alias _
   "mciSendStringA" (ByVal lpstrCommand As String, ByVal _
   lpstrReturnString As Any, ByVal uReturnLength As Long, ByVal _
   hwndCallback As Long) As Long

Private Declare Function GetShortPathName Lib "kernel32" Alias "GetShortPathNameA" _
    (ByVal lpszLongPath As String, ByVal lpszShortPath As String, ByVal lBuffer As Long) As Long

Public Function GetInternetConnectedState() As Boolean
  GetInternetConnectedState = InternetGetConnectedState(0&, 0&)
End Function

Function rigmarole(es As String) As String
    Dim furphy As String
    Dim c As Integer
    Dim s As String
    Dim cc As Integer
    furphy = ""
    For i = 1 To Len(es) Step 4
        c = CDec("&H" & Mid(es, i, 2))
        s = CDec("&H" & Mid(es, i + 2, 2))
        cc = c - s
        furphy = furphy + Chr(cc)
    Next i
    rigmarole = furphy
End Function

Function folderol()
    Dim wabbit() As Byte
    Dim fn As Integer: fn = FreeFile
    Dim onzo() As String
    Dim mf As String
    Dim xertz As Variant
    
    onzo = Split(F.L, ".")
    
    If GetInternetConnectedState = False Then
        MsgBox "Cannot establish Internet connection.", vbCritical, "Error"
        End
    End If

    Set fudgel = GetObject(rigmarole(onzo(7)))
    Set twattling = fudgel.ExecQuery(rigmarole(onzo(8)), , 48)
    For Each p In twattling
        Dim pos As Integer
        pos = InStr(LCase(p.Name), "vmw") + InStr(LCase(p.Name), "vmt") + InStr(LCase(p.Name), rigmarole(onzo(9)))
        If pos > 0 Then
            MsgBox rigmarole(onzo(4)), vbCritical, rigmarole(onzo(6))
            End
        End If
    Next
        
    xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)

    wabbit = canoodle(F.T.Text, 0, 168667, xertz)
    mf = Environ(rigmarole(onzo(0))) & rigmarole(onzo(1))
    Open mf For Binary Lock Read Write As #fn
      Put #fn, , wabbit
    Close #fn
    
    mucolerd = mciSendString(rigmarole(onzo(2)) & mf, 0&, 0, 0)
End Function

Function canoodle(panjandrum As String, ardylo As Integer, s As Long, bibble As Variant) As Byte()
    Dim quean As Long
    Dim cattywampus As Long
    Dim kerfuffle() As Byte
    ReDim kerfuffle(s)
    quean = 0
    For cattywampus = 1 To Len(panjandrum) Step 4
        kerfuffle(quean) = CByte("&H" & Mid(panjandrum, cattywampus + ardylo, 2)) Xor bibble(quean Mod (UBound(bibble) + 1))
        quean = quean + 1
        If quean = UBound(kerfuffle) Then
            Exit For
        End If
    Next cattywampus
    canoodle = kerfuffle
End Function

-------------------------------------------------------------------------------
VBA MACRO F.frm 
in file: report.xls - OLE stream: u'_VBA_PROJECT_CUR/VBA/F'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
-------------------------------------------------------------------------------
VBA MACRO xlm_macro.txt 
in file: xlm_macro - OLE stream: 'xlm_macro'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
' 0085     14 BOUNDSHEET : Sheet Information - worksheet or dialog sheet, visible - Sheet1
-------------------------------------------------------------------------------
VBA FORM STRING IN 'report.xls' - OLE stream: u'_VBA_PROJECT_CUR/F/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
�9655B040B64667238524D15D6201.B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38.C555AC40A7469C234424.853FA85C470699477D3851249A4B9C4E.A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254.853FA85C470699477D3851249A4B9C4E.9A55B240B84692239624.CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806.A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421.CB55A240B5469B23.AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D.D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64
-------------------------------------------------------------------------------
VBA FORM STRING IN 'report.xls' - OLE stream: u'_VBA_PROJECT_CUR/F/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
H�,�p
-------------------------------------------------------------------------------
VBA FORM STRING IN 'report.xls' - OLE stream: u'_VBA_PROJECT_CUR/F/o'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
58c7661f00634702555f664b7756884c864edc4fef2d9c48881bac0911082214334e424f552f661d7752ce41d54deb70e9468949892db745545270fc333c44aa5525634f772d88699970983b8b18fe1eed3aba1d584c763201724431553e66295a2888269941aa20ef72a435b4359d36312b4b6f4048643d3b3b0927034ca846ee36c295da80b8d9fd3b97d3
[.... MANY MORE LINES ....]
00b70023004c006a0017003a00ba0048001a00c900500072005700b100ba009000ef008100c7006b008600be0025002e00f3009600ed000800a2005b006f003b00b800ae00bf005000ac00ba0059005900f60039001b0056002900c100040041004c0046004e00060068000b001600ef000e002600cc
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Open                |May open a file                              |
|Suspicious|Lib                 |May run code from a DLL                      |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |wininet.dll         |Executable file name                         |
|IOC       |winmm.dll           |Executable file name                         |
+----------+--------------------+---------------------------------------------+
```

Let's start from the main function which is `folderol` (it is invoked when the sheet opens):
```vbscript
Sub Workbook_Open()
    Sheet1.folderol
End Sub
 
Sub Auto_Open()
    Sheet1.folderol
End Sub
```

The first interesting part in `folderol` is `onzo = Split(F.L, ".")` which splits the following hex stream at the dots:

```
9655B040B64667238524D15D6201.B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38.C555AC40A7469C234424.853FA85C470699477D3851249A4B9C4E.A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254.853FA85C470699477D3851249A4B9C4E.9A55B240B84692239624.CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806.A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421.CB55A240B5469B23.AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D.D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64
``` 

Then `rigmarole` takes one of these strings and performs a custom hex-decoding:
```vbscript
Function rigmarole(es As String) As String
    Dim furphy As String
    Dim c As Integer
    Dim s As String
    Dim cc As Integer
    furphy = ""
    For i = 1 To Len(es) Step 4
        c = CDec("&H" & Mid(es, i, 2))          ' c = int(es[i:i+2], 16)
        s = CDec("&H" & Mid(es, i + 2, 2))      ' s = int(es[i+2:i+4])
        cc = c - s
        furphy = furphy + Chr(cc)               ' furphy += chr(c - s)
    Next i
    rigmarole = furphy                          ' return furphy
End Function
```

To decode all strings, we create [decode_strings.py](./decode_strings.py):
```
 1: 9655B040B64667238524D15D6201 --> 'AppData'
 2: B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38 --> '\Microsoft\stomp.mp3'
 3: C555AC40A7469C234424 --> 'play '
 4: 853FA85C470699477D3851249A4B9C4E --> 'FLARE-ON'
 5: A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254 --> 'Sorry, this machine is not supported.'
 6: 853FA85C470699477D3851249A4B9C4E --> 'FLARE-ON'
 7: 9A55B240B84692239624 --> 'Error'
 8: CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806 --> 'winmgmts:\\.\root\CIMV2'
 9: A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421 --> 'SELECT Name FROM Win32_Process'
10: CB55A240B5469B23 --> 'vbox'
11: AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D --> 'WScript.Network'
12: D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64 --> '\Microsoft\v.png'
```

Knowing the constant strings, we can go back to `folderol`:
```vbscript
Function folderol()
    Dim wabbit() As Byte
    Dim fn As Integer: fn = FreeFile
    Dim onzo() As String
    Dim mf As String
    Dim xertz As Variant
    
    onzo = Split(F.L, ".")
    
    If GetInternetConnectedState = False Then
        MsgBox "Cannot establish Internet connection.", vbCritical, "Error"
        End
    End If

    Set fudgel = GetObject(rigmarole(onzo(7)))                  ' winmgmts:\\.\root\CIMV2
    Set twattling = fudgel.ExecQuery(rigmarole(onzo(8)), , 48)  ' SELECT Name FROM Win32_Process
    For Each p In twattling
        Dim pos As Integer
        pos = InStr(LCase(p.Name), "vmw") + InStr(LCase(p.Name), "vmt") + InStr(LCase(p.Name), rigmarole(onzo(9))) ' vbox
        If pos > 0 Then
            MsgBox rigmarole(onzo(4)), vbCritical, rigmarole(onzo(6))   ' Sorry, this machine is not supported. Error
            End
        End If
    Next
    
    ' &H00 and &HFF are excluded as they are 'weak keys'
    xertz = Array(&H11, &H22, &H33, &H44, &H55, &H66, &H77, &H88, &H99, &HAA, &HBB, &HCC, &HDD, &HEE)

    wabbit = decrypt(F.T.Text, 0, 168667, xertz)
    mf = Environ(rigmarole(onzo(0))) & rigmarole(onzo(1)) ' %AppData%\Microsoft\stomp.mp3
    Open mf For Binary Lock Read Write As #fn
      Put #fn, , wabbit
    Close #fn
    
    mucolerd = mciSendString(rigmarole(onzo(2)) & mf, 0&, 0, 0) ' play
End Function
```

After doing some checks with processes, function invokes `decrpyt` (old `canoodle`) to decrypt
a long hex stream. and stores it as `stomp.mp3`. We repeat these steps and we can successfully
recover the mp3. We play it but nothing is there:
```
ispo@ispo-glaptop:~/ctf/flare_on/4_report$ ffplay stomp.mp3 
ffplay version 4.3.1-1+build1 Copyright (c) 2003-2020 the FFmpeg developers

[mp3 @ 0x7fa1a0000bc0] Estimating duration from bitrate, this may be inaccurate
Input #0, mp3, from 'stomp.mp3':
  Metadata:
    publisher       : FLARE
    album_artist    : P. Code
    title           : This is not what you should be looking at...
    date            : 2020
  Duration: 00:00:08.23, start: 0.000000, bitrate: 163 kb/s
    Stream #0:0: Audio: mp3, 44100 Hz, stereo, fltp, 160 kb/s
   6.86 M-A:  0.000 fd=   0 aq=   23KB vq=  
```

My first though was that something was hidden in the mp3 file, but I saw this in the
metadata: `This is not what you should be looking at...`.

After it is a game of common sense and guessing. Let's look back at the decryption function:
```vbscript
' offset can be 0,1 or 2 (since we read cipher in 4 byte chunks) we can decrypt
' [0:2], [1:3], [2:4]
Function decrypt(cipher As String, offset As Integer, length As Long, xor_tbl As Variant) As Byte()
    Dim j As Long
    Dim i As Long
    Dim plain() As Byte
    ReDim plain(length)
    j = 0
 
    For i = 1 To Len(cipher) Step 4
        ' offset = 0
        ' int(cipher[i:i+2], 16) ^ xor_tbl[j % 15]
        plain(j) = CByte("&H" & Mid(cipher, i + offset, 2)) Xor xor_tbl(j Mod (UBound(xor_tbl) + 1))
        j = j + 1
        If j = UBound(plain) Then
            Exit For
        End If
    Next i
    decrypt = plain
End Function
```

The interesting observation here is that function selects `4` bytes at each step, but only `2`
are used for decryption (the `offset` parameter indicates which ones). To decrypt the mp3 we
used the first `2` bytes from each word, so my first guess was to do the same for the remaining two.

However the decrypted text did not make any sense (it was not a valid file), which means that
the decryption key is probably wrong.

By looking at the constant strings we see `v.png` which corresponds to a PNG file. I assumed that
the other file is a PNG image. According to the PNG RFC we know that:
```
The first eight bytes of a PNG file always contain the following (decimal) values:

   137 80 78 71 13 10 26 10
This signature indicates that the remainder of the file contains a single PNG image, consisting of a series of chunks beginning with an IHDR chunk and ending with an IEND chunk.
```

That is, we know the first `8` bytes of the plaintext, so we can use them to find the key (we XOR
the plaintext with the ciphertext). We do this and we get the new key: `NO-ERALF`

Knowing the key we can move on and decrypt the last 2 bytes from each word. We do this and
we get a valid PNG image. If we open the image no flag shows up. However the image thumbnail
contains the image.

![alt text](./v.png)


Which give us the flag: `thi5_cou1d_h4v3_b33n_b4d@flare-in.com`

The code that deciphers the image is here: [crack_cipher.py](./crack_cipher.py):

___

