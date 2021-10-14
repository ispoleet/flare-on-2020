
## Flare-On 2021 - #8: BeeLogin
___

### Description: 

*You're nearly done champ, just a few more to go. we put all the hard ones at the beginning of the challenge this year so its smooth sailing from this point. Call your friends, tell 'em you won. They probably don't care. Flare-On is your only friend now.*


`7-zip password: flare`
___


This challenge contains an obfuscated javascript file. File is huge and contains a lot of garbage
functions that are never get executed. To find out which code really gets executed, we load it in
Chrome and we attach a debugger to it. After removing the dead code and renaming the variables we
get a nice javascript listing (the full code is in [beelogin_short.html](./beelogin_short.html)):
```javascript
    function Add(this_) {    
        base64_str_1 = "4fny3zLzDRYIOe37Axvh5Toquw4GGWWdN/[....]PuC+2cX05g==";
        base64_str_2 = "b2JDN2luc2tiYXhLOFZaUWRRWTlSeXdJbk9lVWxLcHlrMXJsRnk5NjJaWkQ4SHdGVjhyOENQeFE5dGxUaEd1dGJ5ZDNOYTEzRmZRN1V1emxkZUJQNTN0Umt6WkxjbDdEaU1KVWF1M29LWURzOGxUWFR2YjJqQW1HUmNEU2RRcXdFSERzM0d3emhOaGVIYlE3dm9aeVJTMHdLY2Vhb3YyVGQ4UnQ2SXUwdm1ZbGlVYjA4YVRES2xESnlXU3NtZENMN0J4MnBYdlZET3RUSmlhY2V6Y3B6eUM2Mm4yOWs=";

        const_len_64      = 64
        decoded_str_1     = atob(base64_str_1).split('');
        decoded_str_1_len = decoded_str_1.length;
        decoded_str_2     = atob(base64_str_2).split('');

        passwd_4 = this_.ZJqLM97qEThEw2Tgkd8VM5OWlcFN6hx4y2.value.split(';')

        char_array = 'gflsdgfdjgflkdsfjg4980utjkfdskfglsldfgjJLmSDA49sdfgjlfdsjjqdgjfj'.split('');

        if (passwd_4[0].length == const_len_64)
            char_array = passwd_4[0].split('');

        for (i=0; i < decoded_str_2.length; i++) {
            decoded_str_2[i] = (decoded_str_2[i].charCodeAt(0) +
                                char_array[i % const_len_64].charCodeAt(0)) & 0xFF;   
        }
    
        decoded_str_1_copy = decoded_str_1

        for (i=0; i < decoded_str_1_len; i++) {
            decoded_str_1_copy[i] = (decoded_str_1_copy[i].charCodeAt(0) -
                                     decoded_str_2[i % decoded_str_2.length]) & 0xFF;   
        }

        stage_2_payload = "";

        for (i=0; i < decoded_str_1.length; i++) {
            stage_2_payload += String.fromCharCode(decoded_str_1_copy[i]);
        }

        if ('rFzmLyTiZ6AHlL1Q4xV7G8pW32' >= stage_2_payload) // always true
            eval(stage_2_payload)
    }
```

Code is fairly easy to understand: The password from the **4th** edit is used to decrypt the payload
in `base64_str_1` which is then passed as input to `eval`. Since the decrypted payload is evaluated,
it **must be valid javascript code, e.g., every byte from plaintext must be printable ASCII, or
newline, or NULL bytes**. Given that, all we have to do is to find what value to assign to the 4th
edit to get a plaintext 2nd Stage payload.

The biggest challenge here is that there are many valid passwords that generate ASCII plaintexts. To
solve this problem we look at the decrypted plaintexts and we choose the one that "makes sense".
For instance:
```
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6\VCN' ~> //Yes, but who can geny whe#mear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6]VCN' ~> //Yes, but who can geny whe#lear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6^VCN' ~> //Yes, but who can geny whe#kear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6_VCN' ~> //Yes, but who can geny whe#jear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6`VCN' ~> //Yes, but who can geny whe#iear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr6aVCN' ~> //Yes, but who can geny whe#hear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9\VCN' ~> //Yes, but who can geny whe mear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9]VCN' ~> //Yes, but who can geny whe lear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9^VCN' ~> //Yes, but who can geny whe kear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9_VCN' ~> //Yes, but who can geny whe jear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9`VCN' ~> //Yes, but who can geny whe iear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4RGr9aVCN' ~> //Yes, but who can geny whe hear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6\VCN' ~> //Yes, but who can geny the#mear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6]VCN' ~> //Yes, but who can geny the#lear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6^VCN' ~> //Yes, but who can geny the#kear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6_VCN' ~> //Yes, but who can geny the#jear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6`VCN' ~> //Yes, but who can geny the#iear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr6aVCN' ~> //Yes, but who can geny the#hear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9\VCN' ~> //Yes, but who can geny the mear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9]VCN' ~> //Yes, but who can geny the lear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9^VCN' ~> //Yes, but who can geny the kear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9_VCN' ~> //Yes, but who can geny the jear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9`VCN' ~> //Yes, but who can geny the iear
[+] Password 'ChVCVYzI1dU9cVg1ukBnO2u4UGr9aVCN' ~> //Yes, but who can geny the hear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6\VCN' ~> //Yes, but who can deny whe#mear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6]VCN' ~> //Yes, but who can deny whe#lear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6^VCN' ~> //Yes, but who can deny whe#kear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6_VCN' ~> //Yes, but who can deny whe#jear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6`VCN' ~> //Yes, but who can deny whe#iear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr6aVCN' ~> //Yes, but who can deny whe#hear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9\VCN' ~> //Yes, but who can deny whe mear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9]VCN' ~> //Yes, but who can deny whe lear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9^VCN' ~> //Yes, but who can deny whe kear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9_VCN' ~> //Yes, but who can deny whe jear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9`VCN' ~> //Yes, but who can deny whe iear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4RGr9aVCN' ~> //Yes, but who can deny whe hear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6\VCN' ~> //Yes, but who can deny the#mear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6]VCN' ~> //Yes, but who can deny the#lear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6^VCN' ~> //Yes, but who can deny the#kear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6_VCN' ~> //Yes, but who can deny the#jear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6`VCN' ~> //Yes, but who can deny the#iear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr6aVCN' ~> //Yes, but who can deny the#hear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9\VCN' ~> //Yes, but who can deny the mear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9]VCN' ~> //Yes, but who can deny the lear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9^VCN' ~> //Yes, but who can deny the kear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9_VCN' ~> //Yes, but who can deny the jear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9`VCN' ~> //Yes, but who can deny the iear
[+] Password 'ChVCVYzI1dU9cVg1ukBqO2u4UGr9aVCN' ~> //Yes, but who can deny the hear
```

Here, we can easily infer that the correct intermediate plaintext is
`//Yes, but who can deny the hear` and hence the correct intermediate password is 
`ChVCVYzI1dU9cVg1ukBqO2u4UGr9aVCN`.

By doing this we can recover the correct password that decrypts the next payload correctly:
```
ChVCVYzI1dU9cVg1ukBqO2u4UGr9aVCNWHpMUuYDLmDO22cdhXq3oqp8jmKBHUWI
```

The script that cracks the password can be found here: [beelogin_crack.py](./beelogin_crack.py).


### Stage #2 Payload

The next payload ([stage_2.js](./stage_2.js)) looks like this:
```
//Yes, but who can deny the heart that is yearning?
//Affirmative!
//Uh-oh!
//This.
//At least you're out in the world. You must meet girls.
//Why is yogurt night so difficult?!

[..... TRUNCATED FOR BREVITY .....]

//My sweater is Ralph Lauren, and I have no pants.
//Here's your change. Have a great afternoon! Can I help who's next?
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+ .........
```

As we can see, payload is heavily obfuscated. However. this is a well known form of obfuscation,
so we can quickly deobfuscate it using [this](https://www.dcode.fr/javascript-unobfuscator) tool.
The deobfuscated payload is shown in [stage_2_deobf.js](./stage_2_deobf.js). This code is identiycal
to the first payload, except that the base64 strings that contain the payload are different.
Therefore, we reuse [beelogin_crack.py](./beelogin_crack.py) to recover the new password:
```
UQ8yjqwAkoVGm7VDdhLoDk0Q75eKKhTfXXke36UFdtKAi0etRZ3DoHPz7NxJPgHl
```

### Stage #3 Payload

The next payload ([stage_3.js](./stage_3.js)) looks like this:
```
//He's not bothering anybody.
//Why would you question anything? We're bees.
//But you've never been a police officer, have you?
//Up on a float, surrounded by flowers, crowds cheering.
//According to all known laws of aviation, there is no way a bee should be able to fly.

[..... TRUNCATED FOR BREVITY .....]

//This is insane, Barry!
//Can I get help with the Sky Mall magazine? I'd like to order the talking inflatable nose and ear hair trimmer.
//Listen, you better go 'cause we're really busy working.
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[]) ....

```

We reuse the same [tool](https://www.dcode.fr/javascript-unobfuscator) to get the deobfuscated
version:
```javascript
    function anonymous( ) { alert("I_h4d_v1rtU411y_n0_r3h34rs4l_f0r_th4t@flare-on.com") }
```

We can also type the whole password on the 4th edit:
```
ChVCVYzI1dU9cVg1ukBqO2u4UGr9aVCNWHpMUuYDLmDO22cdhXq3oqp8jmKBHUWI;UQ8yjqwAkoVGm7VDdhLoDk0Q75eKKhTfXXke36UFdtKAi0etRZ3DoHPz7NxJPgHl
```

Which gives us the flag: `I_h4d_v1rtU411y_n0_r3h34rs4l_f0r_th4t@flare-on.com`

___
