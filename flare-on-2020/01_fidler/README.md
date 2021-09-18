
## Flare-On 2020 - #1 Fidler
___

### Description: 

*Welcome to the Seventh Flare-On Challenge!*

*This is a simple game. Win it by any means necessary and the victory screen will reveal the flag. Enter the flag here on this site to score and move on to the next level.*

*This challenge is written in Python and is distributed as a runnable EXE and matching source code for your convenience. You can run the source code directly on any Python platform with PyGame if you would prefer.*

`7zip password: flare`

___


### Solution:


Open `fidler.py` and look for `decode_flag`:
```python
def decode_flag(frob):
    last_value = frob
    encoded_flag = [1135, 1038, 1126, 1028, 1117, 1071, 1094, 1077, 1121, 1087, 1110, 1092, 1072, 1095, 1090, 1027,
                    1127, 1040, 1137, 1030, 1127, 1099, 1062, 1101, 1123, 1027, 1136, 1054]
    decoded_flag = []

    for i in range(len(encoded_flag)):
        c = encoded_flag[i]
        val = (c - ((i%2)*1 + (i%3)*2)) ^ last_value
        decoded_flag.append(val)
        last_value = c

    return ''.join([chr(x) for x in decoded_flag])
```

As the name suggest, function decodes the flag. The only problem is that we don't know the value of
`frob`. We can calculate the value from `game_screen` (which invokes `victory_screen`,
which invokes `decode_flag`):
```python
def game_screen():
    # ...
    while not done:
        target_amount = (2**36) + (2**35)
        if current_coins > (target_amount - 2**20):
            while current_coins >= (target_amount + 2**20):
                current_coins -= 2**20
            victory_screen(int(current_coins / 10**8))


def victory_screen(token):
    # ...
    flag_content_label.change_text(decode_flag(token))
```

Therefore:
```
>>>  frob = (2**36 + 2**35 - 2**20) / 10**8
1030

>>>  print decode_flag(1030)
idle_with_kitty@flare-on.com
```

Which give us the flag: `idle_with_kitty@flare-on.com`

___

