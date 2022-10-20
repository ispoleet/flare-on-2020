## Flare-On 2022 - #7 anode
___

### Description: 

*You've made it so far! I can't believe it! And so many people are ahead of you!*

`7-zip password: flare`
___

### Solution:

This challenge contains a huge (**55MB**) nodejs binary that implements a whole
javascript engine. However, at the bottom of the file there is some javascript code
(the full code is in [anode.js](./anode.js)):
```javascript
readline.question(`Enter flag: `, flag => {
  readline.close();
  if (flag.length !== 44) {
    console.log("Try again.");
    process.exit(0);
  }
  var b = [];
  for (var i = 0; i < flag.length; i++) {
    b.push(flag.charCodeAt(i));
  }

  // something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }

  var state = 1337;
  while (true) {
    state ^= Math.floor(Math.random() * (2**30));
    switch (state) {
      case 306211:
        if (Math.random() < 0.5) {
          b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + Math.floor(Math.random() * 256);
          b[30] &= 0xFF;
        } else {
          b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225;
          b[26] &= 0xFF;
        }
        state = 868071080;
        continue;
      case 311489:
        if (Math.random() < 0.5) {
          b[10] -= b[32] + b[1] + b[20] + b[30] + b[23] + b[9] + 115;
          b[10] &= 0xFF;
        } else {
          b[7] ^= (b[18] + b[14] + b[11] + b[25] + b[31] + b[21] + 19) & 0xFF;
        }
        state = 22167546;
        continue;

       /*
        *
        * More case statements.
        * Way more case statements.
        * Waaaaaaaaaay more case statements.
        *
        */

      case 1071664271:
        if (Math.random() < 0.5) {
          b[17] += b[0] + b[35] + b[12] + b[42] + b[14] + b[3] + 8;
          b[17] &= 0xFF;
        } else {
          b[18] ^= (b[20] + b[23] + b[6] + b[12] + b[4] + b[25] + Math.floor(Math.random() * 256)) & 0xFF;
        }
        state = 175099911;
        continue;
      case 1071767211:
        if (Math.random() < 0.5) {
          b[30] ^= (b[42] + b[9] + b[2] + b[36] + b[12] + b[16] + 241) & 0xFF;
        } else {
          b[20] ^= (b[41] + b[2] + b[40] + b[21] + b[36] + b[17] + 37) & 0xFF;
        }
        state = 109621765;
        continue;
      default:
        console.log("uh-oh, math.random() is too random...");
        process.exit(0);
    }
    break;
  }

  var target = [106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74, 139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153, 223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76];
  if (b.every((x,i) => x === target[i])) {
    console.log('Congrats!');
  } else {
    console.log('Try again.');
  }
});        
```

It is pretty easy to understand this code: It first copies flag into array `b` then there is a huge
switch statement (which is actually a control flow flattening obfuscation) that makes some
invertible transformations to `b` and finally comapares it with a constant array `target`.

However, the transformations do not seem to be deterministic:
```javascript
case 306211:
    if (Math.random() < 0.5) {
      b[30] -= b[34] + b[23] + b[5] + b[37] + b[33] + b[12] + Math.floor(Math.random() * 256);
      b[30] &= 0xFF;
    } else {
      b[26] -= b[24] + b[41] + b[13] + b[43] + b[6] + b[30] + 225;
      b[26] &= 0xFF;
    }
    state = 868071080;
    continue;
```

Even worse, there is something weird here:
```javascript
  // something strange is happening...
  if (1n) {
    console.log("uh-oh, math is too correct...");
    process.exit(0);
  }
```

The only explanation here is that math functions are patched in the binary in order to
return different than normal values. Finding where this patching was made was hard as the binary
is huge, so I followed a black-box approach.

I observed that if I modify the javascript in the binary it will still be executed without
crashing, as long I do not modify the binary size. Since the computations are deterministic
(the correct flag should be correct every time), despite the `Math.random()`, I replaced all
transformations to `b` with `console.log` statements:
```javascript
  var state = 1337;
  while (true) {
    state ^= Math.floor(Math.random() * (2**30));
    switch (state) {
      case 306211:
        if (Math.random() < 0.5) {
console.log("stmt #00000 ~> " + Math.floor(Math.random() * 256));                                 
          b[30] &= 0xFF;
        } else {
console.log("stmt #00001");                                           
          b[26] &= 0xFF;
        }
        state = 868071080;
        continue;
      case 311489:
        if (Math.random() < 0.5) {
console.log("stmt #00002");                                          
          b[10] &= 0xFF;
        } else {
console.log("stmt #00003");                                                   
        }
        state = 22167546;
        continue;
       /* ....*/
```

Then I run the patched program and got a trace with the order of the transformations
along with the results of `Math.floor(Math.random() * 256))`
(the full trace is in [trace.txt](./trace.txt)):
```
C:\Users\ispol\Dropbox\for_share>anode.patched.exe
Enter flag: 12345678901234567890123456789012345678901234
stmt #01935
stmt #00907
stmt #00354
stmt #01821 ~> 245
stmt #01125
stmt #00767
stmt #00547
....
```

Every time I run the program I was getting the same output (as expected). Here we know that the 
first transformation is **#1935**, the second is **#907** and so on:
```
#1935 ~>  b[29] -= b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7;
#907  ~>  b[39] += b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79;
```

Once we know the exact order of the equation along with the numbers returned by `Math.random()`
we can unflatten the program and write the equations in the correct order.

#### Cracking the Code

As mentioned earlier, it is easy to observe that all transformations are invertible (they consist
of only `+`, `-` and `^` operations), so we can initialized `b` to the value of `target` and
run the equations in the reverse order:
```python
b = [ 106, 196, 106, 178, 174, 102, 31, 91, 66, 255, 86, 196, 74,
   139, 219, 166, 106, 4, 211, 68, 227, 72, 156, 38, 239, 153,
   223, 225, 73, 171, 51, 4, 234, 50, 207, 82, 18, 111, 180, 212, 81, 189, 73, 76]

b[39] -= b[18] + b[16] + b[8] + b[19] + b[5] + b[23] + 36; b[39] &= 0xFF;
b[22] -= b[16] + b[18] + b[7] + b[23] + b[1] + b[27] + 50; b[22] &= 0xFF;
# ....
b[39] -= b[34] + b[2] + b[1] + b[43] + b[20] + b[9] + 79; b[39] &= 0xFF;
b[29] += b[37] + b[23] + b[22] + b[24] + b[26] + b[10] + 7; b[29] &= 0xFF;

flag = ''.join([chr(a) for a in b])
```

The full script is in [reversed_equations_auto_gen.py](./reversed_equations_auto_gen.py)

The script that generates the reversed equations can be found in
[anode_equ_gen.py](./anode_equ_gen.py).

We run the script and we get the flag: `n0t_ju5t_A_j4vaSCriP7_ch4l1eng3@flare-on.com`
___
