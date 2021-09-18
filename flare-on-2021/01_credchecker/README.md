## Flare-On 2021 - #1 Credchecker
___

### Description: 

*Welcome to Flare-On 8! This challenge surves as your tutorial mission for the epic quest you are about to emark upon. Reverse engineer the Javascript code to determine the correct username and password the web page is looking for and it will show you the flag. Enter that flag here to advance to the next stage. All flags will be in the format of valid email addresses and all end with "@flare-on.com".*

`7-zip password: flare`

___

### Solution:


If we open the [admin.html](./admin.html) file, we can see the how the password is verified:
```javascript
var form = document.getElementById("credform");
var username = document.getElementById("usrname");
var password = document.getElementById("psw");
var info = document.getElementById("infolabel");
var checkbtn = document.getElementById("checkbtn");
var encoded_key = "P1xNFigYIh0BGAofD1o5RSlXeRU2JiQQSSgCRAJdOw=="

function dataEntered() {
	if (username.value.length > 0 && password.value.length > 0) {
		checkbtn.disabled = false;
	} else {
		checkbtn.disabled = true;
	}
}

function checkCreds() {
	if (username.value == "Admin" && atob(password.value) == "goldenticket") 
	{
		var key = atob(encoded_key);
		var flag = "";
		for (let i = 0; i < key.length; i++)
		{
			flag += String.fromCharCode(key.charCodeAt(i) ^ password.value.charCodeAt(i % password.value.length))
		}
		document.getElementById("banner").style.display = "none";
		document.getElementById("formdiv").style.display = "none";
		document.getElementById("message").style.display = "none";
		document.getElementById("final_flag").innerText = flag;
		document.getElementById("winner").style.display = "block";
	}
	else
	{
		document.getElementById("message").style.display = "block";
	}
}
```

All we have to do to get the flag, is to run the following python commands:
```python
import base64

key = base64.b64decode("P1xNFigYIh0BGAofD1o5RSlXeRU2JiQQSSgCRAJdOw==")
pw = base64.b64encode(b"goldenticket")
flag = ''.join(chr(key[i] ^ pw[i % len(pw)]) for i in range(len(key)))
```

Which gives us the flag: `enter_the_funhouse@flare-on.com`

___

