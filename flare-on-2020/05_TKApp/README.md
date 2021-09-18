
## Flare-On 2020 - #5 TKApp
___

### Description: 

*Now you can play Flare-On on your watch! As long as you still have an arm left to put a watch on, or emulate the watch's operating system with sophisticated developer tools.*


`*7zip password: flare`
___

### Solution:


We have to deal with a `*.tpk` file, which is essentially a zip archive:
```
ispo@ispo-glaptop:~/ctf/flare_on/5_TKApp$ file TKApp.tpk 
TKApp.tpk: Zip archive data, at least v2.0 to extract

ispo@ispo-glaptop:~/ctf/flare_on/5_TKApp$ unzip -l TKApp.tpk
Archive:  TKApp.tpk
  Length      Date    Time    Name
---------  ---------- -----   ----
     7944  2020-08-03 15:23   author-signature.xml
        0  2020-08-03 15:23   lib/
     8008  2020-08-03 15:23   signature1.xml
      920  2020-08-03 14:11   tizen-manifest.xml
     4316  2020-08-03 15:23   TKApp.deps.json
    18432  2018-05-04 10:58   bin/ExifLib.Standard.dll
    75264  2019-10-30 16:57   bin/Tizen.Wearable.CircularUI.Forms.dll
   119808  2019-10-30 16:57   bin/Tizen.Wearable.CircularUI.Forms.Renderer.dll
   111616  2020-08-03 15:23   bin/TKApp.dll
   906360  2019-08-17 02:11   bin/Xamarin.Forms.Core.dll
    17024  2019-08-17 02:11   bin/Xamarin.Forms.Platform.dll
   312456  2019-08-17 02:11   bin/Xamarin.Forms.Platform.Tizen.dll
   103544  2019-08-17 02:11   bin/Xamarin.Forms.Xaml.dll
   217395  2020-06-22 17:30   res/gallery/01.jpg
   178289  2020-07-03 17:24   res/gallery/02.jpg
    92022  2020-06-22 16:48   res/gallery/03.jpg
   161177  2020-06-22 17:40   res/gallery/04.jpg
   129115  2020-06-22 18:33   res/gallery/05.jpg
      392  2016-08-08 05:18   res/img/img.png
    87301  2020-07-07 13:52   res/img/tiger1.png
    79109  2020-07-07 13:47   res/img/tiger2.png
      239  2016-08-08 05:18   res/img/todo.png
    87942  2020-07-07 14:30   shared/res/TKApp.png
---------                     -------
  2718673                     23 files
```

The file that we are interested in analyzing is `bin/TKApp.dll`, which is actually a .NET
application. To analyze this file we use [dnspy](https://github.com/0xd4d/dnSpy).

The code that gives us the flag (as an image) is function `GetImage` from `MainPage` class.
```C#
// Token: 0x06000027 RID: 39 RVA: 0x00002640 File Offset: 0x00000840
private bool GetImage(object sender, EventArgs e)
{
	if (string.IsNullOrEmpty(App.Password) || string.IsNullOrEmpty(App.Note) || string.IsNullOrEmpty(App.Step) || string.IsNullOrEmpty(App.Desc))
	{
		this.btn.Source = "img/tiger1.png";
		this.btn.Clicked -= this.Clicked;
		return false;
	}
	string text = new string(new char[]
	{
		App.Desc[2],
		App.Password[6],
		App.Password[4],
		App.Note[4],
		App.Note[0],
		App.Note[17],
		App.Note[18],
		App.Note[16],
		App.Note[11],
		App.Note[13],
		App.Note[12],
		App.Note[15],
		App.Step[4],
		App.Password[6],
		App.Desc[1],
		App.Password[2],
		App.Password[2],
		App.Password[4],
		App.Note[18],
		App.Step[2],
		App.Password[4],
		App.Note[5],
		App.Note[4],
		App.Desc[0],
		App.Desc[3],
		App.Note[15],
		App.Note[8],
		App.Desc[4],
		App.Desc[3],
		App.Note[4],
		App.Step[2],
		App.Note[13],
		App.Note[18],
		App.Note[18],
		App.Note[8],
		App.Note[4],
		App.Password[0],
		App.Password[7],
		App.Note[0],
		App.Password[4],
		App.Note[11],
		App.Password[6],
		App.Password[4],
		App.Desc[4],
		App.Desc[3]
	});
	byte[] key = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(text));
	byte[] bytes = Encoding.ASCII.GetBytes("NoSaltOfTheEarth");
	try
	{
		App.ImgData = Convert.FromBase64String(Util.GetString(Runtime.Runtime_dll, key, bytes));
		return true;
	}
	catch (Exception ex)
	{
		Toast.DisplayText("Failed: " + ex.Message, 1000);
	}
	return false;
}
```

To get the flag we need `4` variables: `App.Password`, `App.Note`, `App.Step` and `App.Desc`.
Once we know all these variables the flag is decrypted, then base64 decoded and it is stored into
a file. To get the `password`, program performs an 1-byte XOR with a constant string.
```c#
// TKApp.TKData
// Token: 0x04000014 RID: 20
public static byte[] Password = new byte[]
{
	62,
	38,
	63,
	63,
	54,
	39,
	59,
	50,
	39
};

// TKApp.UnlockPage
// Token: 0x0600004D RID: 77 RVA: 0x0000349D File Offset: 0x0000169D
private bool IsPasswordCorrect(string password)
{
	return password == Util.Decode(TKData.Password);
}

// TKApp.Util
// Token: 0x06000053 RID: 83 RVA: 0x00003750 File Offset: 0x00001950
public static string Decode(byte[] e)
{
	string text = "";
	foreach (byte b in e)
	{
		text += Convert.ToChar((int)(b ^ 83)).ToString();
	}
	return text;
}

```

The initial password is `>&??6';2'` and after the XOR, it becomes `mullethat`.
To get the `description`, we read the metadata from `05.jpg` image:
```c#
// TKApp.GalleryPage
// Token: 0x06000016 RID: 22 RVA: 0x000022C4 File Offset: 0x000004C4
private void IndexPage_CurrentPageChanged(object sender, EventArgs e)
{
	if (base.Children.IndexOf(base.CurrentPage) == 4)
	{
		using (ExifReader exifReader = new ExifReader(Path.Combine(Application.Current.DirectoryInfo.Resource, "gallery", "05.jpg")))
		{
			string desc;
			if (exifReader.GetTagValue<string>(ExifTags.ImageDescription, out desc))
			{
				App.Desc = desc;
			}
			return;
		}
	}
	App.Desc = "";
}
```
 
To read the image metadata we use [metapicz](http://metapicz.com/) online tool:
```
ImageDescription	water
```

Therefore `desc` is `water`.
To get the value of `step`, program loads the value of `its` metadata variable:
```c#
// TKApp.MainPage
// Token: 0x06000023 RID: 35 RVA: 0x000024C0 File Offset: 0x000006C0
private void PedDataUpdate(object sender, PedometerDataUpdatedEventArgs e)
{
	if (e.StepCount > 50U && string.IsNullOrEmpty(App.Step))
	{
		App.Step = Application.Current.ApplicationInfo.Metadata["its"];
	}

/* ... */
```

The metadata are defined in `tizen-manifest.xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest package="com.flare-on.TKApp" version="1.0.0" api-version="5.5" xmlns="http://tizen.org/ns/packages">
        <metadata key="http://tizen.org/metadata/prefer_dotnet_aot" value="true" />
        <metadata key="its" value="magic" />
</manifest>
```

Therefore, `step` is initialized to `magic`. Finally, to get the `notes`, we look at the `SetupList` function:
```c#
// TKApp.TodoPage
// Token: 0x0600003E RID: 62 RVA: 0x000030B8 File Offset: 0x000012B8
private void SetupList()
{
	List<TodoPage.Todo> list = new List<TodoPage.Todo>();
	if (!this.isHome)
	{
		list.Add(new TodoPage.Todo("go home", "and enable GPS", false));
	}
	else
	{
		TodoPage.Todo[] collection = new TodoPage.Todo[]
		{
			new TodoPage.Todo("hang out in tiger cage", "and survive", true),
			new TodoPage.Todo("unload Walmart truck", "keep steaks for dinner", false),
			new TodoPage.Todo("yell at staff", "maybe fire someone", false),
			new TodoPage.Todo("say no to drugs", "unless it's a drinking day", false),
			new TodoPage.Todo("listen to some tunes", "https://youtu.be/kTmZnQOfAF8", true)
		};
		list.AddRange(collection);
	}
	List<TodoPage.Todo> list2 = new List<TodoPage.Todo>();
	foreach (TodoPage.Todo todo in list)
	{
		if (!todo.Done)
		{
			list2.Add(todo);
		}
	}
	this.mylist.ItemsSource = list2;
	App.Note = list2[0].Note;
}
```

Then we go a step back and we look what values are passed as `.Note` into the `Todo` function:
```c#
// Token: 0x0200000B RID: 11
public class Todo
{
	// Token: 0x0600004A RID: 74 RVA: 0x00003439 File Offset: 0x00001639
	public Todo(string Name, string Note, bool Done)
	{
		this.Name = Name;
		this.Note = Note;
		this.Done = Done;
	}
}
```

The set of all possibles values are `and enable GPS`, `and survive`, `keep steaks for dinner`,
`maybe fire someone`, `unless it's a drinking day` and `https://youtu.be/kTmZnQOfAF8`.
(this set is actually smaller as we only select the first item: `App.Note = list2[0].Note`).
To figure out the correct value of `note` we look into `PedDataUpdate` function:
```c#
// TKApp.MainPage
// Token: 0x06000023 RID: 35 RVA: 0x000024C0 File Offset: 0x000006C0
private void PedDataUpdate(object sender, PedometerDataUpdatedEventArgs e)
{
	if (e.StepCount > 50U && string.IsNullOrEmpty(App.Step))
	{
		App.Step = Application.Current.ApplicationInfo.Metadata["its"];
	}
	if (!string.IsNullOrEmpty(App.Password) && !string.IsNullOrEmpty(App.Note) && !string.IsNullOrEmpty(App.Step) && !string.IsNullOrEmpty(App.Desc))
	{
		HashAlgorithm hashAlgorithm = SHA256.Create();
		byte[] bytes = Encoding.ASCII.GetBytes(App.Password + App.Note + App.Step + App.Desc);
		byte[] first = hashAlgorithm.ComputeHash(bytes);
		byte[] second = new byte[]
		{
			50,
			148,
			76,
			233,
			110,
			199,
			228,
			72,
			114,
			227,
			78,
			138,
			93,
			189,
			189,
			147,
			159,
			70,
			66,
			223,
			123,
			137,
			44,
			73,
			101,
			235,
			129,
			16,
			181,
			139,
			104,
			56
		};
		if (first.SequenceEqual(second))
		{
			this.btn.Source = "img/tiger2.png";
			this.btn.Clicked += this.Clicked;
			return;
		}
		this.btn.Source = "img/tiger1.png";
		this.btn.Clicked -= this.Clicked;
	}
}
```

That is, for each possible value for `note` we calculate the value of `App.Password + App.Note + App.Step + App.Desc`
and we calculate its SHA256 value. If value matches with:
```
32944CE96EC7E44872E34E8A5DBDBD939F4642DF7B892C4965EB8110B58B6838
```

Then we have found the value. The value that matches is: `keep steaks for dinner`.

#### Breaking the code

So far we know all `4` variables we need to decrypt the image:
```
Password: mullethat
Step: magic
Desc: water
Note: keep steaks for dinner
```

We go back into the `GetImage` function:
```C#
// Token: 0x06000027 RID: 39 RVA: 0x00002640 File Offset: 0x00000840
private bool GetImage(object sender, EventArgs e)
{
	if (string.IsNullOrEmpty(App.Password) || string.IsNullOrEmpty(App.Note) || string.IsNullOrEmpty(App.Step) || string.IsNullOrEmpty(App.Desc))
	{
		this.btn.Source = "img/tiger1.png";
		this.btn.Clicked -= this.Clicked;
		return false;
	}
	string text = new string(new char[]
	{
		App.Desc[2],
		App.Password[6],
		App.Password[4],
		App.Note[4],
		App.Note[0],
		App.Note[17],
		App.Note[18],
		App.Note[16],
		App.Note[11],
		App.Note[13],
		App.Note[12],
		App.Note[15],
		App.Step[4],
		App.Password[6],
		App.Desc[1],
		App.Password[2],
		App.Password[2],
		App.Password[4],
		App.Note[18],
		App.Step[2],
		App.Password[4],
		App.Note[5],
		App.Note[4],
		App.Desc[0],
		App.Desc[3],
		App.Note[15],
		App.Note[8],
		App.Desc[4],
		App.Desc[3],
		App.Note[4],
		App.Step[2],
		App.Note[13],
		App.Note[18],
		App.Note[18],
		App.Note[8],
		App.Note[4],
		App.Password[0],
		App.Password[7],
		App.Note[0],
		App.Password[4],
		App.Note[11],
		App.Password[6],
		App.Password[4],
		App.Desc[4],
		App.Desc[3]
	});
	byte[] key = SHA256.Create().ComputeHash(Encoding.ASCII.GetBytes(text));
	byte[] bytes = Encoding.ASCII.GetBytes("NoSaltOfTheEarth");
	try
	{
		App.ImgData = Convert.FromBase64String(Util.GetString(Runtime.Runtime_dll, key, bytes));
		return true;
	}
	catch (Exception ex)
	{
		Toast.DisplayText("Failed: " + ex.Message, 1000);
	}
	return false;
}
```

The value of text is `the kind of challenges we are gonna make here`.
Function `GetString` performs a vanilla Rijndeal decryption (AES):
```c#
// TKApp.Util
// Token: 0x06000052 RID: 82 RVA: 0x00003694 File Offset: 0x00001894
public static string GetString(byte[] cipherText, byte[] Key, byte[] IV)
{
	string result = null;
	using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
	{
		rijndaelManaged.Key = Key;
		rijndaelManaged.IV = IV;
		ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
		using (MemoryStream memoryStream = new MemoryStream(cipherText))
		{
			using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, 0))
			{
				using (StreamReader streamReader = new StreamReader(cryptoStream))
				{
					result = streamReader.ReadToEnd();
				}
			}
		}
	}
	return result;
}
```

That is, code performs an AES-128 decrpytion on `Runtime.Runtime_dll` ciphertext using 
`the kind of challenges we are gonna make here` as key and `NoSaltOfTheEarth` as IV.
The `Runtime_dll` object is declared as a resource:
```c#
// Token: 0x1700000F RID: 15
// (get) Token: 0x06000035 RID: 53 RVA: 0x00002EC3 File Offset: 0x000010C3
internal static byte[] Runtime_dll
{
	get
	{
		return (byte[])Runtime.ResourceManager.GetObject("Runtime.dll", Runtime.resourceCulture);
	}
}
```

Below are the first bytes of `Runtime.dll` resource:
```c#
new byte[] {
	0x36, 0x9B, 0x51, 0x94, 0xAA, 0x87, 0x45, 0x7E, 0x6E, 0x0D, 0x46, 0x48, 0x13, 0x84, 0x83, 0xE5,
	0xD2, 0xE4, 0x18, 0xAC, 0x94, 0xE1, 0x0A, 0xEA, 0x55, 0x3A, 0x5B, 0x22, 0x66, 0xC8, 0x3A, 0xE1,
	0x83, 0xB6, 0xE4, 0xA0, 0xB9, 0xBC, 0x3D, 0x7E, 0x76, 0xA1, 0xCD, 0xAC, 0xDE, 0x93, 0x71, 0xD9,
	0x96, 0xB9, 0x83, 0x6F, 0xBB, 0xD6, 0x35, 0x1B, 0x29, 0x5E, 0xC0, 0x44, 0x36, 0x30, 0x64, 0x89,
	0xA9, 0x6A, 0x7F, 0x97, 0xBE, 0x0C, 0xFC, 0xEA, 0x64, 0x2B, 0x01, 0x04, 0xF4, 0xF1, 0x49, 0x43,
	0x28, 0xCA, 0x6F, 0x02, 0xFE, 0x3F, 0xA0, 0x1A, 0x2F, 0x45 /* ..... */
};
```

After decryption we get a nice base64 string: `/9j/4AAQSkZJRgABAQEBLAEsAAD/4R2qRXhpZgAASUkqAAgAAAAFABoBBQABAAAA...`
which decodes in a JPEG image.

![alt text](./flag.jpeg)


Which give us the flag: `n3ver_go1ng_to_recov3r@flare-on.com`

The code that deciphers the image is here: [tkapp_crack.py](./tkapp_crack.py):

___

