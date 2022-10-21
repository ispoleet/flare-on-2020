using System;
using System.IO;

namespace BackdoorDecryptor
{
	class Program
	{
		static void Main(string[] args)
        {
            Console.WriteLine("Flare On 9 - Backdoor decryptor started.");

			// Decrypt Layer #1.
			byte[] buff1 = DecryptLayer1.Decrypt(
				@"C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.exe"
			);
			File.WriteAllBytes(
				@"C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.exe",
				buff1
			);

			// Uncomment the line below, to get the correct stack trace
			// (we need this for the decryption key generation).
			// StackTrace.GetStackTrace(
			//		@"C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.exe");

			// Decrypt Layer #2.
			byte[] buff2 = DecryptLayer2.Decrypt(
				@"C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.exe"
			);

			File.WriteAllBytes(
				@"C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.all.exe",
				buff2);

			Console.WriteLine("Program finished! Bye bye :)");
		}
    }
}
