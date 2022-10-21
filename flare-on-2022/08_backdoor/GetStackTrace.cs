using System;
using System.Reflection;


namespace BackdoorDecryptor
{
	public class StackTrace
	{
		/** Uses reflection to invoke flare_57() and grab the result (stack trace).*/
		public static void GetStackTrace(string backdoor_filename_patched)
		{
			string version = AppDomain.CurrentDomain.SetupInformation.TargetFrameworkName;
			Console.WriteLine("[+] Current .NET version (must be 4.7.2): {0}", version);

			Console.WriteLine("[+] Getting Stack Trace from: {0}", backdoor_filename_patched);
			var asm = Assembly.LoadFile(backdoor_filename_patched);
	    
			// Locate method flare_57 and invoke it using reflection to see the result.
			Type type = asm.GetType("FlareOn.Backdoor.FLARE14");
			MethodInfo methodInfo = type.GetMethod("flare_57");
			object[] parametersArray = new object[] { };

			object result = methodInfo.Invoke(methodInfo, parametersArray);
			Console.WriteLine("[+] flare_57() return value: {0}", result);
		}
	}
}
/*
Flare On 9 - Backdoor decryptor started.
[+] Current .NET version (must be 4.7.2): .NETCoreApp,Version=v4.7.2
[+] Getting Stack Trace from: C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.exe
[+] flare_57() return value: System.Object InvokeMethod(System.Object, System.Object[], System.Signature, Boolean)System.Object Invoke(System.Object, System.Reflection.BindingFlags, System.Reflection.Binder, System.Object[], System.Globalization.CultureInfo)"
 */
