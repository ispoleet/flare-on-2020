using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace BackdoorDecryptor {
	public class DecryptLayer2
	{
		// All the encrypted PE Section names in the backdoored binary.
		public static List<string>PESectionNames = new List<string>
		{
			"5aeb2b97", "8de5507b", "0651f80b", "7135726c", "77c01ab2", "4f0f2ca3", "30b905e5",
			"f8a2493f", "846fcbb2", "5ca8a517", "80761762", "305a002f", "1b8e2238", "310d4de0",
			"31d82380", "db08afea", "977deaed", "96c576e4", "69991a3e", "94957fff", "ffc58f78",
			"ee6d9a21", "b1c8119c", "30752c49", "74fbaf68", "326aa956", "719ee568", "becb82d3",
			"a4691056", "b3650258", "689d7525", "f9a758d3", "1aa22d63", "d787bb6b", "33d51cd2",
			"794ac846", "7cddb7c1", "27086010", "344f2938", "89b957e3", "cc80b00c", "4a0fb136",
			"85b3a7dd", "892fac73", "ede0bad0", "3460378b", "81e1a476", "710b11bc", "f965be73",
			"0686a47b", "4ea4cf8d", "699fdcf2", "a537f738", "9181748d", "2fad6d86", "c4493ff5",
			"520c2390", "8d3a199f", "e530c010", "7c5ccd91", "82b8dfa1", "8a966e19", "538fcc69",
			"0e5cf5d9", "edd1976b", "4951e547", "11d539d6", "37875be2", "c61192c7", "e712183a"
		};

		/** Gets all encrypted methods from backdoor binary (using reflection). */
		public static Dictionary<String, MethodInfo> GetEncryptedMethods(Assembly asm)
		{
			var encryptedMethods = new Dictionary<String, MethodInfo>();

			foreach (var type in asm.GetTypes())
			{
				Console.WriteLine("[+] Checking class: {0}", type.FullName);

				if (type.FullName.StartsWith("FlareOn.Backdoor.FLARE") ||
					type.FullName.StartsWith("FlareOn.Backdoor.Program"))
				{
					foreach (var method in type.GetMethods())
					{
						if (method.Name.StartsWith("flared_"))
						{
							Console.WriteLine("[+]    Encrypted method found: {0}", method.Name);
							encryptedMethods[method.Name] = method;
						}
					}
				}
			}

			return encryptedMethods;
		}

		/** Generates a hash (used as decryption key) from a MethodInfo. */
		public static string GenerateHash(MethodInfo methodInfo)
		{
			// This function is flared_66() as it is.
			Console.WriteLine("[+] Generating hash from MethodInfo for: {0}",
							  methodInfo.Name);
			string text = "";
			string text2 = "";
			System.Reflection.MethodBody methodBody = methodInfo.GetMethodBody();
			byte[] bytes = Encoding.ASCII.GetBytes(methodInfo.Attributes.ToString());
			byte[] bytes2 = Encoding.ASCII.GetBytes(methodInfo.ReturnType.ToString());
			byte[] bytes3 = Encoding.ASCII.GetBytes(methodInfo.CallingConvention.ToString());
			foreach (ParameterInfo parameterInfo in methodInfo.GetParameters())
			{
				string str = text2;
				Type parameterType = parameterInfo.ParameterType;
				text2 = str + ((parameterType != null) ? parameterType.ToString() : null);
			}
			byte[] bytes4 = Encoding.ASCII.GetBytes(methodBody.MaxStackSize.ToString());
			byte[] bytes5 = BitConverter.GetBytes(methodBody.GetILAsByteArray().Length);
			foreach (LocalVariableInfo localVariableInfo in methodBody.LocalVariables)
			{
				string str2 = text;
				Type localType = localVariableInfo.LocalType;
				text = str2 + ((localType != null) ? localType.ToString() : null);
			}
			byte[] bytes6 = Encoding.ASCII.GetBytes(text);
			byte[] bytes7 = Encoding.ASCII.GetBytes(text2);

			Console.WriteLine("[+] Value of bytes : {0}", System.Text.Encoding.UTF8.GetString(bytes));
			Console.WriteLine("[+] Value of bytes2: {0}", System.Text.Encoding.UTF8.GetString(bytes2));
			Console.WriteLine("[+] Value of bytes3: {0}", System.Text.Encoding.UTF8.GetString(bytes3));
			Console.WriteLine("[+] Value of bytes4: {0}", System.Text.Encoding.UTF8.GetString(bytes4));
			Console.WriteLine("[+] Value of bytes5: {0}", BitConverter.ToString(bytes5));
			Console.WriteLine("[+] Value of bytes6: {0}", System.Text.Encoding.UTF8.GetString(bytes6));
			Console.WriteLine("[+] Value of bytes7: {0}", System.Text.Encoding.UTF8.GetString(bytes7));

			IncrementalHash incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
			incrementalHash.AppendData(bytes5);
			incrementalHash.AppendData(bytes);
			incrementalHash.AppendData(bytes2);
			incrementalHash.AppendData(bytes4);
			incrementalHash.AppendData(bytes6);
			incrementalHash.AppendData(bytes7);
			incrementalHash.AppendData(bytes3);

			byte[] hashAndReset = incrementalHash.GetHashAndReset();
			StringBuilder stringBuilder = new StringBuilder(hashAndReset.Length * 2);
			for (int j = 0; j < hashAndReset.Length; j++)
			{
				stringBuilder.Append(hashAndReset[j].ToString("x2"));
			}

			Console.WriteLine("[+] Final SHA256: {0}", stringBuilder.ToString());

			return stringBuilder.ToString();
		}

		/** Loads the contents of PE Section.*/
		public static byte[] GetPESectionContents(string hash)
		{
			Console.WriteLine("[+] Loading PE Section: {0}", hash.Substring(0, 8));

			return File.ReadAllBytes(@"C:\Users\ispol\Desktop\reversing\pe_sections\" +
									 hash.Substring(0, 8));
		}

		/** Implements a vanilla RC4 decryption. */
		public static byte[] RC4Decrypt(byte[] p, byte[] d)
		{
			// This function is flared_47() as it is.
			int[] array = new int[256];
			int[] array2 = new int[256];
			byte[] array3 = new byte[d.Length];
			int i;

			for (i = 0; i < 256; i++)
			{
				array[i] = (int)p[i % p.Length];
				array2[i] = i;
			}
			
			int num;
			for (i = (num = 0); i < 256; i++)
			{
				num = (num + array2[i] + array[i]) % 256;
				int num2 = array2[i];
				array2[i] = array2[num];
				array2[num] = num2;
			}
			
			int num3;
			num = (num3 = (i = 0));
			while (i < d.Length)
			{
				num3++;
				num3 %= 256;
				num += array2[num3];
				num %= 256;
				int num2 = array2[num3];
				array2[num3] = array2[num];
				array2[num] = num2;
				int num4 = array2[(array2[num3] + array2[num]) % 256];
				array3[i] = (byte)((int)d[i] ^ num4);
				i++;
			}
			
			return array3;
		}

		/** Converts a byte array to an int. */
		public static int ByteArrToInt(byte[] b, int o)
		{
			// This function is flared_68() as it is.
			int num = (int)b[o + 3] * 16777216;
			num += (int)b[o + 2] * 65536;
			num += (int)b[o + 1] * 256;
			return num + (int)b[o];
		}

		/** Applies code rellocations to the decrypted function. */
		public static byte[] DoCodeRellocationsV2(byte[] b)
		{
			// Do what flared_67() does, but simpler
			// (do not do any relocations; just patch the tokens).
			int j = 0;
			while (j < b.Length)
			{
				bool flag = b[j] == 254;
				uint key;

				if (flag)
				{
					key = 65024U + (uint)b[j + 1];
					j++;
				}
				else
				{
					key = (uint)b[j];
				}
				int ot = BackdoorConstants.dictionary[key];
				j++;
				switch (ot)
				{
					case 1:
						{
							uint num = (uint)ByteArrToInt(b, j);
							num ^= 2727913149U;
							int tokenFor = (int)num;
							b[j] = (byte)tokenFor;
							b[j + 1] = (byte)(tokenFor >> 8);
							b[j + 2] = (byte)(tokenFor >> 16);
							b[j + 3] = (byte)(tokenFor >> 24);
							j += 4;
							break;
						}
					case 2:
					case 4:
						j++;
						break;
					case 3:
					case 6:
						j += 4;
						break;
					case 5:
						j += 2;
						break;
					case 7:
						j += 8;
						break;
					case 8:
						j += 4 + ByteArrToInt(b, j) * 4;
						break;
				}
			}

			return b;
		}

		/** Searches for an IL pattern into `buff` and overwrittes it. */
		static void PatchCodeToFile(byte[] buff, byte[] il_pattern, List<byte> new_bytecode)
		{
			int matched_index = 0;

			foreach (var idx in DecryptLayer1.FindAll(buff, il_pattern))
			{
				Console.WriteLine("[+] Offset found: 0x{0:X}", idx);
				matched_index = idx;
			}

			if (matched_index == 0)
            {
				throw new Exception("Cannot find IL pattern!");
			}

			for (int i = 0; i < new_bytecode.Count; ++i)
			{
				buff[matched_index + i] = new_bytecode[i];
			}
		}

		/** Applies the 2nd layer of decryption to the backdoor. */
		public static byte[] Decrypt(string backdoor_filename_patched)
		{
			Console.WriteLine("[+] Applying 2nd layer of decryption to: {0}",
							  backdoor_filename_patched);

			var asm = Assembly.LoadFile(backdoor_filename_patched);
			byte[] buff = File.ReadAllBytes(backdoor_filename_patched);

			// Decrypt every encrypted function.
			foreach (KeyValuePair<string, MethodInfo> keyValuePair in GetEncryptedMethods(asm))
			{
				string name = keyValuePair.Key;
				MethodInfo methodInfo = keyValuePair.Value;

				Console.WriteLine("[+] Decrypting {0} ({1}) ...", name, methodInfo.Name);

				if (methodInfo.Name == "flared_35" ||
					methodInfo.Name == "flared_47" ||
					methodInfo.Name == "flared_66" ||
					methodInfo.Name == "flared_67" ||
					methodInfo.Name == "flared_68" ||
					methodInfo.Name == "flared_69" ||
					methodInfo.Name == "flared_70")
				{
					Console.WriteLine("[+] Method {0}() decrypted already in the 1st layer. Skip.",
								   	  methodInfo.Name);

					string hash = GenerateHash(methodInfo);
					Console.WriteLine("[+] Removing SHA256 from list: {0}", hash);
					PESectionNames.Remove(hash.Substring(0, 8));
					continue;
				}

				// Method is encrypted. Decrypt it.
				try
				{
					string hash = GenerateHash(methodInfo);
					Console.WriteLine("[+] Calculating method hash: {0}", hash);
					PESectionNames.Remove(hash.Substring(0, 8));

					byte[] contents = GetPESectionContents(hash);
					Console.WriteLine("[+] PE Section contents: {0}",
									  BitConverter.ToString(contents));

					byte[] plain = RC4Decrypt(new byte[] {18, 120, 171, 223}, contents);
					Console.WriteLine("[+] Decrypted Bytecode: {0}",
									  BitConverter.ToString(plain));

					byte[] relocated = DoCodeRellocationsV2(plain);
					Console.WriteLine("[+] Rellocated Bytecode: {0}",
									  BitConverter.ToString(relocated));

					// Patch code into executable buffer.
					DecryptLayer1.PatchCodeToFile(buff, methodInfo, new List<byte>(relocated));
				}
				catch (FileNotFoundException)
				{
					Console.WriteLine("[+] Method not found in PE: {0}", methodInfo.Name);
				}
			}

			/**
			 * NOTE: The above code works great for all functions except
			 * flared_14 and flared_15. Fuck it, I'm doing it manually.
			 * I have no idea why code throws an exceptions for these 2 guys.
			 */
			Console.WriteLine("[+] Leftovers In PESectionNames: {0}",
							  String.Join(", ", PESectionNames));

			// Leftover SHAs are: 5aeb2b97, 94957fff, 0e5cf5d9.
			byte[] data1 = GetPESectionContents("5aeb2b97");
			byte[] data2 = GetPESectionContents("94957fff");
			byte[] data3 = GetPESectionContents("0e5cf5d9");
			
			// PE Section sizes are : 11421531, 99, and 60
			// Based on the function sizes, we can easily associate them:
			//		data2 -> flared_14
			//		data3 -> flared_15

			// Do for flared_14().
			byte[] plain2 = RC4Decrypt(new byte[] {18, 120, 171, 223}, data2);
			Console.WriteLine("[+] Decrypted Bytecode: {0}", BitConverter.ToString(plain2));
			byte[] relocated2 = DoCodeRellocationsV2(plain2);
			Console.WriteLine("[+] Rellocated Bytecode: {0}",
							  BitConverter.ToString(relocated2));
			PatchCodeToFile(
				buff,
				new byte[] {
					// Just the first 16 bytes from flared_14() as a matching pattern.
					0x2B, 0x72, 0x77, 0x9D, 0xFF, 0x97, 0x40, 0x21,
					0xBF, 0xBB, 0xBB, 0x00, 0xAD, 0xB2, 0x7A, 0xF2
				},
				new List<byte>(relocated2)
			);

			// Do for flared_15().
			byte[] plain3 = RC4Decrypt(new byte[] {18, 120, 171, 223}, data3);
			Console.WriteLine("[+] Decrypted Bytecode: {0}", BitConverter.ToString(plain3));
			byte[] relocated3 = DoCodeRellocationsV2(plain3);
			Console.WriteLine("[+] Rellocated Bytecode: {0}",
							  BitConverter.ToString(relocated3));
			PatchCodeToFile(
				buff,
				new byte[] { 
					// Just the first 16 bytes from flared_15() as a matching pattern.
					0x34, 0x27, 0xA6, 0xC5, 0x09, 0x11, 0xEF, 0x36,
					0xA9, 0xB5, 0xA2, 0xD6, 0x82, 0x0F, 0x1D, 0x8F
				},
				new List<byte>(relocated3)
			);

			return buff;
		}
	}
}
/*
[+] Applying 2nd layer of decryption to: C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.patched.exe
[+] Checking class: FlareOn.Backdoor.FLARE01
[+]    Encrypted method found: flared_00
[+]    Encrypted method found: flared_01
[+] Checking class: FlareOn.Backdoor.FLARE02
[+]    Encrypted method found: flared_02
[+]    Encrypted method found: flared_03
[+]    Encrypted method found: flared_04
[+]    Encrypted method found: flared_05
[+] Checking class: FlareOn.Backdoor.FLARE02+<>c
[+] Checking class: FlareOn.Backdoor.FLARE03
[+]    Encrypted method found: flared_06
[+]    Encrypted method found: flared_07
[+]    Encrypted method found: flared_08
[+]    Encrypted method found: flared_09
[+]    Encrypted method found: flared_10
[+]    Encrypted method found: flared_11
[+]    Encrypted method found: flared_12
[+]    Encrypted method found: flared_13
[+]    Encrypted method found: flared_14
[+]    Encrypted method found: flared_15
[+]    Encrypted method found: flared_16
[+] Checking class: FlareOn.Backdoor.FLARE04
[+]    Encrypted method found: flared_17
[+]    Encrypted method found: flared_18
[+] Checking class: FlareOn.Backdoor.FLARE05
[+]    Encrypted method found: flared_19
[+]    Encrypted method found: flared_20
[+]    Encrypted method found: flared_21
[+]    Encrypted method found: flared_22
[+]    Encrypted method found: flared_23
[+]    Encrypted method found: flared_24
[+]    Encrypted method found: flared_25
[+]    Encrypted method found: flared_26
[+]    Encrypted method found: flared_27
[+]    Encrypted method found: flared_28
[+]    Encrypted method found: flared_29
[+]    Encrypted method found: flared_30
[+]    Encrypted method found: flared_31
[+]    Encrypted method found: flared_32
[+]    Encrypted method found: flared_33
[+]    Encrypted method found: flared_34
[+] Checking class: FlareOn.Backdoor.FLARE05+<>c__DisplayClass0_0
[+] Checking class: FlareOn.Backdoor.FLARE05+<>c__DisplayClass2_0
[+] Checking class: FlareOn.Backdoor.FLARE05+<>c__DisplayClass4_0
[+] Checking class: FlareOn.Backdoor.FLARE05+<>c__DisplayClass6_0
[+] Checking class: FlareOn.Backdoor.FLARE06
[+] Checking class: FlareOn.Backdoor.FLARE06+DomT
[+] Checking class: FlareOn.Backdoor.FLARE06+DT
[+] Checking class: FlareOn.Backdoor.FLARE06+TT
[+] Checking class: FlareOn.Backdoor.FLARE06+SR
[+] Checking class: FlareOn.Backdoor.FLARE06+OT
[+] Checking class: FlareOn.Backdoor.FLARE07
[+] Checking class: FlareOn.Backdoor.FLARE08
[+] Checking class: FlareOn.Backdoor.FLARE09
[+]    Encrypted method found: flared_35
[+]    Encrypted method found: flared_36
[+]    Encrypted method found: flared_37
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_DOS_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_DATA_DIRECTORY
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_OPTIONAL_HEADER32
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_OPTIONAL_HEADER64
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_FILE_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09+IMAGE_SECTION_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09+DataSectionFlags
[+] Checking class: FlareOn.Backdoor.Program
[+]    Encrypted method found: flared_38
[+]    Encrypted method found: flared_39
[+]    Encrypted method found: flared_40
[+] Checking class: FlareOn.Backdoor.Program+<>c
[+] Checking class: FlareOn.Backdoor.FLARE10
[+]    Encrypted method found: flared_41
[+] Checking class: FlareOn.Backdoor.FLARE11
[+]    Encrypted method found: flared_42
[+]    Encrypted method found: flared_43
[+]    Encrypted method found: flared_44
[+]    Encrypted method found: flared_45
[+]    Encrypted method found: flared_46
[+] Checking class: FlareOn.Backdoor.FLARE12
[+]    Encrypted method found: flared_47
[+] Checking class: FlareOn.Backdoor.FLARE13
[+]    Encrypted method found: flared_48
[+]    Encrypted method found: flared_49
[+]    Encrypted method found: flared_50
[+] Checking class: FlareOn.Backdoor.FLARE13+FLARE16
[+] Checking class: FlareOn.Backdoor.FLARE14
[+]    Encrypted method found: flared_51
[+]    Encrypted method found: flared_52
[+]    Encrypted method found: flared_53
[+]    Encrypted method found: flared_54
[+]    Encrypted method found: flared_55
[+]    Encrypted method found: flared_56
[+]    Encrypted method found: flared_57
[+] Checking class: FlareOn.Backdoor.FLARE14+<>c__DisplayClass14_0
[+] Checking class: FlareOn.Backdoor.FLARE14+<>c__DisplayClass14_1
[+] Checking class: FlareOn.Backdoor.FLARE15
[+]    Encrypted method found: flared_58
[+]    Encrypted method found: flared_59
[+]    Encrypted method found: flared_60
[+]    Encrypted method found: flared_61
[+]    Encrypted method found: flared_62
[+]    Encrypted method found: flared_63
[+]    Encrypted method found: flared_64
[+]    Encrypted method found: flared_65
[+]    Encrypted method found: flared_66
[+]    Encrypted method found: flared_67
[+]    Encrypted method found: flared_68
[+]    Encrypted method found: flared_69
[+]    Encrypted method found: flared_70
[+] Checking class: FlareOn.Backdoor.Properties.Resources
[+] Checking class: <PrivateImplementationDetails>
[+] Decrypting flared_00 (flared_00) ...
[+] Generating hash from MethodInfo for: flared_00
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: F9-00-00-00
[+] Value of bytes6: System.Int32System.Char[]System.ByteSystem.ByteSystem.Int32System.BooleanSystem.Byte[]System.Int32System.ByteSystem.BooleanSystem.BooleanSystem.String
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: 89b957e3cbcc1acc0649a02914815042749ef4bf809987ac3b24a303f31a37f8
[+] Calculating method hash: 89b957e3cbcc1acc0649a02914815042749ef4bf809987ac3b24a303f31a37f8
[+] Loading PE Section: 89b957e3
[+] PE Section contents: 96-4A-D2-76-06-AD-E1-49-AA-63-4A-4C-FF-B5-DC-00-2A-39-F2-69-F3-E1-79-14-AF-0B-4F-05-9F-B6-8C-C6-7F-2E-4D-3F-6C-AF-B8-05-49-CB-C2-5B-87-CE-CE-05-A6-B2-02-43-FA-0B-14-2B-4B-C4-2A-95-FA-56-52-67-99-9B-77-2B-D8-6A-43-83-F6-35-21-1D-95-77-D5-37-1A-6B-CC-58-64-D0-33-F9-D9-53-3A-C8-C0-28-77-65-32-D1-4C-03-D7-0B-0A-97-BC-C2-78-41-73-EC-6A-BA-77-4D-7E-E8-85-18-A8-57-A1-FC-F4-C3-C9-15-AD-4F-95-62-E0-B7-85-A6-8D-0E-DB-DF-9D-E1-E7-DB-FE-1A-3A-5A-CA-03-F3-35-F2-8B-D6-C2-C5-0D-AD-49-3C-41-0C-F4-AE-53-32-0F-16-7D-6B-89-E8-3F-7C-E3-22-66-8C-7E-A1-32-13-99-BC-56-9D-5F-9E-4B-C0-C6-96-B9-DF-6B-F2-4B-35-DA-EC-E6-7D-D1-5A-64-09-39-C9-DE-D9-5D-A6-E9-6E-51-AC-14-F7-9B-46-C3-B0-AF-BE-F2-B3-B4-52-26-13-79-52-10-E9-AB-6C-C4-7F-9E-85-59-6E-5C-1B-AC-23-AA-76-3A-4D
[+] Decrypted Bytecode: 00-02-2C-07-02-8E-16-FE-01-2B-01-17-13-05-11-05-2C-0C-00-72-BC-A6-98-D2-73-A8-A6-98-A8-7A-02-8E-69-6C-23-00-00-00-00-00-00-14-40-5B-28-AB-A6-98-A8-69-1E-5A-0A-06-8D-91-A6-98-A3-0B-16-0C-1B-0D-16-13-04-00-02-13-06-16-13-07-2B-6A-11-06-11-07-91-13-08-00-08-11-08-1E-09-59-1F-1F-5F-63-60-D2-0C-07-11-04-25-17-58-13-04-08-28-B9-A6-98-A4-9D-09-1A-FE-04-13-09-11-09-2C-24-00-11-08-19-09-59-1F-1F-5F-63-1F-1F-5F-D2-0C-07-11-04-25-17-58-13-04-08-28-B9-A6-98-A4-9D-09-1B-58-D2-0D-00-09-19-59-D2-0D-11-08-09-1F-1F-5F-62-1F-1F-5F-D2-0C-00-11-07-17-58-13-07-11-07-11-06-8E-69-32-8E-11-04-06-FE-01-16-FE-01-13-0A-11-0A-2C-11-00-07-11-04-25-17-58-13-04-08-28-B9-A6-98-A4-9D-00-07-73-AA-A6-98-A8-72-B0-A6-98-D2-72-AC-A6-98-D2-28-A5-A6-98-A8-13-0B-2B-00-11-0B-2A
[+] Rellocated Bytecode: 00-02-2C-07-02-8E-16-FE-01-2B-01-17-13-05-11-05-2C-0C-00-72-01-00-00-70-73-15-00-00-0A-7A-02-8E-69-6C-23-00-00-00-00-00-00-14-40-5B-28-16-00-00-0A-69-1E-5A-0A-06-8D-2C-00-00-01-0B-16-0C-1B-0D-16-13-04-00-02-13-06-16-13-07-2B-6A-11-06-11-07-91-13-08-00-08-11-08-1E-09-59-1F-1F-5F-63-60-D2-0C-07-11-04-25-17-58-13-04-08-28-04-00-00-06-9D-09-1A-FE-04-13-09-11-09-2C-24-00-11-08-19-09-59-1F-1F-5F-63-1F-1F-5F-D2-0C-07-11-04-25-17-58-13-04-08-28-04-00-00-06-9D-09-1B-58-D2-0D-00-09-19-59-D2-0D-11-08-09-1F-1F-5F-62-1F-1F-5F-D2-0C-00-11-07-17-58-13-07-11-07-11-06-8E-69-32-8E-11-04-06-FE-01-16-FE-01-13-0A-11-0A-2C-11-00-07-11-04-25-17-58-13-04-08-28-04-00-00-06-9D-00-07-73-17-00-00-0A-72-0D-00-00-70-72-11-00-00-70-28-18-00-00-0A-13-0B-2B-00-11-0B-2A
[+] Overwriting bytecode for flared_00: 125-111-6-113-121-132-66-194-54-57-146-35-31-193-181-120-139-106-133-129-212-53-214-92-137-11-49-67-36-126-60-239-244-20-170-138-231-135-241-167-90-103-19-147-39-9-240-170-133-191-232-223-229-214-211-72-153-169-232-110-82-254-157-183-252-162-47-11-22-0-145-3-121-222-39-109-33-67-53-127-27-134-190-100-150-92-10-29-64-98-241-62-159-131-84-91-201-92-150-133-218-228-148-91-46-228-102-6-175-102-39-85-116-104-82-203-64-56-33-160-151-17-203-179-56-83-99-245-138-203-163-197-173-175-165-54-242-99-54-177-246-4-110-217-59-156-201-55-48-136-26-144-59-246-237-200-25-224-34-219-129-112-123-227-195-97-168-196-194-28-217-221-2-111-169-147-163-241-120-156-137-44-197-1-176-19-137-183-193-221-28-17-64-91-48-133-136-139-22-217-244-4-116-20-175-61-142-203-76-90-37-40-104-134-81-85-171-122-50-176-216-241-3-229-255-199-156-166-62-36-10-23-219-158-167-132-183-176-81-115-132-189-106-103-183-244-168-186-9
[+] Offset found: 0x91A0
[+] Decrypting flared_01 (flared_01) ...
[+] Generating hash from MethodInfo for: flared_01
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Char
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 37-00-00-00
[+] Value of bytes6: System.BooleanSystem.CharSystem.Boolean
[+] Value of bytes7: System.Byte
[+] Final SHA256: 689d7525fedc82ecb6ae5046342b45e3bccb57e9f9209f658b3f240d1a74069c
[+] Calculating method hash: 689d7525fedc82ecb6ae5046342b45e3bccb57e9f9209f658b3f240d1a74069c
[+] Loading PE Section: 689d7525
[+] PE Section contents: 96-4A-E1-6B-FA-27-FD-B1-87-41-4B-59-F3-D1-95-D4-0D-1E-D0-19-50-67-1F-C2-D0-AB-C5-94-37-CE-91-50-4E-93-65-14-7C-DD-16-A3-D1-0D-F0-EA-09-FD-BA-EE-AA-7D-84-B1-8A-0A-B3
[+] Decrypted Bytecode: 00-02-1F-1A-FE-04-0A-06-2C-09-00-02-1F-61-58-D1-0B-2B-22-02-1F-20-FE-04-0C-08-2C-09-00-02-1F-18-58-D1-0B-2B-10-72-AE-A6-98-D2-72-EA-A6-98-D2-73-A4-A6-98-A8-7A-07-2A
[+] Rellocated Bytecode: 00-02-1F-1A-FE-04-0A-06-2C-09-00-02-1F-61-58-D1-0B-2B-22-02-1F-20-FE-04-0C-08-2C-09-00-02-1F-18-58-D1-0B-2B-10-72-13-00-00-70-72-57-00-00-70-73-19-00-00-0A-7A-07-2A
[+] Overwriting bytecode for flared_01: 135-66-12-118-81-202-79-110-51-48-8-174-237-109-187-198-83-94-162-65-96-165-174-110-134-95-84-146-211-60-234-14-20-34-172-66-160-57-151-96-103-166-96-18-76-57-248-216-10-232-247-29-105-27-100
[+] Offset found: 0x92EC
[+] Decrypting flared_02 (flared_02) ...
[+] Generating hash from MethodInfo for: flared_02
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 20-00-00-00
[+] Value of bytes6: System.String
[+] Value of bytes7: System.String
[+] Final SHA256: 30752c497d0229b3fecf3e058c2c8d39a9a46a5f27b02da69c0c5a997e97a80e
[+] Calculating method hash: 30752c497d0229b3fecf3e058c2c8d39a9a46a5f27b02da69c0c5a997e97a80e
[+] Loading PE Section: 30752c49
[+] PE Section contents: 96-3A-18-D7-9C-F1-85-69-0D-D0-99-59-9E-66-6B-9D-D4-1D-54-BD-D7-EF-C9-70-7A-3B-4D-97-1C-CC-88-62
[+] Decrypted Bytecode: 00-72-E6-A6-98-D2-72-DE-A6-98-D2-02-72-D6-A6-98-D2-28-A6-A6-98-A8-28-B6-A6-98-A4-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-72-5B-00-00-70-72-63-00-00-70-02-72-6B-00-00-70-28-1B-00-00-0A-28-0B-00-00-06-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_02: 93-202-87-65-252-238-61-5-175-176-165-245-253-65-41-227-61-128-232-40-55-205-127-88-240-232-244-115-159-179-50-30
[+] Offset found: 0x9378
[+] Decrypting flared_03 (flared_03) ...
[+] Generating hash from MethodInfo for: flared_03
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 16-00-00-00
[+] Value of bytes6: System.String
[+] Value of bytes7: System.String
[+] Final SHA256: 7c5ccd915cbf3032739fa1df6b8578099f01baa6b94aebc638f0dc285ffcc915
[+] Calculating method hash: 7c5ccd915cbf3032739fa1df6b8578099f01baa6b94aebc638f0dc285ffcc915
[+] Loading PE Section: 7c5ccd91
[+] PE Section contents: 96-3A-3E-D7-9C-F1-F5-C5-AD-EE-D3-89-C4-16-6B-9D-AE-3F-D9-1B-49-6D
[+] Decrypted Bytecode: 00-72-C0-A6-98-D2-02-72-06-A6-98-D2-28-A6-A6-98-A8-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-72-7D-00-00-70-02-72-BB-00-00-70-28-1B-00-00-0A-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_03: 155-236-232-162-169-25-162-173-12-206-27-103-220-8-61-169-39-86-11-135-37-212
[+] Offset found: 0x93E8
[+] Decrypting flared_04 (flared_04) ...
[+] Generating hash from MethodInfo for: flared_04
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 66-00-00-00
[+] Value of bytes6: System.Diagnostics.ProcessStartInfoSystem.Diagnostics.ProcessSystem.String
[+] Value of bytes7: System.StringSystem.String
[+] Final SHA256: 5ca8a51747ebd16b041721bf56a30cd5f39f1829df27e51eadfba77003a38393
[+] Calculating method hash: 5ca8a51747ebd16b041721bf56a30cd5f39f1829df27e51eadfba77003a38393
[+] Loading PE Section: 5ca8a517
[+] PE Section contents: 96-4A-FD-02-A5-85-6F-1F-A1-4E-5D-34-4C-16-55-AD-06-33-E5-74-EC-E1-79-6E-DC-A5-FE-F2-95-6A-16-E0-16-44-79-50-F1-09-20-AD-49-D9-95-6F-33-C3-F0-35-0E-A8-83-BF-68-A5-92-BD-EB-33-17-38-74-F2-49-6D-E0-11-D5-B3-72-5F-42-FA-7D-94-92-DF-EB-EA-62-A8-23-7F-AB-C2-CA-59-93-88-4B-AC-BD-7F-B7-DE-B1-2F-96-DA-76-07-FA-36
[+] Decrypted Bytecode: 00-02-03-73-A1-A6-98-A8-0A-06-16-6F-A0-A6-98-A8-00-06-17-6F-A3-A6-98-A8-00-06-17-6F-A2-A6-98-A8-00-06-17-6F-9D-A6-98-A8-00-06-17-6F-9C-A6-98-A8-00-73-9F-A6-98-A8-0B-07-06-6F-9E-A6-98-A8-00-07-6F-99-A6-98-A8-26-07-6F-98-A6-98-A8-6F-9B-A6-98-A8-07-6F-9A-A6-98-A8-6F-9B-A6-98-A8-28-95-A6-98-A8-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-02-03-73-1C-00-00-0A-0A-06-16-6F-1D-00-00-0A-00-06-17-6F-1E-00-00-0A-00-06-17-6F-1F-00-00-0A-00-06-17-6F-20-00-00-0A-00-06-17-6F-21-00-00-0A-00-73-22-00-00-0A-0B-07-06-6F-23-00-00-0A-00-07-6F-24-00-00-0A-26-07-6F-25-00-00-0A-6F-26-00-00-0A-07-6F-27-00-00-0A-6F-26-00-00-0A-28-28-00-00-0A-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_04: 233-82-151-217-249-67-193-26-8-0-197-120-65-207-209-175-136-142-185-238-90-126-55-153-227-217-133-124-113-62-113-50-30-31-112-219-82-83-223-195-201-189-31-127-67-73-224-134-217-47-82-106-9-196-234-107-26-254-246-31-190-68-168-202-185-146-90-34-94-246-93-53-174-246-36-156-95-183-86-154-249-255-163-66-236-7-40-89-52-5-192-83-93-191-5-132-21-84-198-176-238-189
[+] Offset found: 0x9450
[+] Decrypting flared_05 (flared_05) ...
[+] Generating hash from MethodInfo for: flared_05
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: 5A-01-00-00
[+] Value of bytes6: System.StringSystem.StringSystem.String[]System.Int32System.StringSystem.BooleanSystem.BooleanSystem.BooleanSystem.String
[+] Value of bytes7: System.String
[+] Final SHA256: 96c576e472cc6ff877cb1db64b2dbd0494f518d3550b213fe753319665721b6b
[+] Calculating method hash: 96c576e472cc6ff877cb1db64b2dbd0494f518d3550b213fe753319665721b6b
[+] Loading PE Section: 96c576e4
[+] PE Section contents: 96-4A-F4-71-7A-B7-51-2F-03-43-49-4C-61-20-6B-9D-A5-10-E4-33-D8-E1-79-6E-7E-B4-86-0B-91-54-26-44-00-4F-56-FF-6C-AF-B8-05-41-D6-18-6F-3E-C3-F0-35-7C-D9-BA-81-22-7F-E1-1C-75-8E-E6-3B-4A-C2-E1-18-8D-2E-EB-F9-A8-01-E3-0D-37-5D-AF-D1-1C-D9-B6-32-2D-E0-16-2A-14-67-A3-35-BF-AF-83-4F-37-39-15-11-A6-04-2F-7F-54-84-80-EB-1D-6C-C8-50-A7-00-68-BF-AC-25-F2-4A-0E-C3-D6-FB-2B-40-5C-A0-B5-AA-3C-C4-F8-0F-19-4C-48-D6-77-7A-4F-70-FE-91-64-54-74-7B-4C-F4-7A-68-3A-08-F0-8E-77-AB-E9-79-38-9B-47-2A-F3-BE-71-2D-9F-A0-91-CA-27-EF-E6-24-0B-A1-88-FE-35-6F-48-6B-13-9B-BC-54-A0-71-10-25-DA-D8-21-25-71-83-0D-5C-D8-DD-EE-EA-40-D5-76-72-7B-50-7E-42-2E-62-6B-5C-F2-F1-8F-AD-56-12-E6-76-25-0E-55-F0-1E-2C-FA-5D-B4-87-C7-CB-93-89-A3-A2-A9-A5-27-EE-F1-CE-39-58-F7-55-60-3B-67-B1-48-DB-2D-8D-EB-3C-A0-0E-FE-5F-2F-3E-A9-34-59-1B-BB-2F-1F-8E-82-71-3A-75-63-F6-EA-00-A9-3A-16-D1-31-7C-E3-9F-BB-7D-AF-EC-D6-E4-50-21-53-53-5C-4F-CB-EC-2C-45-39-C7-4B-7C-2E-82-18-A5-C6-3D-AB-09-D6-29-C9-9A-5B-2F-5C-58-46-62-ED-CC-6E-17-CC-31-5A-7D-94-0B-ED-C8-E9-F8-BC-AA-7C-DA-63-E7-41-34
[+] Decrypted Bytecode: 00-02-0A-00-7E-94-A6-98-A8-0B-02-17-8D-90-A6-98-A3-25-16-28-97-A6-98-A8-A2-17-6F-96-A6-98-A8-0C-16-0D-38-C0-00-00-00-00-08-09-9A-6F-91-A6-98-A8-72-02-A6-98-D2-72-78-A6-98-D2-6F-A5-A6-98-A8-72-02-A6-98-D2-72-78-A6-98-D2-6F-A5-A6-98-A8-72-02-A6-98-D2-72-78-A6-98-D2-6F-A5-A6-98-A8-72-02-A6-98-D2-72-78-A6-98-D2-6F-A5-A6-98-A8-72-74-A6-98-D2-72-72-A6-98-D2-6F-A5-A6-98-A8-72-74-A6-98-D2-72-72-A6-98-D2-6F-A5-A6-98-A8-72-74-A6-98-D2-72-72-A6-98-D2-6F-A5-A6-98-A8-72-74-A6-98-D2-72-72-A6-98-D2-6F-A5-A6-98-A8-13-04-11-04-28-90-A6-98-A8-16-FE-01-13-05-11-05-2C-28-00-07-28-90-A6-98-A8-16-FE-01-13-06-11-06-2C-0E-00-07-72-6E-A6-98-D2-28-95-A6-98-A8-0B-00-07-11-04-28-95-A6-98-A8-0B-00-00-09-17-58-0D-09-08-8E-69-FE-04-13-07-11-07-3A-31-FF-FF-FF-07-0A-00-DE-05-26-00-00-DE-00-72-6A-A6-98-D2-7E-B2-A6-98-A6-1B-28-BC-A6-98-89-7E-BF-A6-98-A6-25-2D-17-26-7E-BC-A6-98-A6-FE-06-AC-A6-98-A4-73-92-A6-98-A8-25-80-BF-A6-98-A6-28-BF-A6-98-89-28-BE-A6-98-89-73-AA-A6-98-A8-28-95-A6-98-A8-06-28-8F-A6-98-A8-00-06-16-1F-0C-6F-8E-A6-98-A8-13-08-2B-00-11-08-2A
[+] Rellocated Bytecode: 00-02-0A-00-7E-29-00-00-0A-0B-02-17-8D-2D-00-00-01-25-16-28-2A-00-00-0A-A2-17-6F-2B-00-00-0A-0C-16-0D-38-C0-00-00-00-00-08-09-9A-6F-2C-00-00-0A-72-BF-00-00-70-72-C5-00-00-70-6F-18-00-00-0A-72-BF-00-00-70-72-C5-00-00-70-6F-18-00-00-0A-72-BF-00-00-70-72-C5-00-00-70-6F-18-00-00-0A-72-BF-00-00-70-72-C5-00-00-70-6F-18-00-00-0A-72-C9-00-00-70-72-CF-00-00-70-6F-18-00-00-0A-72-C9-00-00-70-72-CF-00-00-70-6F-18-00-00-0A-72-C9-00-00-70-72-CF-00-00-70-6F-18-00-00-0A-72-C9-00-00-70-72-CF-00-00-70-6F-18-00-00-0A-13-04-11-04-28-2D-00-00-0A-16-FE-01-13-05-11-05-2C-28-00-07-28-2D-00-00-0A-16-FE-01-13-06-11-06-2C-0E-00-07-72-D3-00-00-70-28-28-00-00-0A-0B-00-07-11-04-28-28-00-00-0A-0B-00-00-09-17-58-0D-09-08-8E-69-FE-04-13-07-11-07-3A-31-FF-FF-FF-07-0A-00-DE-05-26-00-00-DE-00-72-D7-00-00-70-7E-0F-00-00-04-1B-28-01-00-00-2B-7E-02-00-00-04-25-2D-17-26-7E-01-00-00-04-FE-06-11-00-00-06-73-2F-00-00-0A-25-80-02-00-00-04-28-02-00-00-2B-28-03-00-00-2B-73-17-00-00-0A-28-28-00-00-0A-06-28-32-00-00-0A-00-06-16-1F-0C-6F-33-00-00-0A-13-08-2B-00-11-08-2A
[+] Overwriting bytecode for flared_05: 239-234-229-64-242-175-166-3-132-4-166-0-234-141-234-158-124-167-64-184-198-17-55-204-0-132-189-154-52-157-32-202-131-37-223-210-73-184-232-255-147-250-185-130-55-218-3-206-179-173-200-83-215-186-110-221-178-24-21-109-242-11-207-231-228-219-166-196-174-24-84-196-190-64-36-203-88-181-148-80-129-238-231-135-213-204-242-200-183-1-31-49-162-122-13-136-43-210-158-91-51-62-32-155-88-3-148-150-149-162-133-253-131-197-236-3-36-72-17-23-232-222-13-172-248-35-34-67-51-156-159-133-23-57-28-67-206-75-46-209-55-92-50-20-124-34-173-220-142-10-99-227-192-134-114-85-48-115-163-53-225-81-99-249-2-255-229-74-168-169-52-216-25-63-224-140-171-248-47-213-117-69-181-40-57-187-197-145-198-199-18-90-168-248-240-230-248-57-17-125-60-98-51-229-214-138-201-128-166-230-169-55-68-205-192-155-155-59-192-70-57-84-132-224-150-217-48-33-79-249-148-113-230-178-152-19-17-208-81-174-242-68-234-224-30-218-22-219-56-84-74-188-121-202-67-232-221-82-78-252-90-168-48-172-81-55-80-145-52-172-138-203-233-17-84-245-105-164-194-187-195-84-233-251-174-216-248-28-110-176-53-191-129-85-84-74-19-61-142-230-138-132-167-139-202-126-210-103-118-78-126-57-144-146-56-5-190-53-254-121-62-52-35-131-119-202-74-148-189-10-225-44-22-219-49-62-173-94-49-47-5-145-166-32-50-251
[+] Offset found: 0x950C
[+] Decrypting flared_06 (flared_06) ...
[+] Generating hash from MethodInfo for: flared_06
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 30-00-00-00
[+] Value of bytes6: System.Boolean
[+] Value of bytes7:
[+] Final SHA256: 305a002f193b2c1ed9295410535693b9f52c47aaf4f685bccd787b2145af07de
[+] Calculating method hash: 305a002f193b2c1ed9295410535693b9f52c47aaf4f685bccd787b2145af07de
[+] Loading PE Section: 305a002f
[+] PE Section contents: 96-60-5C-D7-9C-87-E1-49-AA-42-4D-77-F4-B0-DB-7B-AF-93-6A-BD-67-88-47-5E-78-23-47-3B-AF-6A-A6-E8-B0-DA-CA-19-6C-DC-32-A3-D1-77-02-97-08-FD-CE-B7
[+] Decrypted Bytecode: 00-28-A2-A6-98-A4-16-FE-01-0A-06-2C-18-00-16-7E-A9-A6-98-A6-28-CF-A6-98-A4-80-AE-A6-98-A6-28-A0-A6-98-A4-26-00-73-8A-A6-98-A8-80-97-A7-98-A6-2A
[+] Rellocated Bytecode: 00-28-1F-00-00-06-16-FE-01-0A-06-2C-18-00-16-7E-14-00-00-04-28-72-00-00-06-80-13-00-00-04-28-1D-00-00-06-26-00-73-37-00-00-0A-80-2A-01-00-04-2A
[+] Overwriting bytecode for flared_06: 113-57-2-18-11-247-37-134-44-117-118-138-23-155-167-94-89-136-181-229-135-246-170-188-83-158-10-141-247-220-152-152-23-234-101-159-101-140-200-4-215-248-177-5-171-201-74-22
[+] Offset found: 0x96DC
[+] Decrypting flared_07 (flared_07) ...
[+] Generating hash from MethodInfo for: flared_07
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 8
[+] Value of bytes5: 13-00-00-00
[+] Value of bytes6:
[+] Value of bytes7: System.Int32
[+] Final SHA256: b1c8119c5c717d00c46b7a6c43cf3eda111059ac6b4c6cb4a440575dde65e014
[+] Calculating method hash: b1c8119c5c717d00c46b7a6c43cf3eda111059ac6b4c6cb4a440575dde65e014
[+] Loading PE Section: b1c8119c
[+] PE Section contents: 96-4A-8D-F4-A2-BB-5F-37-04-EE-D3-FD-C4-10-6B-9D-A2-13-D8
[+] Decrypted Bytecode: 00-02-73-85-A6-98-A8-80-AF-A6-98-A6-28-A0-A6-98-A4-26-2A
[+] Rellocated Bytecode: 00-02-73-38-00-00-0A-80-12-00-00-04-28-1D-00-00-06-26-2A
[+] Overwriting bytecode for flared_07: 162-0-179-130-22-115-97-40-26-73-128-125-28-189-205-30-36-194-223
[+] Offset found: 0x908A
[+] Decrypting flared_08 (flared_08) ...
[+] Generating hash from MethodInfo for: flared_08
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 2F-00-00-00
[+] Value of bytes6: System.Boolean
[+] Value of bytes7:
[+] Final SHA256: 538fcc692564863f834626beee91b70f1f100389e96a91b9b836d7c65acb0dc5
[+] Calculating method hash: 538fcc692564863f834626beee91b70f1f100389e96a91b9b836d7c65acb0dc5
[+] Loading PE Section: 538fcc69
[+] PE Section contents: 96-36-50-D7-9C-85-E0-EF-2B-E6-ED-C3-4A-CE-63-A3-9E-93-8C-B2-E9-DF-47-38-D8-B5-17-9C-3D-CA-A2-40-16-54-EE-91-CA-37-1E-05-61-7F-24-98-0B-43-42
[+] Decrypted Bytecode: 00-7E-AE-A6-98-A6-17-58-80-AE-A6-98-A6-7E-AE-A6-98-A6-7E-A9-A6-98-A6-FE-04-16-FE-01-0A-06-2C-08-00-16-80-AE-A6-98-A6-00-28-A0-A6-98-A4-26-2A
[+] Rellocated Bytecode: 00-7E-13-00-00-04-17-58-80-13-00-00-04-7E-13-00-00-04-7E-14-00-00-04-FE-04-16-FE-01-0A-06-2C-08-00-16-80-13-00-00-04-00-28-1D-00-00-06-26-2A
[+] Overwriting bytecode for flared_08: 200-170-93-222-253-118-86-241-87-184-66-51-36-54-139-168-195-88-83-89-108-94-180-123-15-154-228-17-238-154-251-44-128-84-237-246-99-63-14-56-165-64-19-62-64-11-181
[+] Offset found: 0x9794
[+] Decrypting flared_09 (flared_09) ...
[+] Generating hash from MethodInfo for: flared_09
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Int32
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 0B-00-00-00
[+] Value of bytes6: System.Int32
[+] Value of bytes7:
[+] Final SHA256: 326aa956a45a5b48c14bd56e606a978d80263a80db167f6e604ff770d65f2f1a
[+] Calculating method hash: 326aa956a45a5b48c14bd56e606a978d80263a80db167f6e604ff770d65f2f1a
[+] Loading PE Section: 326aa956
[+] PE Section contents: 96-36-50-D7-9C-85-FD-9C-AB-4E-61
[+] Decrypted Bytecode: 00-7E-AE-A6-98-A6-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-7E-13-00-00-04-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_09: 0-116-132-95-215-91-190-170-116-225-158
[+] Offset found: 0x9808
[+] Decrypting flared_10 (flared_10) ...
[+] Generating hash from MethodInfo for: flared_10
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Nullable`1[System.Int32]
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 0B-00-00-00
[+] Value of bytes6: System.Nullable`1[System.Int32]
[+] Value of bytes7:
[+] Final SHA256: becb82d3c6bb7eed0697117dec50c26813eb9d9710b85c50842b9b4648d45aef
[+] Calculating method hash: becb82d3c6bb7eed0697117dec50c26813eb9d9710b85c50842b9b4648d45aef
[+] Loading PE Section: becb82d3
[+] PE Section contents: 96-36-51-D7-9C-85-FD-9C-AB-4E-61
[+] Decrypted Bytecode: 00-7E-AF-A6-98-A6-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-7E-12-00-00-04-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_10: 74-212-132-1-173-16-183-120-246-156-34
[+] Offset found: 0x985C
[+] Decrypting flared_11 (flared_11) ...
[+] Generating hash from MethodInfo for: flared_11
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 55-00-00-00
[+] Value of bytes6: System.Int32System.ExceptionSystem.Boolean
[+] Value of bytes7:
[+] Final SHA256: 7135726c5225c7883449ffdd33bb30f26d4e32cfeb3600d9fcdac23baa43833b
[+] Calculating method hash: 7135726c5225c7883449ffdd33bb30f26d4e32cfeb3600d9fcdac23baa43833b
[+] Loading PE Section: 7135726c
[+] PE Section contents: 96-48-8C-31-A2-BB-25-C8-04-EE-D3-FD-C4-34-6B-9D-AE-18-F5-69-E9-E0-79-14-F7-B1-96-32-91-54-28-60-91-E4-F6-97-66-BD-B8-2D-CF-79-1A-A8-87-F2-CE-05-A6-A4-B2-BF-68-AB-B1-3C-4B-C4-21-B6-4A-FC-D1-C2-A7-07-D5-B3-72-79-45-4B-E3-39-0A-61-88-AF-C0-27-87-53-C4-50-46
[+] Decrypted Bytecode: 00-00-72-40-A6-98-D2-7F-AF-A6-98-A6-28-84-A6-98-A8-2D-07-72-A6-A7-98-D2-2B-12-7F-AF-A6-98-A6-28-87-A6-98-A8-0A-12-00-28-86-A6-98-A8-28-97-A6-98-A8-7F-AE-A6-98-A6-28-86-A6-98-A8-28-A6-A6-98-A8-28-8F-A6-98-A8-00-00-DE-06-0B-00-16-0C-DE-04-17-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-00-72-FD-00-00-70-7F-12-00-00-04-28-39-00-00-0A-2D-07-72-1B-01-00-70-2B-12-7F-12-00-00-04-28-3A-00-00-0A-0A-12-00-28-3B-00-00-0A-28-2A-00-00-0A-7F-13-00-00-04-28-3B-00-00-0A-28-1B-00-00-0A-28-32-00-00-0A-00-00-DE-06-0B-00-16-0C-DE-04-17-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_11: 114-113-32-129-32-156-94-123-125-17-56-56-152-159-94-6-136-157-4-132-10-123-108-108-160-2-97-104-193-204-48-121-247-95-31-216-138-67-78-187-14-102-101-190-108-240-153-210-177-0-201-137-116-141-146-246-5-179-225-29-58-245-185-177-225-191-64-57-127-133-123-69-79-73-118-163-21-173-0-175-104-143-182-193-3
[+] Offset found: 0x98B0
[+] Decrypting flared_12 (flared_12) ...
[+] Generating hash from MethodInfo for: flared_12
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 59-00-00-00
[+] Value of bytes6: System.String[]System.BooleanSystem.ExceptionSystem.Boolean
[+] Value of bytes7:
[+] Final SHA256: 4a0fb13652122a0f14c212c36437a5d23d53a19cadf059d11b6bbab3907022e2
[+] Calculating method hash: 4a0fb13652122a0f14c212c36437a5d23d53a19cadf059d11b6bbab3907022e2
[+] Loading PE Section: 4a0fb136
[+] PE Section contents: 96-48-DE-00-11-23-F7-9F-63-EE-D3-FF-EC-C2-8D-A3-9E-E7-DA-9A-E9-DF-49-CC-DA-B5-73-EF-91-6B-16-9A-3E-C2-C8-A7-C4-A4-BF-29-5D-DF-84-16-35-4D-EB-3B-96-73-6F-9C-56-95-31-3A-42-FA-11-38-EC-5C-5E-F0-A7-0B-D5-B3-72-F9-EB-33-7D-94-0A-A9-82-7D-C4-26-86-A6-C0-4F-61-EA-3B-EE-FA
[+] Decrypted Bytecode: 00-00-20-71-15-00-00-28-C8-A6-98-A4-00-72-40-A6-98-D2-28-81-A6-98-A8-0A-06-16-9A-72-A6-A7-98-D2-28-80-A6-98-A8-0B-07-2C-14-00-06-16-9A-28-83-A6-98-A8-73-85-A6-98-A8-80-AF-A6-98-A6-00-06-17-9A-28-83-A6-98-A8-80-AE-A6-98-A6-00-DE-06-0C-00-16-0D-DE-04-17-0D-2B-00-09-2A
[+] Rellocated Bytecode: 00-00-20-71-15-00-00-28-75-00-00-06-00-72-FD-00-00-70-28-3C-00-00-0A-0A-06-16-9A-72-1B-01-00-70-28-3D-00-00-0A-0B-07-2C-14-00-06-16-9A-28-3E-00-00-0A-73-38-00-00-0A-80-12-00-00-04-00-06-17-9A-28-3E-00-00-0A-80-13-00-00-04-00-DE-06-0C-00-16-0D-DE-04-17-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_12: 46-15-200-116-55-122-12-252-147-142-132-217-47-48-121-154-108-211-37-35-247-228-99-109-110-153-234-39-83-242-122-195-179-9-32-247-25-154-181-167-110-83-96-68-97-158-4-186-49-127-251-33-209-160-197-73-171-91-6-157-144-229-169-161-20-193-38-38-15-129-129-209-30-126-181-164-132-31-12-207-148-47-245-212-246-89-242-19-67
[+] Offset found: 0x9970
[+] Decrypting flared_13 (flared_13) ...
[+] Generating hash from MethodInfo for: flared_13
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 1D-00-00-00
[+] Value of bytes6: System.Int32System.String
[+] Value of bytes7:
[+] Final SHA256: 794ac8464ceed27c1b1afcf98241435748dae7fe6b4952524b631bf81a1e7c0b
[+] Calculating method hash: 794ac8464ceed27c1b1afcf98241435748dae7fe6b4952524b631bf81a1e7c0b
[+] Loading PE Section: 794ac846
[+] PE Section contents: 96-5E-80-DD-A2-BB-51-39-C2-5F-12-73-23-16-55-A1-0C-4B-5E-BD-D7-E1-E7-5C-D7-88-E9-9A-1D
[+] Decrypted Bytecode: 00-16-7E-AC-A6-98-A6-8E-69-17-59-28-CF-A6-98-A4-0A-7E-AC-A6-98-A6-06-9A-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-16-7E-11-00-00-04-8E-69-17-59-28-72-00-00-06-0A-7E-11-00-00-04-06-9A-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_13: 218-217-141-119-207-157-164-3-158-252-250-8-51-97-102-81-53-63-227-40-130-219-154-69-195-238-107-22-186
[+] Offset found: 0x9A34
[+] Decrypting flared_14 (flared_14) ...
[+] Generating hash from MethodInfo for: flared_14
[+] Method not found in PE: flared_14
[+] Decrypting flared_15 (flared_15) ...
[+] Generating hash from MethodInfo for: flared_15
[+] Method not found in PE: flared_15
[+] Decrypting flared_16 (flared_16) ...
[+] Generating hash from MethodInfo for: flared_16
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 6
[+] Value of bytes5: AE-00-00-00
[+] Value of bytes6: System.StringSystem.StringSystem.StringSystem.BooleanSystem.IO.DriveInfo[]System.Int32System.IO.DriveInfoSystem.BooleanSystem.BooleanSystem.String
[+] Value of bytes7:
[+] Final SHA256: 270860100f1937f49306a3325e8523e80b941ec3124e30704e2f154e0f899c83
[+] Calculating method hash: 270860100f1937f49306a3325e8523e80b941ec3124e30704e2f154e0f899c83
[+] Loading PE Section: 27086010
[+] PE Section contents: 96-3A-9A-D6-9C-F1-FD-B1-D5-DC-ED-C3-44-98-3A-A3-9E-9D-FF-12-63-04-E1-C6-F4-55-4F-05-9F-DF-8A-5E-05-47-45-13-7D-AB-A9-00-D3-CC-84-00-BE-63-07-6C-A8-43-B4-0A-F7-1C-9E-96-FD-5C-98-98-83-AA-EF-F2-27-E7-8A-8D-42-D1-4F-BE-EA-32-1B-72-93-29-D7-35-9A-7D-D5-5C-E2-A8-09-2B-D0-0C-57-8B-38-D3-C5-D8-CD-70-C5-AF-E1-14-43-8C-94-D8-50-FE-C3-72-A1-AE-D8-CF-28-F4-CF-7E-37-F8-15-70-FE-D2-C7-24-3C-B0-12-D9-B4-FC-04-1F-4A-78-DB-D0-93-E8-AD-3E-00-91-96-5A-F5-A0-3A-23-F0-8E-77-DE-95-C5-BA-26-BB-FE-CD-8E-8B-AF-9C-9E-A1-71-3D-C0-F7-31-2A-1B
[+] Decrypted Bytecode: 00-72-64-A7-98-D2-0A-06-7E-94-A6-98-A8-28-F7-A6-98-A8-0D-09-2C-43-00-00-28-F6-A6-98-A8-13-04-16-13-05-2B-2C-11-04-11-05-9A-13-06-00-11-06-6F-F1-A6-98-A8-13-07-11-07-2C-10-00-11-06-6F-F0-A6-98-A8-6F-F9-A6-98-A8-0A-2B-0F-00-11-05-17-58-13-05-11-05-11-04-8E-69-32-CC-00-06-72-5C-A7-98-D2-6F-F3-A6-98-A8-13-08-11-08-2C-12-00-06-16-06-6F-89-A6-98-A8-18-59-6F-8E-A6-98-A8-0A-00-06-28-98-A6-98-A4-0B-28-9E-A6-98-A4-0C-08-1F-0D-6F-F2-A6-98-A8-08-17-1A-6F-8E-A6-98-A8-07-08-1A-1A-6F-8E-A6-98-A8-28-ED-A6-98-A8-13-09-2B-00-11-09-2A
[+] Rellocated Bytecode: 00-72-D9-01-00-70-0A-06-7E-29-00-00-0A-28-4A-00-00-0A-0D-09-2C-43-00-00-28-4B-00-00-0A-13-04-16-13-05-2B-2C-11-04-11-05-9A-13-06-00-11-06-6F-4C-00-00-0A-13-07-11-07-2C-10-00-11-06-6F-4D-00-00-0A-6F-44-00-00-0A-0A-2B-0F-00-11-05-17-58-13-05-11-05-11-04-8E-69-32-CC-00-06-72-E1-01-00-70-6F-4E-00-00-0A-13-08-11-08-2C-12-00-06-16-06-6F-34-00-00-0A-18-59-6F-33-00-00-0A-0A-00-06-28-25-00-00-06-0B-28-23-00-00-06-0C-08-1F-0D-6F-4F-00-00-0A-08-17-1A-6F-33-00-00-0A-07-08-1A-1A-6F-33-00-00-0A-28-50-00-00-0A-13-09-2B-00-11-09-2A
[+] Overwriting bytecode for flared_16: 202-132-38-76-209-8-151-218-39-78-160-10-134-239-152-134-203-0-139-150-28-165-71-105-94-249-235-59-159-0-4-75-105-68-134-103-179-134-133-36-163-38-28-233-136-165-91-57-179-52-155-25-36-67-79-37-60-188-238-216-29-91-59-38-74-85-161-65-105-49-210-69-123-103-243-245-136-93-225-185-158-178-135-106-100-234-39-37-245-97-43-246-152-172-6-71-235-246-159-51-3-26-207-130-98-86-157-189-80-89-156-222-219-52-58-107-211-209-193-95-46-123-75-8-6-219-172-206-96-172-10-146-190-173-182-131-226-5-7-14-76-106-213-155-196-76-26-99-114-155-115-26-52-64-5-135-206-199-124-134-169-207-92-163-79-9-32-46-126-182-136-206-201-179
[+] Offset found: 0x9BE4
[+] Decrypting flared_17 (flared_17) ...
[+] Generating hash from MethodInfo for: flared_17
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Byte[]
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 8D-00-00-00
[+] Value of bytes6: System.Byte[]System.BooleanSystem.Byte[]System.IO.MemoryStreamSystem.IO.Compression.DeflateStreamSystem.Byte[]
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: ee6d9a21346018078a87ea4079959b4ed9cf153ae077c93273ea38c718b00b51
[+] Calculating method hash: ee6d9a21346018078a87ea4079959b4ed9cf153ae077c93273ea38c718b00b51
[+] Loading PE Section: ee6d9a21
[+] PE Section contents: 96-4A-D2-79-06-AD-9E-A0-55-4C-60-5A-FB-BB-CA-29-03-35-E6-17-64-32-92-2A-7A-3B-41-90-37-C5-99-5F-65-AD-C8-A7-C4-BC-BC-05-58-DB-80-16-AD-EB-01-F2-E0-7D-84-B1-F0-1C-9D-D5-04-FA-11-36-EC-53-26-82-29-10-DB-FF-57-EB-E3-0D-46-21-0F-7E-92-1B-D2-5F-60-DE-5C-F0-4A-C8-2A-E2-C6-03-4A-3F-39-D3-BF-DE-51-3C-FB-9F-5A-3A-43-81-B2-CA-8E-F5-C4-70-E2-2F-6F-53-EF-17-30-89-11-5E-51-D8-2A-D9-C8-20-A3-1F-E5-86-19-4C-32-B9-0E-DA-DB-F3-8C-ED-E8
[+] Decrypted Bytecode: 00-02-2C-08-02-8E-69-17-FE-04-2B-01-17-0B-07-2C-05-00-14-0C-2B-75-73-EC-A6-98-A8-0D-00-09-17-17-73-EF-A6-98-A8-13-04-00-11-04-02-16-02-8E-69-6F-EE-A6-98-A8-00-11-04-6F-E9-A6-98-A8-00-09-6F-E8-A6-98-A8-D4-8D-92-A6-98-A3-13-05-09-16-6A-16-6F-EB-A6-98-A8-26-09-11-05-16-09-6F-E8-A6-98-A8-69-6F-EA-A6-98-A8-26-11-05-0A-00-DE-0D-11-04-2C-08-11-04-6F-FB-A6-98-A8-00-DC-00-DE-0B-09-2C-07-09-6F-FB-A6-98-A8-00-DC-06-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-02-2C-08-02-8E-69-17-FE-04-2B-01-17-0B-07-2C-05-00-14-0C-2B-75-73-51-00-00-0A-0D-00-09-17-17-73-52-00-00-0A-13-04-00-11-04-02-16-02-8E-69-6F-53-00-00-0A-00-11-04-6F-54-00-00-0A-00-09-6F-55-00-00-0A-D4-8D-2F-00-00-01-13-05-09-16-6A-16-6F-56-00-00-0A-26-09-11-05-16-09-6F-55-00-00-0A-69-6F-57-00-00-0A-26-11-05-0A-00-DE-0D-11-04-2C-08-11-04-6F-46-00-00-0A-00-DC-00-DE-0B-09-2C-07-09-6F-46-00-00-0A-00-DC-06-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_17: 125-196-121-219-193-47-85-125-76-14-63-246-213-162-220-91-169-253-217-246-81-130-41-241-4-192-216-130-93-32-213-138-162-243-233-239-177-192-122-98-12-103-212-176-157-61-12-233-91-102-43-109-218-164-100-251-155-136-215-1-87-211-31-43-57-181-84-226-184-236-170-233-131-119-234-234-174-120-83-199-179-238-39-247-244-103-175-254-143-238-84-40-232-120-11-57-71-168-119-232-233-0-49-111-188-66-234-99-185-122-77-34-53-16-78-104-172-40-54-210-6-85-82-202-151-129-0-10-108-177-162-5-1-107-222-136-189-184-58-178-124
[+] Offset found: 0x9D90
[+] Decrypting flared_18 (flared_18) ...
[+] Generating hash from MethodInfo for: flared_18
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Byte[]
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: A6-00-00-00
[+] Value of bytes6: System.Byte[]System.BooleanSystem.Byte[]System.IO.MemoryStreamSystem.IO.Compression.DeflateStreamSystem.IO.MemoryStreamSystem.Byte[]System.Int32System.Boolean
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: c4493ff5f1dc3be5ca9fa51900dbfb69dce66febae5e025cecb68051d27eefef
[+] Calculating method hash: c4493ff5f1dc3be5ca9fa51900dbfb69dce66febae5e025cecb68051d27eefef
[+] Loading PE Section: c4493ff5
[+] PE Section contents: 96-4A-D2-79-06-AD-9E-A0-55-4C-60-5A-FB-BB-CA-29-0E-35-E6-17-77-CC-E1-C6-DC-A1-9A-78-91-54-26-45-16-4B-78-4C-88-09-20-AD-5A-DB-82-73-43-C3-F0-35-1D-DE-1C-39-F0-4D-99-BA-60-CE-2F-06-4F-49-4F-41-80-88-62-2E-CB-7F-53-84-E2-5D-E4-D1-1C-D9-C4-30-9A-7C-D5-5E-7A-D0-3D-69-B9-65-CF-71-07-E3-32-A4-39-C0-A3-05-E1-14-43-8C-95-1D-41-FD-BA-93-68-BF-D6-5D-80-32-9B-00-BC-72-85-C9-F1-BD-3A-AA-3C-BE-8A-A1-BF-0A-97-A8-D6-F0-DF-C9-88-8A-39-6A-3E-A1-3E-8E-E2-64-5E-A4-7A-11-D6-B6-66-79-38-E1-35-84-53-2A-88-42-32-2C
[+] Decrypted Bytecode: 00-02-2C-08-02-8E-69-17-FE-04-2B-01-17-0B-07-2C-08-00-14-0C-38-8B-00-00-00-02-73-E5-A6-98-A8-0D-00-09-16-73-E4-A6-98-A8-13-04-00-73-EC-A6-98-A8-13-05-00-20-00-40-00-00-8D-92-A6-98-A3-13-06-2B-0F-00-11-05-11-06-16-11-07-6F-EE-A6-98-A8-00-00-11-04-11-06-16-11-06-8E-69-6F-EA-A6-98-A8-25-13-07-16-FE-02-13-08-11-08-2D-D7-11-05-6F-E7-A6-98-A8-0A-00-DE-0D-11-05-2C-08-11-05-6F-FB-A6-98-A8-00-DC-00-DE-0D-11-04-2C-08-11-04-6F-FB-A6-98-A8-00-DC-00-DE-0B-09-2C-07-09-6F-FB-A6-98-A8-00-DC-06-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-02-2C-08-02-8E-69-17-FE-04-2B-01-17-0B-07-2C-08-00-14-0C-38-8B-00-00-00-02-73-58-00-00-0A-0D-00-09-16-73-59-00-00-0A-13-04-00-73-51-00-00-0A-13-05-00-20-00-40-00-00-8D-2F-00-00-01-13-06-2B-0F-00-11-05-11-06-16-11-07-6F-53-00-00-0A-00-00-11-04-11-06-16-11-06-8E-69-6F-57-00-00-0A-25-13-07-16-FE-02-13-08-11-08-2D-D7-11-05-6F-5A-00-00-0A-0A-00-DE-0D-11-05-2C-08-11-05-6F-46-00-00-0A-00-DC-00-DE-0D-11-04-2C-08-11-04-6F-46-00-00-0A-00-DC-00-DE-0B-09-2C-07-09-6F-46-00-00-0A-00-DC-06-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_18: 106-28-227-90-158-172-37-35-60-239-125-74-202-163-162-131-110-51-58-207-175-170-181-193-92-46-240-43-241-207-69-146-234-107-55-27-25-126-116-109-253-78-200-149-110-47-140-70-89-150-164-116-135-127-234-191-102-34-253-112-188-249-49-109-169-234-96-95-108-134-106-240-191-204-209-97-226-32-82-45-162-170-209-90-0-209-10-106-128-119-181-246-128-4-177-3-28-90-235-131-206-44-217-211-44-179-181-186-173-137-221-70-207-207-206-18-40-214-66-216-223-245-222-244-209-115-112-187-27-206-68-135-53-207-94-117-208-254-46-119-28-79-188-247-154-111-39-176-53-159-219-69-24-18-163-217-77-229-1-185-67-249-159-223-68-86
[+] Offset found: 0x9E8C
[+] Decrypting flared_19 (flared_19) ...
[+] Generating hash from MethodInfo for: flared_19
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 54-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE05+<>c__DisplayClass0_0System.BooleanSystem.Nullable`1[System.Int32]FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: cc80b00c4bb40917278fde45c00e4e4df426ba455513c251a650878d40bc2d83
[+] Calculating method hash: cc80b00c4bb40917278fde45c00e4e4df426ba455513c251a650878d40bc2d83
[+] Loading PE Section: cc80b00c
[+] PE Section contents: E5-A5-58-E9-A0-29-F7-B1-BC-35-EB-FD-74-16-E5-A3-A0-AD-56-17-5D-45-C9-42-7A-3B-41-B0-24-D8-70-4E-EB-E4-F6-9B-1F-49-1E-9D-E1-F7-77-A6-37-C1-43-9C-19-D0-1B-35-E4-0D-9F-44-EB-B0-2F-06-48-29-AF-CC-17-20-5B-DE-7C-E1-E1-B3-E5-34-71-D7-22-E9-62-3D-A0-78-CD-72
[+] Decrypted Bytecode: 73-ED-A6-98-A4-0A-00-06-17-7D-A0-A6-98-A6-28-A6-A6-98-A4-0C-12-02-28-84-A6-98-A8-2D-13-14-FE-06-FD-A6-98-A4-73-E6-A6-98-A8-28-F5-A6-98-A4-2B-01-17-0B-07-2C-14-00-06-FE-06-EC-A6-98-A4-73-E6-A6-98-A8-28-F5-A6-98-A4-26-00-06-7B-A0-A6-98-A6-0D-2B-00-09-2A
[+] Rellocated Bytecode: 73-50-00-00-06-0A-00-06-17-7D-1D-00-00-04-28-1B-00-00-06-0C-12-02-28-39-00-00-0A-2D-13-14-FE-06-40-00-00-06-73-5B-00-00-0A-28-48-00-00-06-2B-01-17-0B-07-2C-14-00-06-FE-06-51-00-00-06-73-5B-00-00-0A-28-48-00-00-06-26-00-06-7B-1D-00-00-04-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_19: 36-12-135-162-223-78-14-21-109-175-139-87-210-174-70-166-19-128-243-186-218-113-77-135-36-57-46-186-153-68-20-59-131-174-223-214-221-107-220-129-77-72-219-151-29-130-208-131-122-112-228-76-101-186-92-179-191-255-125-166-32-84-124-40-155-79-211-35-207-112-200-168-164-114-109-146-149-181-106-161-104-171-63-40
[+] Offset found: 0x9FAC
[+] Decrypting flared_20 (flared_20) ...
[+] Generating hash from MethodInfo for: flared_20
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 5B-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE05+<>c__DisplayClass2_0System.BooleanSystem.Func`1[System.Boolean]FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 30b905e5d66a3ad24630f11a9f05c361251881c82487d5aec3614474cfebbaf0
[+] Calculating method hash: 30b905e5d66a3ad24630f11a9f05c361251881c82487d5aec3614474cfebbaf0
[+] Loading PE Section: 30b905e5
[+] PE Section contents: E5-A7-58-E9-A0-29-F7-B1-BC-35-E8-FD-74-16-E6-0C-06-22-DA-17-E9-DF-45-C6-DC-DD-4C-3B-AF-6A-F0-E2-B0-DA-C8-10-4A-A9-C3-A7-EF-47-24-25-82-73-4E-9B-08-25-1A-F7-56-95-3D-C9-0B-FA-11-36-C9-56-34-C8-29-10-D5-23-F2-8C-E3-0D-41-19-0B-61-8F-76-E9-F0-8D-03-67-FE-F4-67-36-CC-D0-03-0F
[+] Decrypted Bytecode: 73-EF-A6-98-A4-0A-00-06-17-7D-A3-A6-98-A6-2B-09-00-17-28-0C-A6-98-A4-00-00-7E-A5-A6-98-A6-7E-AA-A6-98-A6-2F-26-06-7B-A2-A6-98-A6-25-2D-16-26-06-06-FE-06-EE-A6-98-A4-73-E6-A6-98-A8-25-0C-7D-A2-A6-98-A6-08-28-F5-A6-98-A4-2B-01-16-0B-07-2D-C0-06-7B-A3-A6-98-A6-0D-2B-00-09-2A
[+] Rellocated Bytecode: 73-52-00-00-06-0A-00-06-17-7D-1E-00-00-04-2B-09-00-17-28-B1-00-00-06-00-00-7E-18-00-00-04-7E-17-00-00-04-2F-26-06-7B-1F-00-00-04-25-2D-16-26-06-06-FE-06-53-00-00-06-73-5B-00-00-0A-25-0C-7D-1F-00-00-04-08-28-48-00-00-06-2B-01-16-0B-07-2D-C0-06-7B-1E-00-00-04-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_20: 51-146-106-233-123-92-129-121-240-150-196-230-58-115-182-43-99-105-178-65-220-105-216-7-246-189-238-28-93-176-174-24-60-136-169-104-97-66-204-93-222-198-175-11-118-69-131-52-219-187-156-36-162-237-158-201-185-98-243-190-110-101-27-63-231-172-169-177-202-78-202-33-157-85-98-21-185-205-145-176-57-185-65-161-19-138-117-79-234-223-174
[+] Offset found: 0xA048
[+] Decrypting flared_21 (flared_21) ...
[+] Generating hash from MethodInfo for: flared_21
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 66-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE05+<>c__DisplayClass4_0System.BooleanSystem.Func`1[System.Boolean]FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 11d539d6204eadbccd1d370ee6bc6225a8c710d5d2e34e923d7a24876b376ed7
[+] Calculating method hash: 11d539d6204eadbccd1d370ee6bc6225a8c710d5d2e34e923d7a24876b376ed7
[+] Loading PE Section: 11d539d6
[+] PE Section contents: E5-A1-58-E9-A0-29-F7-B1-BC-35-D6-FD-74-16-E6-0C-06-22-DA-17-E9-DF-45-C6-DC-DD-4F-3B-AF-6A-F0-EF-B0-DA-C8-10-5D-A9-C3-99-EF-47-24-25-82-73-4E-9B-08-25-1A-F1-56-95-3D-C9-0B-FA-11-36-C9-56-34-F6-29-10-D5-23-F2-8C-E3-0D-41-1E-01-71-FF-EC-62-A8-2D-6F-3A-59-47-C0-2D-EC-D7-27-90-D1-E4-D6-B1-2F-98-DB-76-07-FB-36
[+] Decrypted Bytecode: 73-E9-A6-98-A4-0A-00-06-17-7D-9D-A6-98-A6-2B-09-00-17-28-0C-A6-98-A4-00-00-7E-A6-A6-98-A6-7E-A7-A6-98-A6-2F-31-06-7B-9C-A6-98-A6-25-2D-16-26-06-06-FE-06-E8-A6-98-A4-73-E6-A6-98-A8-25-0C-7D-9C-A6-98-A6-08-28-F5-A6-98-A4-2C-0B-06-7B-9D-A6-98-A6-17-FE-01-2B-01-16-0B-07-2D-B5-06-7B-9D-A6-98-A6-0D-2B-00-09-2A
[+] Rellocated Bytecode: 73-54-00-00-06-0A-00-06-17-7D-20-00-00-04-2B-09-00-17-28-B1-00-00-06-00-00-7E-1B-00-00-04-7E-1A-00-00-04-2F-31-06-7B-21-00-00-04-25-2D-16-26-06-06-FE-06-55-00-00-06-73-5B-00-00-0A-25-0C-7D-21-00-00-04-08-28-48-00-00-06-2C-0B-06-7B-20-00-00-04-17-FE-01-2B-01-16-0B-07-2D-B5-06-7B-20-00-00-04-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_21: 60-145-24-75-225-105-95-223-253-55-6-74-168-164-237-110-163-156-187-24-136-74-44-207-31-35-26-106-248-91-127-137-182-234-171-20-147-229-18-217-72-65-131-49-50-80-136-232-41-20-232-133-150-92-226-242-101-73-44-189-79-244-231-162-184-124-148-189-249-216-218-189-137-225-208-70-198-250-156-207-155-50-65-227-115-250-242-90-8-185-175-74-185-84-138-84-90-225-121-181-188-202
[+] Offset found: 0xA0EC
[+] Decrypting flared_22 (flared_22) ...
[+] Generating hash from MethodInfo for: flared_22
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 67-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE05+<>c__DisplayClass6_0System.BooleanSystem.Func`1[System.Boolean]FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 8de5507bdedfad2f1bd4b340eb476abab4442cead1b922e8e18521f7d0cd7f7d
[+] Calculating method hash: 8de5507bdedfad2f1bd4b340eb476abab4442cead1b922e8e18521f7d0cd7f7d
[+] Loading PE Section: 8de5507b
[+] PE Section contents: E5-A3-58-E9-A0-29-F7-B1-BC-35-D4-FD-74-16-E6-0C-06-22-DA-17-E9-DF-45-C6-DC-DD-4C-3B-AF-6A-F0-E2-B0-DA-C8-10-5E-D1-1E-A3-D1-79-FC-A7-09-FD-CE-B2-28-DD-67-87-56-95-3F-9F-C0-4A-AF-98-EA-A4-4F-80-29-10-D7-58-3C-DF-DD-3D-C0-3E-77-E9-22-E9-62-38-A3-8D-62-C0-C8-EA-3A-F1-DB-0D-08-63-99-30-88-11-A6-70-50-2C-F2-15-78
[+] Decrypted Bytecode: 73-EB-A6-98-A4-0A-00-06-17-7D-9F-A6-98-A6-2B-09-00-17-28-0C-A6-98-A4-00-00-7E-A5-A6-98-A6-7E-AA-A6-98-A6-2F-32-7E-A6-A6-98-A6-7E-A7-A6-98-A6-2F-26-06-7B-9E-A6-98-A6-25-2D-16-26-06-06-FE-06-EA-A6-98-A4-73-E6-A6-98-A8-25-0C-7D-9E-A6-98-A6-08-28-F5-A6-98-A4-2B-01-16-0B-07-2D-B4-06-7B-9F-A6-98-A6-0D-2B-00-09-2A
[+] Rellocated Bytecode: 73-56-00-00-06-0A-00-06-17-7D-22-00-00-04-2B-09-00-17-28-B1-00-00-06-00-00-7E-18-00-00-04-7E-17-00-00-04-2F-32-7E-1B-00-00-04-7E-1A-00-00-04-2F-26-06-7B-23-00-00-04-25-2D-16-26-06-06-FE-06-57-00-00-06-73-5B-00-00-0A-25-0C-7D-23-00-00-04-08-28-48-00-00-06-2B-01-16-0B-07-2D-B4-06-7B-22-00-00-04-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_22: 67-64-84-164-94-63-90-199-235-0-26-136-152-174-136-190-99-162-247-87-218-85-15-200-13-49-99-33-246-88-111-154-149-133-138-59-230-244-99-74-131-164-39-47-249-35-110-69-224-238-216-162-241-107-201-238-49-139-151-44-220-57-209-147-187-128-243-18-36-77-216-110-63-173-212-53-45-224-206-234-195-29-64-8-127-204-168-0-188-155-10-90-93-54-109-73-211-148-116-121-47-91-33
[+] Offset found: 0xA19C
[+] Decrypting flared_23 (flared_23) ...
[+] Generating hash from MethodInfo for: flared_23
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: 49-00-00-00
[+] Value of bytes6: System.Byte[]System.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7: FlareOn.Backdoor.FLARE07&
[+] Final SHA256: 4f0f2ca37f08cf119f3185e28118947d704968babe1557b56db844a614098cd7
[+] Calculating method hash: 4f0f2ca37f08cf119f3185e28118947d704968babe1557b56db844a614098cd7
[+] Loading PE Section: 4f0f2ca3
[+] PE Section contents: 96-50-80-D4-A2-BB-51-9F-B1-EE-D3-FF-F5-CE-7E-A3-9E-93-E4-74-C4-E1-79-6E-B3-42-4F-05-9F-E4-77-EE-8E-E6-6E-3D-7B-FB-AA-05-61-24-24-98-0B-6E-6F-B1-06-DD-34-EE-56-95-3D-91-EC-4A-85-96-C0-5F-49-68-96-DC-73-2C-D7-52-45-9C-CF
[+] Decrypted Bytecode: 00-18-7E-A5-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-28-F9-A6-98-A4-00-02-17-54-12-00-28-FB-A6-98-A4-0B-07-2C-08-06-28-F7-A6-98-A4-2B-01-16-0C-08-2C-05-00-02-19-54-00-07-0D-2B-00-09-2A
[+] Rellocated Bytecode: 00-18-7E-18-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-28-44-00-00-06-00-02-17-54-12-00-28-46-00-00-06-0B-07-2C-08-06-28-4A-00-00-06-2B-01-16-0C-08-2C-05-00-02-19-54-00-07-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_23: 195-38-149-203-154-23-29-12-196-61-164-56-225-68-222-246-139-223-155-145-132-220-126-119-82-255-225-228-43-215-7-65-130-121-149-83-102-119-148-223-73-93-179-38-65-172-226-39-165-131-212-123-138-48-77-231-168-29-120-154-54-57-224-237-54-99-182-103-175-138-143-19-74
[+] Offset found: 0xA24C
[+] Decrypting flared_24 (flared_24) ...
[+] Generating hash from MethodInfo for: flared_24
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 6
[+] Value of bytes5: 26-01-00-00
[+] Value of bytes6: System.Int32System.Int32System.Byte[]System.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7: FlareOn.Backdoor.FLARE07&
[+] Final SHA256: 85b3a7dd78eb9d17c2832a9c0bf0db35aa018f34dde74bcf4a47d98409e1ec52
[+] Calculating method hash: 85b3a7dd78eb9d17c2832a9c0bf0db35aa018f34dde74bcf4a47d98409e1ec52
[+] Loading PE Section: 85b3a7dd
[+] PE Section contents: 96-36-59-D7-9C-85-89-11-0D-D0-ED-02-E6-CE-7D-A3-9E-93-F4-33-AF-E1-79-6E-D7-DD-4F-3B-AF-6A-98-B6-17-51-6A-2E-68-83-DD-05-5E-A1-24-A6-37-C3-40-87-A8-43-B8-00-8E-BE-3F-22-4B-4A-E6-15-4A-C2-E1-05-6E-2E-EB-83-A4-DE-E3-0D-43-1A-10-D1-1C-D5-DD-4E-38-DE-5C-FE-7A-AE-B0-41-48-A2-4A-36-39-D3-BF-C9-9F-70-C5-A1-8C-BA-F4-1C-1E-E2-E9-5E-4D-FD-C9-0F-C6-F1-18-65-BE-AA-1F-C6-04-F0-4B-74-59-A8-8C-B0-2C-E5-17-FC-63-1F-4A-78-D7-D8-A7-AD-C2-DB-D8-AF-98-CA-44-92-4F-0B-CE-B2-C6-A7-2E-79-38-EF-23-37-DE-80-3B-EA-55-E7-AF-FA-9C-95-56-86-BB-97-50-C0-3B-E1-10-42-B9-38-35-D8-8B-71-A8-84-6A-C1-AF-06-7F-0D-7A-75-74-7D-67-48-44-4E-D0-ED-A1-16-21-7C-64-EE-FE-FA-68-4E-D0-BF-53-2B-19-F8-28-0C-C0-51-06-29-EB-51-8F-E7-CA-CA-B3-F6-6C-C4-09-A5-26-EE-F0-D8-0D-A7-0A-B2-33-31-60-47-BE-5B-B5-29-26-3B-C3-63-74-DE-FD-42-51-8A-3F-BC-B3-0F-B2-20-36-F1-44-C8-D9-3A-45-36-8D-06-3A-AD-96-8E-7B-39-4C-68-0A-61-4E-51-2A-99
[+] Decrypted Bytecode: 00-7E-A7-A6-98-A6-7E-A6-A6-98-A6-59-0A-7E-B0-A6-98-A6-06-28-E0-A6-98-A8-0B-7E-A6-A6-98-A6-16-FE-01-13-04-11-04-2C-65-00-17-7E-A6-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-7E-A7-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-7E-A1-A6-98-A6-7E-A6-A6-98-A6-28-B9-A6-98-89-07-28-B8-A6-98-89-28-BB-A6-98-89-28-BF-A6-98-A4-28-A6-A6-98-A8-28-F9-A6-98-A4-00-00-2B-48-00-17-7E-A6-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-7E-A1-A6-98-A6-7E-A6-A6-98-A6-28-B9-A6-98-89-07-28-B8-A6-98-89-28-BB-A6-98-89-28-BF-A6-98-A4-28-95-A6-98-A8-28-F9-A6-98-A4-00-00-02-17-54-12-02-28-FB-A6-98-A4-0D-09-13-05-11-05-2C-38-00-08-28-F1-A6-98-A4-13-06-11-06-2C-05-00-02-18-54-00-07-28-F3-A6-98-A4-13-07-11-07-2C-19-00-02-4A-18-FE-01-13-08-11-08-2C-09-00-02-1C-54-09-13-09-2B-0A-02-1B-54-00-00-09-13-09-2B-00-11-09-2A
[+] Rellocated Bytecode: 00-7E-1A-00-00-04-7E-1B-00-00-04-59-0A-7E-0D-00-00-04-06-28-5D-00-00-0A-0B-7E-1B-00-00-04-16-FE-01-13-04-11-04-2C-65-00-17-7E-1B-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-7E-1A-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-7E-1C-00-00-04-7E-1B-00-00-04-28-04-00-00-2B-07-28-05-00-00-2B-28-06-00-00-2B-28-02-00-00-06-28-1B-00-00-0A-28-44-00-00-06-00-00-2B-48-00-17-7E-1B-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-7E-1C-00-00-04-7E-1B-00-00-04-28-04-00-00-2B-07-28-05-00-00-2B-28-06-00-00-2B-28-02-00-00-06-28-28-00-00-0A-28-44-00-00-06-00-00-02-17-54-12-02-28-46-00-00-06-0D-09-13-05-11-05-2C-38-00-08-28-4C-00-00-06-13-06-11-06-2C-05-00-02-18-54-00-07-28-4E-00-00-06-13-07-11-07-2C-19-00-02-4A-18-FE-01-13-08-11-08-2C-09-00-02-1C-54-09-13-09-2B-0A-02-1B-54-00-00-09-13-09-2B-00-11-09-2A
[+] Overwriting bytecode for flared_24: 36-45-3-176-192-111-163-230-53-96-70-230-210-118-204-227-136-219-182-163-185-123-110-117-71-253-16-87-226-148-10-246-4-49-83-143-50-248-169-26-46-65-137-171-5-195-43-19-150-69-43-217-8-117-15-168-191-142-105-194-94-75-4-160-86-79-225-161-34-60-177-143-50-155-116-120-242-194-111-131-210-253-193-156-105-49-238-143-33-171-208-163-142-230-187-227-61-232-85-182-225-137-240-89-148-155-166-108-0-151-182-252-30-229-239-97-138-103-55-37-97-82-127-119-108-13-0-75-224-145-59-9-108-185-161-72-12-104-8-205-138-129-142-138-245-211-133-168-246-90-88-213-177-48-85-143-10-120-236-135-154-90-140-111-92-172-143-101-68-166-84-34-95-105-154-223-195-244-130-152-135-88-84-133-56-101-88-60-100-18-62-147-123-128-50-47-245-31-46-72-67-32-100-80-6-54-118-71-149-117-204-21-246-84-255-66-5-7-54-246-84-83-0-49-104-192-167-222-55-107-234-164-198-57-84-103-243-4-127-2-238-16-167-238-69-40-157-39-129-239-41-237-232-55-244-240-31-51-231-69-143-151-16-0-139-39-79-188-255-151-79-1-136-52-8-67-171-17-235-63-34-127-93-71-65-252-187-142-69-100-72-192-29-57
[+] Offset found: 0xA300
[+] Decrypting flared_25 (flared_25) ...
[+] Generating hash from MethodInfo for: flared_25
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 6
[+] Value of bytes5: CC-00-00-00
[+] Value of bytes6: System.Int32System.Int32System.Byte[]System.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7: FlareOn.Backdoor.FLARE07&
[+] Final SHA256: 520c23900a8cc6b701184426230786fc29f82f39b50c6a75b5f7418e34d1c39b
[+] Calculating method hash: 520c23900a8cc6b701184426230786fc29f82f39b50c6a75b5f7418e34d1c39b
[+] Loading PE Section: 520c2390
[+] PE Section contents: 96-36-59-D7-9C-85-89-11-0D-D0-ED-02-E6-CE-7D-A3-9E-93-F4-33-AF-E1-79-6E-D7-BA-97-3B-91-54-28-60-0C-E4-F6-9B-75-D1-0B-A3-D1-79-94-6F-24-C3-F0-35-61-3A-BA-81-58-73-3C-1C-75-FA-A1-84-4A-C2-ED-73-F1-3B-D5-B3-7C-6F-2A-1E-43-AA-A2-18-65-D7-5C-98-F5-D9-62-C0-CA-BF-9D-41-48-AC-0D-6E-39-D3-9E-B0-16-6E-FB-9F-7B-34-E9-22-20-43-78-47-73-EC-6A-0F-D8-F1-18-44-BE-E8-1F-C6-29-D8-F6-C5-95-1E-A6-3E-71-DB-27-70-97-B0-C1-D8-C6-DC-A0-DD-C2-C4-8E-FE-98-CA-46-A9-50-BC-53-3A-DA-D9-9F-C6-F4-49-32-70-A6-80-3B-E6-29-00-18-64-18-F2-F7-22-69-28-D0-67-8E-7E-A7-6D-2C-97-AD-53-91-0D-19-31-FA-63-8D-BF-C2-C1-F3-5D-C2-C8-F7-C7-6C-CA-7E-5F
[+] Decrypted Bytecode: 00-7E-A7-A6-98-A6-7E-A6-A6-98-A6-59-0A-7E-B0-A6-98-A6-06-28-E0-A6-98-A8-0B-19-7E-A6-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-7E-A5-A6-98-A6-28-1A-A6-98-A4-19-7E-B3-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-7E-A1-A6-98-A6-7E-A6-A6-98-A6-28-B9-A6-98-89-07-28-B8-A6-98-89-28-BB-A6-98-89-28-BF-A6-98-A4-28-A6-A6-98-A8-28-F9-A6-98-A4-00-02-17-54-12-02-28-FB-A6-98-A4-0D-09-13-04-11-04-2C-38-00-08-28-F7-A6-98-A4-13-05-11-05-2C-05-00-02-19-54-00-07-28-F3-A6-98-A4-13-06-11-06-2C-19-00-02-4A-19-FE-01-13-07-11-07-2C-09-00-02-1D-54-09-13-08-2B-0A-02-1B-54-00-00-09-13-08-2B-00-11-08-2A
[+] Rellocated Bytecode: 00-7E-1A-00-00-04-7E-1B-00-00-04-59-0A-7E-0D-00-00-04-06-28-5D-00-00-0A-0B-19-7E-1B-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-7E-18-00-00-04-28-A7-00-00-06-19-7E-0E-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-7E-1C-00-00-04-7E-1B-00-00-04-28-04-00-00-2B-07-28-05-00-00-2B-28-06-00-00-2B-28-02-00-00-06-28-1B-00-00-0A-28-44-00-00-06-00-02-17-54-12-02-28-46-00-00-06-0D-09-13-04-11-04-2C-38-00-08-28-4A-00-00-06-13-05-11-05-2C-05-00-02-19-54-00-07-28-4E-00-00-06-13-06-11-06-2C-19-00-02-4A-19-FE-01-13-07-11-07-2C-09-00-02-1D-54-09-13-08-2B-0A-02-1B-54-00-00-09-13-08-2B-00-11-08-2A
[+] Overwriting bytecode for flared_25: 69-93-175-22-187-157-10-113-76-63-85-187-31-120-245-89-157-66-89-122-232-5-93-53-60-173-221-1-105-14-170-180-22-216-171-188-130-162-82-207-45-66-136-135-251-35-146-79-25-185-254-158-222-103-80-63-0-121-217-14-192-9-8-61-148-160-164-70-204-57-214-251-239-137-77-166-125-214-57-24-26-142-231-176-16-12-214-175-135-107-188-8-200-68-15-36-58-75-243-90-127-76-130-224-226-2-174-84-26-170-194-41-64-192-243-49-34-87-44-135-202-245-190-97-125-205-50-171-121-40-108-49-227-223-153-206-11-6-205-13-94-130-148-221-168-146-200-8-80-222-2-226-30-107-144-137-141-32-99-20-208-2-219-241-62-145-70-96-38-36-37-27-138-31-40-72-97-224-185-234-5-0-90-155-38-137-19-119-78-16-65-235-163-184-61-92-166-163-158-23-76-103-225-44
[+] Offset found: 0xA490
[+] Decrypting flared_26 (flared_26) ...
[+] Generating hash from MethodInfo for: flared_26
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 33-00-00-00
[+] Value of bytes6: System.Byte[]System.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7: FlareOn.Backdoor.FLARE07&
[+] Final SHA256: f965be7303dbadaee57d174da473ba7b9297feb886fb008c1f89e0a125c44519
[+] Calculating method hash: f965be7303dbadaee57d174da473ba7b9297feb886fb008c1f89e0a125c44519
[+] Loading PE Section: f965be73
[+] PE Section contents: 96-52-80-E5-A2-BB-5F-9F-52-EE-D3-FF-EC-B2-DA-51-14-35-DA-E0-E9-DF-45-CD-DB-8F-E1-9B-1F-3D-28-D0-B2-69-6F-29-60-A7-94-00-49-DD-9A-54-AF-62-65-B6-0E-D2-36
[+] Decrypted Bytecode: 00-1A-7E-94-A6-98-A8-28-F9-A6-98-A4-00-02-17-54-12-00-28-FB-A6-98-A4-0B-07-2C-08-06-28-F1-A6-98-A4-2B-01-16-0C-08-2C-05-00-02-18-54-00-07-0D-2B-00-09-2A
[+] Rellocated Bytecode: 00-1A-7E-29-00-00-0A-28-44-00-00-06-00-02-17-54-12-00-28-46-00-00-06-0B-07-2C-08-06-28-4C-00-00-06-2B-01-16-0C-08-2C-05-00-02-18-54-00-07-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_26: 247-133-117-220-215-127-231-202-51-193-73-235-182-76-50-86-106-255-250-220-7-111-29-47-88-214-196-202-231-235-152-217-23-112-81-48-59-8-133-101-234-203-33-184-57-96-177-141-17-224-18
[+] Offset found: 0xA5C4
[+] Decrypting flared_27 (flared_27) ...
[+] Generating hash from MethodInfo for: flared_27
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 2B-00-00-00
[+] Value of bytes6: System.Byte[]System.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7:
[+] Final SHA256: 0651f80b2cb667ae922cbf418343ac73f73956788d9f8a729bab11e1cf35a85e
[+] Calculating method hash: 0651f80b2cb667ae922cbf418343ac73f73956788d9f8a729bab11e1cf35a85e
[+] Loading PE Section: 0651f80b
[+] PE Section contents: 96-5E-80-DC-A2-BB-51-9F-52-EE-D3-FF-EC-A2-CD-2D-FD-93-6A-BF-44-40-ED-CE-F0-A8-E9-9B-2E-5D-A6-E0-B0-DA-CA-3F-6C-A8-B5-2E-49-D6-A8
[+] Decrypted Bytecode: 00-16-7E-AD-A6-98-A6-28-F9-A6-98-A4-00-12-00-28-FB-A6-98-A4-0B-07-0C-08-2C-0B-00-06-19-91-28-A8-A6-98-A4-00-00-07-0D-2B-00-09-2A
[+] Rellocated Bytecode: 00-16-7E-10-00-00-04-28-44-00-00-06-00-12-00-28-46-00-00-06-0B-07-0C-08-2C-0B-00-06-19-91-28-15-00-00-06-00-00-07-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_27: 139-247-178-147-30-85-189-64-113-110-164-40-219-236-120-48-45-113-226-197-111-68-229-38-4-36-20-176-212-125-155-175-220-228-217-163-65-176-86-122-113-206-107
[+] Offset found: 0xA660
[+] Decrypting flared_28 (flared_28) ...
[+] Generating hash from MethodInfo for: flared_28
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 8
[+] Value of bytes5: 16-00-00-00
[+] Value of bytes6:
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: 846fcbb2e5f6c174ad51ca99b9f088effefc36c8e67a37df6019289da27fe09b
[+] Calculating method hash: 846fcbb2e5f6c174ad51ca99b9f088effefc36c8e67a37df6019289da27fe09b
[+] Loading PE Section: 846fcbb2
[+] PE Section contents: 96-5E-7E-D7-A2-BB-51-B5-25-21-CB-FC-4A-28-6B-07-86-94-54-83-E9-6D
[+] Decrypted Bytecode: 00-16-80-A6-A6-98-A6-02-8E-69-80-A7-A6-98-A6-02-80-A1-A6-98-A6-2A
[+] Rellocated Bytecode: 00-16-80-1B-00-00-04-02-8E-69-80-1A-00-00-04-02-80-1C-00-00-04-2A
[+] Overwriting bytecode for flared_28: 159-189-77-236-230-50-112-183-56-150-110-19-75-203-255-147-123-161-151-119-251-30
[+] Offset found: 0x909E
[+] Decrypting flared_29 (flared_29) ...
[+] Generating hash from MethodInfo for: flared_29
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: BF-00-00-00
[+] Value of bytes6: System.BooleanSystem.StringSystem.BooleanSystem.Nullable`1[System.Int32]System.Boolean
[+] Value of bytes7: FlareOn.Backdoor.FLARE06+DomTSystem.String
[+] Final SHA256: edd1976b2b2ba673e1e95247a54238a9b27fb7965bbb117e306524d93e3f99f1
[+] Calculating method hash: edd1976b2b2ba673e1e95247a54238a9b27fb7965bbb117e306524d93e3f99f1
[+] Loading PE Section: edd1976b
[+] PE Section contents: 96-36-55-D7-9C-85-E1-49-AA-42-4D-62-42-B0-CD-05-06-37-E8-E5-4E-4B-E9-EA-C7-A3-C1-3B-91-54-2A-45-04-41-46-B8-CA-37-10-2D-53-79-1A-A4-2F-CD-CE-05-A8-DB-37-5D-F2-1B-67-BB-FE-58-98-9A-C0-4F-49-68-A7-92-D5-B3-7E-7A-6D-00-43-AA-A2-F7-2C-D7-5C-96-8B-53-E1-58-6E-E9-21-41-48-AE-0D-71-39-D3-B3-BA-2C-D5-75-80-54-84-FA-AC-A2-6C-C8-5C-D6-5C-68-81-E6-FF-00-44-30-89-1F-5E-A5-7C-52-4A-65-24-BA-B0-12-D9-B4-AA-32-1F-4A-7A-D0-F0-94-43-5A-68-8E-AD-98-CA-46-92-41-0B-CE-B2-C6-A7-2F-79-38-EF-23-37-DE-80-3B-EA-55-E7-AF-FA-9C-99-EF-84-BB-E3-06-FA-3B-E1-12-42-ED-38-35-F9-0C-F1-B6-BA-54-48-AD
[+] Decrypted Bytecode: 00-7E-AB-A6-98-A6-16-FE-01-0A-06-39-AE-00-00-00-00-02-1A-FE-01-0C-08-2C-1B-00-28-A6-A6-98-A4-0D-12-03-28-87-A6-98-A8-28-1A-A6-98-A4-80-A8-A6-98-A6-00-2B-44-02-16-FE-01-13-04-11-04-2C-15-00-02-28-1A-A6-98-A4-03-28-95-A6-98-A8-80-A8-A6-98-A6-00-2B-25-00-02-28-1A-A6-98-A4-28-A6-A6-98-A4-0D-12-03-28-87-A6-98-A8-28-1A-A6-98-A4-03-28-A6-A6-98-A8-80-A8-A6-98-A6-00-28-A4-A6-98-A4-28-1E-A6-98-A4-0B-7E-A8-A6-98-A6-07-28-18-A6-98-A4-28-A4-A6-98-A4-28-14-A6-98-A4-19-7E-B2-A6-98-A6-16-6F-8B-A6-98-A8-6F-E1-A6-98-A8-72-18-A4-98-D2-28-9C-A6-98-A4-28-ED-A6-98-A8-80-A8-A6-98-A6-00-2A
[+] Rellocated Bytecode: 00-7E-16-00-00-04-16-FE-01-0A-06-39-AE-00-00-00-00-02-1A-FE-01-0C-08-2C-1B-00-28-1B-00-00-06-0D-12-03-28-3A-00-00-0A-28-A7-00-00-06-80-15-00-00-04-00-2B-44-02-16-FE-01-13-04-11-04-2C-15-00-02-28-A7-00-00-06-03-28-28-00-00-0A-80-15-00-00-04-00-2B-25-00-02-28-A7-00-00-06-28-1B-00-00-06-0D-12-03-28-3A-00-00-0A-28-A7-00-00-06-03-28-1B-00-00-0A-80-15-00-00-04-00-28-19-00-00-06-28-A3-00-00-06-0B-7E-15-00-00-04-07-28-A5-00-00-06-28-19-00-00-06-28-A9-00-00-06-19-7E-0F-00-00-04-16-6F-36-00-00-0A-6F-5C-00-00-0A-72-A5-02-00-70-28-21-00-00-06-28-50-00-00-0A-80-15-00-00-04-00-2A
[+] Overwriting bytecode for flared_29: 150-147-44-212-235-5-53-125-139-0-137-213-78-89-215-148-122-219-6-21-34-15-208-67-16-39-178-41-28-249-51-123-253-84-47-103-9-239-179-32-32-72-241-218-206-159-117-10-232-52-236-33-175-202-36-135-194-232-195-195-83-12-96-146-247-14-216-250-0-112-138-138-39-229-245-218-29-246-117-112-178-167-64-231-12-18-203-50-48-167-164-33-44-239-205-19-231-95-226-191-198-123-224-120-169-97-249-202-213-73-106-204-114-83-17-171-203-120-133-229-67-166-201-130-203-105-94-56-24-225-243-190-19-182-170-55-199-200-61-170-25-1-92-230-61-216-174-216-222-34-72-110-217-253-124-32-177-93-172-64-3-193-177-243-86-171-184-188-168-218-228-2-58-219-204-65-74-227-69-242-187-133-89-245-153-132-229-22-57-138-133
[+] Offset found: 0xA714
[+] Decrypting flared_30 (flared_30) ...
[+] Generating hash from MethodInfo for: flared_30
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 49-00-00-00
[+] Value of bytes6: System.BooleanSystem.Net.IPHostEntrySystem.Boolean
[+] Value of bytes7: System.Byte[]&
[+] Final SHA256: 9181748dca8875decbf8e9ded90515da514028154a2396682a4ffc705e43c4c7
[+] Calculating method hash: 9181748dca8875decbf8e9ded90515da514028154a2396682a4ffc705e43c4c7
[+] Loading PE Section: 9181748d
[+] PE Section contents: 96-5F-F4-73-10-72-F7-C9-03-EE-D3-FD-C4-6D-6B-9D-AE-3E-F0-1C-20-9B-47-5E-74-B5-73-F2-E8-6A-16-E0-47-54-EE-94-CA-37-1E-2D-E3-79-1A-A4-AF-65-B6-8E-28-DB-62-B2-56-95-3F-AD-B5-DC-22-38-74-FC-5F-60-8F-56-73-2D-D6-52-45-9D-CF
[+] Decrypted Bytecode: 00-17-0A-02-14-51-00-7E-A8-A6-98-A6-28-DD-A6-98-A8-0B-02-07-6F-DC-A6-98-A8-16-9A-6F-DF-A6-98-A8-51-16-80-AB-A6-98-A6-28-AA-A6-98-A4-00-00-DE-13-26-00-7E-AB-A6-98-A6-17-58-80-AB-A6-98-A6-16-0A-00-DE-00-06-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-17-0A-02-14-51-00-7E-15-00-00-04-28-60-00-00-0A-0B-02-07-6F-61-00-00-0A-16-9A-6F-62-00-00-0A-51-16-80-16-00-00-04-28-17-00-00-06-00-00-DE-13-26-00-7E-16-00-00-04-17-58-80-16-00-00-04-16-0A-00-DE-00-06-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_30: 143-75-202-251-26-89-118-145-112-76-201-224-234-138-69-226-107-191-0-31-138-233-43-55-128-233-219-30-191-192-132-183-56-167-108-165-149-225-112-100-101-134-180-90-230-17-97-61-206-239-24-213-60-6-58-165-32-146-123-49-125-88-210-176-199-18-167-66-30-160-77-138-79
[+] Offset found: 0xA82C
[+] Decrypting flared_31 (flared_31) ...
[+] Generating hash from MethodInfo for: flared_31
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 5C-00-00-00
[+] Value of bytes6: System.BooleanSystem.BooleanSystem.BooleanSystem.Boolean
[+] Value of bytes7: System.Func`1[System.Boolean]
[+] Final SHA256: 3460378b704cb824bf52d41dedc68d99a1afedee8d70267a29841721775572de
[+] Calculating method hash: 3460378b704cb824bf52d41dedc68d99a1afedee8d70267a29841721775572de
[+] Loading PE Section: 3460378b
[+] PE Section contents: 96-5E-F4-67-84-88-51-2F-0D-63-42-5B-F5-98-C1-A3-9E-91-F2-1B-4D-28-3F-60-44-0B-C4-93-49-67-28-D0-B0-3C-D8-99-F4-09-46-01-62-DE-94-0B-A8-48-B4-E3-A5-7D-84-BF-8E-BB-3F-22-4B-A2-8D-88-12-5B-45-62-A3-98-73-3D-5A-D2-E3-0D-43-1A-A0-D1-1C-D5-C4-30-A0-7C-C4-4F-66-C1-3D-EA-FB-0A-2C-FD
[+] Decrypted Bytecode: 00-16-0A-16-80-AB-A6-98-A6-2B-09-00-19-28-0C-A6-98-A4-00-00-02-6F-DE-A6-98-A8-2D-0E-7E-AB-A6-98-A6-7E-B6-A6-98-A6-FE-04-2B-01-16-0B-07-2D-DC-7E-AB-A6-98-A6-7E-B6-A6-98-A6-FE-04-16-FE-01-0C-08-2C-10-00-16-80-AB-A6-98-A6-28-AA-A6-98-A4-00-00-2B-04-00-17-0A-00-06-0D-2B-00-09-2A
[+] Rellocated Bytecode: 00-16-0A-16-80-16-00-00-04-2B-09-00-19-28-B1-00-00-06-00-00-02-6F-63-00-00-0A-2D-0E-7E-16-00-00-04-7E-0B-00-00-04-FE-04-2B-01-16-0B-07-2D-DC-7E-16-00-00-04-7E-0B-00-00-04-FE-04-16-FE-01-0C-08-2C-10-00-16-80-16-00-00-04-28-17-00-00-06-00-00-2B-04-00-17-0A-00-06-0D-2B-00-09-2A
[+] Overwriting bytecode for flared_31: 186-11-157-176-33-57-232-31-243-83-102-196-237-111-0-101-166-250-46-61-143-59-237-176-32-218-78-111-10-10-222-167-176-232-154-59-48-86-232-115-248-16-117-213-25-222-125-210-211-119-95-209-255-246-39-127-29-236-144-70-235-120-20-233-117-191-19-5-212-239-52-79-17-186-69-126-197-24-150-66-93-123-156-147-170-12-168-186-192-27-30-68
[+] Offset found: 0xA90C
[+] Decrypting flared_32 (flared_32) ...
[+] Generating hash from MethodInfo for: flared_32
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: A1-00-00-00
[+] Value of bytes6: System.Int32System.UInt16System.BooleanSystem.Byte[]System.Boolean
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: e530c0106f2f9e2498ef8cc04c59d7e721caa3dc018c4c8450e4d395e6e92176
[+] Calculating method hash: e530c0106f2f9e2498ef8cc04c59d7e721caa3dc018c4c8450e4d395e6e92176
[+] Loading PE Section: e530c010
[+] PE Section contents: 96-36-54-D7-9C-85-89-12-0D-D0-ED-02-E6-B2-43-6C-00-1D-12-BD-D7-EF-30-CD-DE-B5-97-39-91-54-28-36-B3-E4-F6-99-6B-87-61-A3-D1-77-82-7E-0A-C3-F0-3B-14-83-9C-BC-56-95-3F-C4-48-FA-11-38-92-F0-EF-F2-29-76-77-3D-24-78-49-9D-C9-7D-0A-09-2E-D7-5C-96-06-EA-62-C0-CF-CC-45-43-76-92-83-C1-96-5D-69-1D-98-4E-FB-2F-2B-BA-CA-2C-B8-B4-C7-5F-4D-D2-C7-48-A6-F1-18-44-96-07-39-FB-2B-40-52-C4-41-A6-02-8E-2C-03-1B-72-02-1F-C4-A2-73-7E-14-43-4C-A5-8E-D2-98-CA-4A-BA-42-BE-52-3D-DA-CF-8E-DB-8B-49-24-5C-7F
[+] Decrypted Bytecode: 00-7E-AA-A6-98-A6-7E-A5-A6-98-A6-59-0A-02-8E-69-06-28-E0-A6-98-A8-D1-0B-02-16-7E-A4-A6-98-A6-7E-A5-A6-98-A6-07-28-D9-A6-98-A8-00-7E-A5-A6-98-A6-1A-58-80-A5-A6-98-A6-7E-A5-A6-98-A6-7E-AA-A6-98-A6-FE-04-16-FE-01-0C-08-2C-4F-00-7E-AA-A6-98-A6-8D-92-A6-98-A3-0D-7E-A4-A6-98-A6-16-09-16-7E-AA-A6-98-A6-28-D9-A6-98-A8-00-7E-97-A7-98-A6-09-6F-D8-A6-98-A8-00-16-80-A5-A6-98-A6-16-80-AA-A6-98-A6-7E-A4-A6-98-A6-16-7E-A4-A6-98-A6-8E-69-28-DB-A6-98-A8-00-17-13-04-2B-05-16-13-04-2B-00-11-04-2A
[+] Rellocated Bytecode: 00-7E-17-00-00-04-7E-18-00-00-04-59-0A-02-8E-69-06-28-5D-00-00-0A-D1-0B-02-16-7E-19-00-00-04-7E-18-00-00-04-07-28-64-00-00-0A-00-7E-18-00-00-04-1A-58-80-18-00-00-04-7E-18-00-00-04-7E-17-00-00-04-FE-04-16-FE-01-0C-08-2C-4F-00-7E-17-00-00-04-8D-2F-00-00-01-0D-7E-19-00-00-04-16-09-16-7E-17-00-00-04-28-64-00-00-0A-00-7E-2A-01-00-04-09-6F-65-00-00-0A-00-16-80-18-00-00-04-16-80-17-00-00-04-7E-19-00-00-04-16-7E-19-00-00-04-8E-69-28-66-00-00-0A-00-17-13-04-2B-05-16-13-04-2B-00-11-04-2A
[+] Overwriting bytecode for flared_32: 138-49-144-179-134-58-20-122-168-222-85-255-14-242-115-204-112-227-26-144-135-121-81-190-195-111-163-77-200-82-125-14-190-120-119-32-184-34-27-125-221-80-62-235-150-69-19-104-183-64-36-113-44-40-253-16-223-210-240-22-150-199-178-85-96-71-65-150-123-82-19-77-199-157-179-55-58-102-39-125-92-58-149-136-46-12-225-149-122-103-64-230-50-5-231-22-158-232-138-79-4-125-237-100-45-214-170-143-117-197-213-121-170-114-186-91-49-41-39-84-101-171-27-20-18-44-27-194-182-157-153-81-220-216-120-222-77-48-91-87-98-82-31-181-145-199-59-191-74-139-228-116-193-53-233-89-97-217-82-0-187
[+] Offset found: 0xA9B8
[+] Decrypting flared_33 (flared_33) ...
[+] Generating hash from MethodInfo for: flared_33
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 4E-00-00-00
[+] Value of bytes6: System.BooleanSystem.Boolean
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: f9a758d38e2e4e3641c0fafbac22ffa3314edbaba50e6e5538e3a99a193def7f
[+] Calculating method hash: f9a758d38e2e4e3641c0fafbac22ffa3314edbaba50e6e5538e3a99a193def7f
[+] Loading PE Section: f9a758d3
[+] PE Section contents: 96-4A-E8-E0-24-A3-F7-B7-AB-B6-4F-4D-12-B1-C7-03-2A-03-F2-0D-CF-E2-47-5E-7A-A1-FE-B5-8E-6A-16-C1-0F-6A-D6-99-F4-26-90-BE-EF-47-0B-28-B9-C3-F0-39-8E-71-BA-81-56-73-33-1C-75-FA-04-0C-4A-C2-EA-EA-2B-2E-EB-8D-CD-72-6E-91-F3-39-21-77-83-5B
[+] Decrypted Bytecode: 00-02-16-91-20-80-00-00-00-FE-04-16-FE-01-0A-06-2C-36-00-16-80-A5-A6-98-A6-02-17-28-B9-A6-98-89-19-28-B8-A6-98-89-28-BB-A6-98-89-28-16-A6-98-A4-80-AA-A6-98-A6-7E-AA-A6-98-A6-8D-92-A6-98-A3-80-A4-A6-98-A6-17-0B-2B-04-16-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-02-16-91-20-80-00-00-00-FE-04-16-FE-01-0A-06-2C-36-00-16-80-18-00-00-04-02-17-28-04-00-00-2B-19-28-05-00-00-2B-28-06-00-00-2B-28-AB-00-00-06-80-17-00-00-04-7E-17-00-00-04-8D-2F-00-00-01-80-19-00-00-04-17-0B-2B-04-16-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_33: 220-12-170-11-14-217-136-13-93-78-78-175-227-86-155-31-110-224-102-193-114-124-34-72-30-74-237-249-32-198-148-199-31-231-154-3-196-143-140-123-170-211-37-10-169-190-130-63-119-182-50-27-198-117-31-96-234-98-237-196-235-143-237-150-185-134-143-251-187-151-91-223-83-234-23-159-86-23
[+] Offset found: 0xAAAC
[+] Decrypting flared_34 (flared_34) ...
[+] Generating hash from MethodInfo for: flared_34
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Boolean
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 4A-00-00-00
[+] Value of bytes6: System.BooleanSystem.Boolean
[+] Value of bytes7: System.Int32
[+] Final SHA256: f8a2493f82ee664325c6407b5cf8465ee02cfea3a24f6a8037add8e4ba5bb648
[+] Calculating method hash: f8a2493f82ee664325c6407b5cf8465ee02cfea3a24f6a8037add8e4ba5bb648
[+] Loading PE Section: f8a2493f
[+] PE Section contents: 96-36-58-D7-9C-85-F5-EF-2B-EE-ED-C3-4A-CE-6B-A3-9E-93-8C-BC-E9-DF-47-38-D8-B5-17-9C-3D-CA-A2-6C-16-54-EE-99-CA-37-1E-13-C9-78-24-98-09-1B-C9-3B-96-7D-0A-67-51-AB-01-1C-63-35-A1-45-4A-C2-E1-6A-98-83-58-2F-CC-72-6E-95-E2-18
[+] Decrypted Bytecode: 00-7E-A6-A6-98-A6-02-58-80-A6-A6-98-A6-7E-A6-A6-98-A6-7E-A7-A6-98-A6-FE-04-16-FE-01-0A-06-2C-24-00-16-80-A6-A6-98-A6-16-80-A7-A6-98-A6-7E-A1-A6-98-A6-16-7E-A1-A6-98-A6-8E-69-28-DB-A6-98-A8-00-17-0B-2B-04-16-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-7E-1B-00-00-04-02-58-80-1B-00-00-04-7E-1B-00-00-04-7E-1A-00-00-04-FE-04-16-FE-01-0A-06-2C-24-00-16-80-1B-00-00-04-16-80-1A-00-00-04-7E-1C-00-00-04-16-7E-1C-00-00-04-8E-69-28-66-00-00-0A-00-17-0B-2B-04-16-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_34: 127-47-203-237-66-158-247-193-25-113-19-4-119-212-185-241-254-54-152-195-192-35-226-71-233-174-35-177-39-107-29-103-216-243-230-177-61-230-63-164-0-159-136-27-138-155-205-31-133-27-64-255-19-27-206-91-77-131-4-147-123-70-153-173-84-171-43-131-238-8-180-24-246-243
[+] Offset found: 0xAB4C
[+] Decrypting flared_35 (flared_35) ...
[+] Method flared_35() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_35
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 9B-00-00-00
[+] Value of bytes6: System.IO.FileStreamSystem.IO.BinaryReaderSystem.UInt32System.Int32System.Boolean
[+] Value of bytes7: System.String
[+] Final SHA256: d787bb6bb380aebfdd031a4da2153b0985d25090529fca1214416cd43d9ccc2e
[+] Removing SHA256 from list: d787bb6bb380aebfdd031a4da2153b0985d25090529fca1214416cd43d9ccc2e
[+] Decrypting flared_36 (flared_36) ...
[+] Generating hash from MethodInfo for: flared_36
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE09
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 1F-00-00-00
[+] Value of bytes6: System.StringFlareOn.Backdoor.FLARE09FlareOn.Backdoor.FLARE09
[+] Value of bytes7:
[+] Final SHA256: 1aa22d6334aa58ad2077d2f1f4199167ef9912756bbc0389770327b587441730
[+] Calculating method hash: 1aa22d6334aa58ad2077d2f1f4199167ef9912756bbc0389770327b587441730
[+] Loading PE Section: 1aa22d63
[+] PE Section contents: 96-60-29-D7-9C-8B-98-61-0D-D0-E3-51-9F-68-6B-9D-A2-3E-F4-33-AB-E1-79-62-DC-A4-E5-B6-37-C4-A4
[+] Decrypted Bytecode: 00-28-D7-A6-98-A8-6F-D6-A6-98-A8-0A-73-D8-A6-98-A4-0B-06-28-E4-A6-98-A4-00-07-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-28-6A-00-00-0A-6F-6B-00-00-0A-0A-73-65-00-00-06-0B-06-28-59-00-00-06-00-07-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_36: 190-139-224-108-102-176-232-152-107-204-6-205-96-116-190-13-41-221-83-105-51-173-81-217-88-196-125-51-226-167-199
[+] Offset found: 0xACF0
[+] Decrypting flared_37 (flared_37) ...
[+] Generating hash from MethodInfo for: flared_37
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE09
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 29-00-00-00
[+] Value of bytes6: System.StringFlareOn.Backdoor.FLARE09FlareOn.Backdoor.FLARE09
[+] Value of bytes7:
[+] Final SHA256: 892fac736928f224083e373766972ba02aa77c0b44a1f35033c08cd7da79b25f
[+] Calculating method hash: 892fac736928f224083e373766972ba02aa77c0b44a1f35033c08cd7da79b25f
[+] Loading PE Section: 892fac73
[+] PE Section contents: 96-98-57-D7-9C-83-DF-66-0D-D0-E3-73-3C-16-55-AD-69-E3-54-83-E7-4D-92-1E-7A-3B-4D-96-31-E4-6A-EE-8E-E6-6E-38-60-84-B8-0D-63
[+] Decrypted Bytecode: 00-D0-A9-A6-98-A0-28-D1-A6-98-A8-28-D0-A6-98-A8-6F-D6-A6-98-A8-0A-73-D8-A6-98-A4-0B-06-28-E4-A6-98-A4-00-07-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-D0-14-00-00-02-28-6C-00-00-0A-28-6D-00-00-0A-6F-6B-00-00-0A-0A-73-65-00-00-06-0B-06-28-59-00-00-06-00-07-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_37: 226-64-250-164-105-32-17-209-127-197-53-116-69-38-219-98-22-8-226-140-83-111-227-86-114-10-212-238-200-58-18-242-114-2-182-8-238-78-14-167-120
[+] Offset found: 0xAD58
[+] Decrypting flared_38 (flared_38) ...
[+] Generating hash from MethodInfo for: flared_38
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: F8-00-00-00
[+] Value of bytes6: System.BooleanSystem.Threading.MutexSystem.BooleanFlareOn.Backdoor.FLARE13FlareOn.Backdoor.FLARE08FlareOn.Backdoor.FLARE08System.Exception
[+] Value of bytes7: System.String[]
[+] Final SHA256: ffc58f783ea75c62c4afa6527e902ce857152317cf4dbcbe5947e4dd23705f4e
[+] Calculating method hash: ffc58f783ea75c62c4afa6527e902ce857152317cf4dbcbe5947e4dd23705f4e
[+] Loading PE Section: ffc58f78
[+] PE Section contents: 96-5F-8C-65-A0-BB-25-A5-AB-3B-8A-FD-74-18-C6-05-00-39-FA-22-9E-47-E1-C6-DC-D0-DE-3B-AF-68-83-60-2E-E4-F6-9B-6C-87-16-A3-D1-7B-82-38-1B-65-68-9D-0E-DB-34-26-56-95-3D-A9-E8-4D-8C-8D-E8-4B-4D-2F-87-88-73-2B-D8-79-45-95-EE-32-0A-77-9C-71-C4-30-AE-78-C4-58-5E-C1-3B-E7-EF-0A-25-D7-D3-4B-17-B7-67-D6-5D-07-D9-78-44-AC-8C-6C-C8-5C-F3-5F-95-0F-A8-F1-18-48-BE-25-1F-C6-29-FE-DF-9C-E9-81-02-8E-2E-55-8B-72-02-1D-F4-F7-96-F0-03-43-5A-68-8E-3D-98-CA-46-9C-7E-99-7E-3B-79-41-39-F7-94-EF-AD-FC-73-0D-84-6A-B3-A0-91-C6-1C-DF-51-B8-87-17-05-7C-B5-F2-10-F2-A4-B6-99-F7-14-FD-36-09-FF-60-57-1B-41-31-DB-69-6D-43-5B-CA-47-DB-76-AB-06-2D-DE-DA-FC-4A-20-FF-4C-59-84-73-51-03-3C-5E-A7-80-0D-FE-8D-84-FA-54-9B-98-35-3D-64-07-14-57-AA-9A-27-F8-99-0F-AE-3F-A0-AA-BB-1B
[+] Decrypted Bytecode: 00-17-72-14-A4-98-D2-12-00-73-C1-A6-98-A8-0B-00-06-0C-08-39-D1-00-00-00-00-73-37-A6-98-A4-0D-28-38-A6-98-A4-00-28-AE-A6-98-A4-00-38-B4-00-00-00-00-00-28-3F-A6-98-A4-13-05-11-05-13-04-11-04-45-08-00-00-00-02-00-00-00-0B-00-00-00-18-00-00-00-25-00-00-00-32-00-00-00-3F-00-00-00-4C-00-00-00-59-00-00-00-2B-64-16-28-34-A6-98-A4-26-2B-5B-28-D6-A6-98-A4-28-34-A6-98-A4-26-2B-4E-28-8D-A6-98-A4-28-34-A6-98-A4-26-2B-41-28-8F-A6-98-A4-28-34-A6-98-A4-26-2B-34-28-2D-A6-98-A4-28-34-A6-98-A4-26-2B-27-28-89-A6-98-A4-28-34-A6-98-A4-26-2B-1A-28-8B-A6-98-A4-28-34-A6-98-A4-26-2B-0D-28-D0-A6-98-A4-28-34-A6-98-A4-26-2B-00-00-DE-0F-13-06-00-00-00-DE-05-26-00-00-DE-00-00-DE-00-17-28-C0-A6-98-A8-00-00-38-47-FF-FF-FF-00-DE-0B-07-2C-07-07-6F-FB-A6-98-A8-00-DC-2A
[+] Rellocated Bytecode: 00-17-72-A9-02-00-70-12-00-73-7C-00-00-0A-0B-00-06-0C-08-39-D1-00-00-00-00-73-8A-00-00-06-0D-28-85-00-00-06-00-28-13-00-00-06-00-38-B4-00-00-00-00-00-28-82-00-00-06-13-05-11-05-13-04-11-04-45-08-00-00-00-02-00-00-00-0B-00-00-00-18-00-00-00-25-00-00-00-32-00-00-00-3F-00-00-00-4C-00-00-00-59-00-00-00-2B-64-16-28-89-00-00-06-26-2B-5B-28-6B-00-00-06-28-89-00-00-06-26-2B-4E-28-30-00-00-06-28-89-00-00-06-26-2B-41-28-32-00-00-06-28-89-00-00-06-26-2B-34-28-90-00-00-06-28-89-00-00-06-26-2B-27-28-34-00-00-06-28-89-00-00-06-26-2B-1A-28-36-00-00-06-28-89-00-00-06-26-2B-0D-28-6D-00-00-06-28-89-00-00-06-26-2B-00-00-DE-0F-13-06-00-00-00-DE-05-26-00-00-DE-00-00-DE-00-17-28-7D-00-00-0A-00-00-38-47-FF-FF-FF-00-DE-0B-07-2C-07-07-6F-46-00-00-0A-00-DC-2A
[+] Overwriting bytecode for flared_38: 162-28-227-230-242-100-252-46-63-211-48-122-77-114-83-226-64-19-242-5-49-198-17-115-142-239-117-3-65-123-85-181-197-12-107-154-125-22-33-0-178-243-33-221-139-227-14-19-174-135-124-91-121-67-46-220-10-112-87-3-238-248-237-195-126-123-181-65-6-185-101-0-241-241-83-61-164-52-232-171-224-98-85-185-254-249-59-129-221-143-143-13-190-29-18-185-6-94-94-15-45-205-12-244-34-82-105-135-240-241-55-213-136-172-35-140-163-51-196-132-63-52-100-119-41-88-107-211-223-154-55-70-214-216-126-19-85-96-151-172-144-180-144-235-87-186-132-18-250-133-21-210-153-218-207-248-105-149-202-202-231-149-167-85-186-240-255-175-45-15-55-66-156-24-244-139-163-120-31-111-211-88-217-90-132-100-173-252-8-133-170-192-150-205-196-250-12-59-49-103-186-212-229-234-77-210-54-128-229-68-85-240-117-90-246-143-188-77-209-85-67-3-166-168-101-119-172-207-84-250-126-104-70-184-180-254-115-238-12-177-45-44-22-196-48-185-74-59
[+] Offset found: 0xAF18
[+] Decrypting flared_39 (flared_39) ...
[+] Generating hash from MethodInfo for: flared_39
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 0E-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb
[+] Calculating method hash: 977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb
[+] Loading PE Section: 977deaed
[+] PE Section contents: 96-50-D6-7D-A2-BB-53-B7-BD-42-60-5B-EA-9A
[+] Decrypted Bytecode: 00-18-28-0C-A6-98-A4-00-16-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-18-28-B1-00-00-06-00-16-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_39: 121-124-81-111-87-181-87-56-144-202-70-216-148-144
[+] Offset found: 0xB0A0
[+] Decrypting flared_40 (flared_40) ...
[+] Generating hash from MethodInfo for: flared_40
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 0E-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb
[+] Calculating method hash: 977deaeda5fff073045620bfdd21f0eaf0fa910ae9fdc86b8cfa6f7c5721fdfb
[+] Loading PE Section: 977deaed
[+] PE Section contents: 96-50-D6-7D-A2-BB-53-B7-BD-42-60-5B-EA-9A
[+] Decrypted Bytecode: 00-18-28-0C-A6-98-A4-00-16-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-18-28-B1-00-00-06-00-16-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_40: 178-188-56-89-140-6-235-71-8-134-242-88-91-26
[+] Offset found: 0xB0F8
[+] Decrypting flared_41 (flared_41) ...
[+] Generating hash from MethodInfo for: flared_41
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Int32
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 21-00-00-00
[+] Value of bytes6: System.BooleanSystem.Int32
[+] Value of bytes7: System.Int32System.Int32
[+] Final SHA256: c61192c7c844195b942eb02b0b64f71f00dad46f11f99b5419bc6d78a72fefb7
[+] Calculating method hash: c61192c7c844195b942eb02b0b64f71f00dad46f11f99b5419bc6d78a72fefb7
[+] Loading PE Section: c61192c7
[+] PE Section contents: 96-4A-FD-8F-06-29-F1-9B-AE-48-48-4B-EC-B0-B3-AE-A1-AD-54-19-4C-50-B9-A9-1E-05-71-35-3C-E7-8E-4F-3C
[+] Decrypted Bytecode: 00-02-03-FE-02-0A-06-2C-05-00-03-10-00-00-7E-AB-A7-98-A6-02-03-17-58-6F-C2-A6-98-A8-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-02-03-FE-02-0A-06-2C-05-00-03-10-00-00-7E-16-01-00-04-02-03-17-58-6F-7F-00-00-0A-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_41: 201-135-65-100-150-143-230-249-8-161-154-52-45-172-56-171-172-15-58-89-9-32-240-35-15-115-187-121-101-66-136-177-69
[+] Offset found: 0xB150
[+] Decrypting flared_42 (flared_42) ...
[+] Generating hash from MethodInfo for: flared_42
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 7
[+] Value of bytes5: F0-00-00-00
[+] Value of bytes6: System.BooleanSystem.Int32System.Boolean
[+] Value of bytes7: System.UInt32
[+] Final SHA256: 0686a47bcd1172713a20e72108b885853e737a949afdc1cd296f4197944db1e2
[+] Calculating method hash: 0686a47bcd1172713a20e72108b885853e737a949afdc1cd296f4197944db1e2
[+] Loading PE Section: 0686a47b
[+] PE Section contents: 96-68-8E-73-04-23-7A-51-0D-D0-E8-DB-46-17-55-A3-26-50-7B-1C-23-C7-44-61-44-05-C9-10-36-CC-8E-C8-B2-E5-F6-99-73-A4-38-A2-EE-47-24-1D-2F-C3-CF-05-A8-FB-9C-4F-DC-90-19-1B-4A-C4-2F-81-E3-DA-E9-CD-17-2E-53-2B-DA-BF-AA-15-46-95-92-D1-9B-63-44-92-2C-E0-62-78-1C-C3-3B-E7-50-97-82-4F-39-6B-E8-48-C1-A9-DD-9B-55-84-F4-A4-B8-CA-50-78-55-EB-69-BF-D8-29-2A-4B-0E-B7-AF-5C-13-A6-6E-75-59-AA-B0-E8-8B-77-B9-F8-B2-B9-FA-E0-71-40-24-CD-FD-6A-3E-A1-BE-C8-45-22-F3-D3-D7-B1-47-7F-89-21-A6-66-93-C0-F1-55-9D-E4-A2-AE-66-5B-92-73-5F-20-23-26-25-4D-AF-79-C8-C0-A7-06-0B-56-F2-FC-B7-BA-54-36-2D-1A-41-33-F4-4A-92-4E-81-46-CB-43-D0-72-1E-67-4D-C5-E2-2E-9F-A0-04-5E-EE-F5-79-C3-44-C6-14-36-CD-5F-02-74-F1-53-83-AF-C8-C2-9B-F9-CE-50-A5-9B-E2-D5
[+] Decrypted Bytecode: 00-20-70-02-00-00-8D-E6-A6-98-A3-80-AA-A7-98-A6-20-65-89-07-6C-80-A5-A7-98-A6-20-8D-01-00-00-80-A4-A7-98-A6-1F-0B-80-A7-A7-98-A6-1D-80-A6-A7-98-A6-20-80-56-2C-9D-80-A1-A7-98-A6-1F-0F-80-A0-A7-98-A6-20-00-00-C6-EF-80-A3-A7-98-A6-1F-12-80-A2-A7-98-A6-20-70-02-00-00-80-9D-A7-98-A6-20-FF-FF-FF-7F-80-9C-A7-98-A6-20-00-00-00-80-80-9F-A7-98-A6-7E-AA-A7-98-A6-16-02-9E-7E-9A-A7-98-A6-14-FE-01-0A-06-2C-28-00-28-3C-A6-98-A8-28-3F-A6-98-A8-80-9A-A7-98-A6-7E-81-A7-98-A6-14-FE-06-2F-A6-98-A4-73-3E-A6-98-A8-6F-39-A6-98-A8-00-00-17-0B-2B-32-00-7E-AA-A7-98-A6-07-7E-A5-A7-98-A6-7E-AA-A7-98-A6-07-17-59-95-7E-AA-A7-98-A6-07-17-59-95-1F-1E-64-61-5A-6E-07-6A-58-28-C0-A6-98-A4-9E-00-07-17-58-0B-07-20-70-02-00-00-FE-04-0C-08-2D-C2-2A
[+] Rellocated Bytecode: 00-20-70-02-00-00-8D-5B-00-00-01-80-17-01-00-04-20-65-89-07-6C-80-18-01-00-04-20-8D-01-00-00-80-19-01-00-04-1F-0B-80-1A-01-00-04-1D-80-1B-01-00-04-20-80-56-2C-9D-80-1C-01-00-04-1F-0F-80-1D-01-00-04-20-00-00-C6-EF-80-1E-01-00-04-1F-12-80-1F-01-00-04-20-70-02-00-00-80-20-01-00-04-20-FF-FF-FF-7F-80-21-01-00-04-20-00-00-00-80-80-22-01-00-04-7E-17-01-00-04-16-02-9E-7E-27-01-00-04-14-FE-01-0A-06-2C-28-00-28-81-00-00-0A-28-82-00-00-0A-80-27-01-00-04-7E-3C-01-00-04-14-FE-06-92-00-00-06-73-83-00-00-0A-6F-84-00-00-0A-00-00-17-0B-2B-32-00-7E-17-01-00-04-07-7E-18-01-00-04-7E-17-01-00-04-07-17-59-95-7E-17-01-00-04-07-17-59-95-1F-1E-64-61-5A-6E-07-6A-58-28-7D-00-00-06-9E-00-07-17-58-0B-07-20-70-02-00-00-FE-04-0C-08-2D-C2-2A
[+] Overwriting bytecode for flared_42: 56-157-149-20-38-21-186-71-100-38-91-162-157-24-115-158-72-134-65-210-91-56-192-70-175-187-79-254-112-251-201-245-52-77-237-68-230-7-203-151-115-64-105-170-182-217-86-153-211-135-139-136-194-110-125-0-221-79-101-106-197-188-214-105-92-101-109-80-43-46-184-64-186-169-94-27-207-21-144-213-101-181-0-233-111-65-51-197-207-236-103-151-162-97-210-183-105-255-77-80-107-6-110-165-207-74-205-24-16-98-48-199-191-143-5-15-145-236-249-27-50-168-128-62-198-33-157-89-215-166-177-207-200-63-106-94-71-133-26-37-116-26-181-109-187-160-215-19-91-195-38-125-6-50-29-195-134-48-222-174-172-115-65-105-176-97-254-127-37-167-200-11-210-212-167-24-243-18-130-38-73-138-254-19-128-52-200-150-34-167-215-22-167-108-120-0-216-75-188-90-161-88-238-180-250-26-170-50-138-4-207-115-173-184-100-34-117-45-232-124-152-104-93-125-207-177-100-102-91-167-63-167-85-40-133-240-156-74-25-102
[+] Offset found: 0xB1D4
[+] Decrypting flared_43 (flared_43) ...
[+] Generating hash from MethodInfo for: flared_43
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: 84-00-00-00
[+] Value of bytes6: System.UInt32System.UInt32System.UInt32System.BooleanSystem.Boolean
[+] Value of bytes7:
[+] Final SHA256: 74fbaf68c82f81c33b3f74468e96439ac6abe8c24f405b2dc0d97cfaebcdc91b
[+] Calculating method hash: 74fbaf68c82f81c33b3f74468e96439ac6abe8c24f405b2dc0d97cfaebcdc91b
[+] Loading PE Section: 74fbaf68
[+] PE Section contents: 96-5E-F4-5A-6E-23-89-1D-0C-D0-ED-5D-79-CE-52-A2-9E-93-AD-65-E5-E0-79-60-DA-B4-B1-BD-47-CE-8E-48-48-D7-10-A3-CB-37-1E-5A-11-B1-AA-C0-09-FD-CC-96-09-CC-78-15-F7-15-C7-AC-13-5F-84-97-C0-4A-49-62-AF-57-C3-23-43-18-2B-BD-25-94-92-D3-88-71-BA-9A-2C-E0-62-5E-12-6B-9C-7F-76-0C-5B-73-38-D3-B1-EF-1E-A6-5F-07-F2-42-C7-8C-D9-54-50-FE-C2-2C-C4-21-5E-27-82-EC-96-EF-BC-4D-89-C9-F0-FF-49-1A-24-8B-2D-E5-19-FE
[+] Decrypted Bytecode: 00-16-0A-2B-6A-00-7E-AA-A7-98-A6-06-95-7E-9F-A7-98-A6-5F-7E-AA-A7-98-A6-06-17-58-20-70-02-00-00-5E-95-7E-9C-A7-98-A6-5F-58-6E-28-C0-A6-98-A4-0B-07-17-64-0C-07-18-5E-16-FE-03-0D-09-2C-10-00-08-20-DF-B0-08-99-61-6E-28-C0-A6-98-A4-0C-00-7E-AA-A7-98-A6-06-7E-AA-A7-98-A6-06-7E-A4-A7-98-A6-58-20-70-02-00-00-5E-95-08-61-9E-00-06-17-58-0A-06-20-70-02-00-00-FE-05-13-04-11-04-2D-88-16-80-9D-A7-98-A6-2A
[+] Rellocated Bytecode: 00-16-0A-2B-6A-00-7E-17-01-00-04-06-95-7E-22-01-00-04-5F-7E-17-01-00-04-06-17-58-20-70-02-00-00-5E-95-7E-21-01-00-04-5F-58-6E-28-7D-00-00-06-0B-07-17-64-0C-07-18-5E-16-FE-03-0D-09-2C-10-00-08-20-DF-B0-08-99-61-6E-28-7D-00-00-06-0C-00-7E-17-01-00-04-06-7E-17-01-00-04-06-7E-19-01-00-04-58-20-70-02-00-00-5E-95-08-61-9E-00-06-17-58-0A-06-20-70-02-00-00-FE-05-13-04-11-04-2D-88-16-80-20-01-00-04-2A
[+] Overwriting bytecode for flared_43: 90-126-5-34-134-173-175-212-203-34-138-124-149-155-97-224-124-179-74-214-3-30-230-153-203-251-220-14-82-224-16-226-187-124-94-70-238-49-20-80-222-239-239-50-169-183-239-216-228-145-239-108-5-89-164-60-152-108-86-139-208-161-129-234-17-168-192-24-61-26-242-75-159-250-247-20-46-179-239-19-11-4-41-193-240-163-221-98-216-33-174-130-218-136-127-60-109-4-32-1-246-214-154-201-159-164-205-10-97-143-13-228-124-66-127-204-120-192-249-109-203-94-64-27-107-111-112-22-123-187-166-41
[+] Offset found: 0xB314
[+] Decrypting flared_44 (flared_44) ...
[+] Generating hash from MethodInfo for: flared_44
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.UInt32
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 80-00-00-00
[+] Value of bytes6: System.UInt32System.BooleanSystem.UInt32
[+] Value of bytes7:
[+] Final SHA256: 719ee568522cdb7a4519108d0a34b9531404122d12775ae8daedafc6f068a016
[+] Calculating method hash: 719ee568522cdb7a4519108d0a34b9531404122d12775ae8daedafc6f068a016
[+] Loading PE Section: 719ee568
[+] PE Section contents: 96-36-63-D6-9C-85-D7-C7-A9-48-4B-A5-E9-A6-33-04-0D-32-DE-13-4F-6F-2B-60-44-07-E9-9D-49-66-29-D0-B0-3C-F3-98-F4-09-2D-0F-4F-D9-FC-A7-08-FD-CE-82-11-84-78-78-FA-0B-9F-C4-4B-FB-11-38-F3-45-16-08-F1-29-D4-B3-7C-26-24-9F-E3-34-74-D7-23-E9-62-2F-94-27-A6-26-CF-66-A3-41-8F-6B-2F-D1-99-35-B5-10-A6-70-42-18-AD-78-33-8E-C6-57-F7-60-73-63-96-A7-E3-F0-18-4A-90-7F-91-9E-2B-40-50-DE-EA-0C-AC-3C
[+] Decrypted Bytecode: 00-7E-9D-A7-98-A6-20-70-02-00-00-FE-05-16-FE-01-0B-07-2C-08-00-28-CA-A6-98-A4-00-00-7E-AA-A7-98-A6-7E-9D-A7-98-A6-95-0A-06-06-7E-A7-A7-98-A6-1F-1F-5F-64-61-0A-06-06-7E-A6-A7-98-A6-1F-1F-5F-62-7E-A1-A7-98-A6-5F-61-0A-06-06-7E-A0-A7-98-A6-1F-1F-5F-62-7E-A3-A7-98-A6-5F-61-0A-06-06-7E-A2-A7-98-A6-1F-1F-5F-64-61-0A-7E-9D-A7-98-A6-17-58-80-9D-A7-98-A6-06-6E-28-C0-A6-98-A4-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-7E-20-01-00-04-20-70-02-00-00-FE-05-16-FE-01-0B-07-2C-08-00-28-77-00-00-06-00-00-7E-17-01-00-04-7E-20-01-00-04-95-0A-06-06-7E-1A-01-00-04-1F-1F-5F-64-61-0A-06-06-7E-1B-01-00-04-1F-1F-5F-62-7E-1C-01-00-04-5F-61-0A-06-06-7E-1D-01-00-04-1F-1F-5F-62-7E-1E-01-00-04-5F-61-0A-06-06-7E-1F-01-00-04-1F-1F-5F-64-61-0A-7E-20-01-00-04-17-58-80-20-01-00-04-06-6E-28-7D-00-00-06-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_44: 205-253-74-105-248-149-210-78-78-167-60-74-106-149-226-28-51-30-115-85-122-224-10-180-44-20-104-229-229-89-112-43-239-195-35-46-203-99-95-88-89-151-223-252-146-221-227-94-227-96-209-205-69-40-178-237-242-149-60-227-44-237-105-244-55-17-91-166-113-179-80-207-190-26-252-226-0-13-34-78-48-10-2-132-136-163-229-198-17-54-60-53-38-124-44-107-45-234-197-129-130-60-236-47-16-1-14-0-44-207-236-228-115-238-178-34-235-228-108-148-43-148-149-59-119-26-168-66
[+] Offset found: 0xB3DC
[+] Decrypting flared_45 (flared_45) ...
[+] Generating hash from MethodInfo for: flared_45
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Int32
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 19-00-00-00
[+] Value of bytes6: System.Int32System.UInt32System.Int32
[+] Value of bytes7: System.Int32System.Int32
[+] Final SHA256: 77c01ab26f569d1a8fb3571757e6a1beed94d3ae2a168fba2fc01c07216c6f8b
[+] Calculating method hash: 77c01ab26f569d1a8fb3571757e6a1beed94d3ae2a168fba2fc01c07216c6f8b
[+] Loading PE Section: 77c01ab2
[+] PE Section contents: 96-4B-FC-28-0E-0B-33-11-33-EC-40-59-86-B7-A3-03-6C-6B-AA-72-43-6C-E1-CE-F6
[+] Decrypted Bytecode: 00-03-02-59-0A-28-C4-A6-98-A4-0B-02-6A-07-6E-06-6A-5E-58-69-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-03-02-59-0A-28-79-00-00-06-0B-02-6A-07-6E-06-6A-5E-58-69-0C-2B-00-08-2A
[+] Overwriting bytecode for flared_45: 149-1-31-72-253-237-93-207-176-91-209-194-204-201-147-202-50-144-235-199-9-7-110-223-28
[+] Offset found: 0xB4A4
[+] Decrypting flared_46 (flared_46) ...
[+] Generating hash from MethodInfo for: flared_46
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.UInt32
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 0C-00-00-00
[+] Value of bytes6: System.UInt32
[+] Value of bytes7: System.Int64
[+] Final SHA256: 2fad6d86f3573b7ceedcb1e688397139901dfc97f1784917d345a22251121627
[+] Calculating method hash: 2fad6d86f3573b7ceedcb1e688397139901dfc97f1784917d345a22251121627
[+] Loading PE Section: 2fad6d86
[+] PE Section contents: 96-4A-D6-49-A2-BB-5F-BD-80-48-4D-71
[+] Decrypted Bytecode: 00-02-28-38-A6-98-A8-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-02-28-85-00-00-0A-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_46: 175-91-206-242-60-252-220-22-241-190-242-131
[+] Offset found: 0xB520
[+] Decrypting flared_47 (flared_47) ...
[+] Method flared_47() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_47
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Byte[]
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: FA-00-00-00
[+] Value of bytes6: System.Int32System.Int32System.Int32System.Int32System.Int32System.Int32[]System.Int32[]System.Byte[]System.BooleanSystem.BooleanSystem.BooleanSystem.Byte[]
[+] Value of bytes7: System.Byte[]System.Byte[]
[+] Final SHA256: 82b8dfa1f5e9dbf88357ea5c516d4377dc1066eb2ed87590f1bc2529b721ab71
[+] Removing SHA256 from list: 82b8dfa1f5e9dbf88357ea5c516d4377dc1066eb2ed87590f1bc2529b721ab71
[+] Decrypting flared_48 (flared_48) ...
[+] Generating hash from MethodInfo for: flared_48
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 12-01-00-00
[+] Value of bytes6:
[+] Value of bytes7:
[+] Final SHA256: b3650258065ed1ee9f35521593eefae670c594c85c3e121f7b5588a0a6de198b
[+] Calculating method hash: b3650258065ed1ee9f35521593eefae670c594c85c3e121f7b5588a0a6de198b
[+] Loading PE Section: b3650258
[+] PE Section contents: 96-5E-D6-4F-A2-BB-53-B7-D8-73-ED-C3-44-95-DB-13-75-03-54-83-EB-5F-8E-FC-7A-3B-41-9D-12-DB-98-3B-20-E4-F6-9B-74-C0-82-A3-D1-77-82-25-B7-72-1B-AB-A8-43-B8-0E-9F-37-3F-22-45-5C-AC-86-F4-29-7F-CC-17-2C-6A-44-E0-DF-DD-3D-E5-17-13-60-F7-47-62-A8-2F-6F-AB-62-CA-59-93-E7-F5-13-3C-A4-A9-ED-8F-13-24-B9-67-A1-6A-B4-52-A1-A2-DD-23-CE-73-EC-6A-3A-11-6D-26-74-3E-11-9C-44-97-AB-C2-74-59-A8-BF-79-B0-DB-27-7C-9A-9C-C9-CB-A4-EE-2A-7D-66-DB-C9-33-98-CA-4A-BA-70-B6-4E-65-E9-7F-05-7B-BC-26-0F-FE-CD-8E-A3-67-21-1D-7A-54-92-73-53-3A-4C-0B-88-FE-35-79-93-71-1C-ED-9B-F7-14-FD-09-4D-C8-EE-1F-15-D9-B0-EF-4A-B8-ED-59-74-C8-CC-19-4F-AF-A6-70-DA-D9-56-E7-89-5C-FF-1C-09-4A-6C-D8-F8-28-00-CD-7D-09-37-89-62-05-47-6E-DB-F4-3D-6C-C4-05-B6-05-E3-EB-87-3E-01-90-0E-7D-5E-5D-C9-D5-55-2D-A8-28-2A-A1-52-FE-5F-59-58-74-A8-67-25-08-07-23-B1-BD-60-E2-E0
[+] Decrypted Bytecode: 00-16-28-3E-A6-98-A4-00-73-3B-A6-98-A8-25-16-16-73-36-A6-98-A4-18-6F-3A-A6-98-A8-00-25-17-16-73-36-A6-98-A4-18-6F-3A-A6-98-A8-00-25-18-17-73-36-A6-98-A4-17-6F-3A-A6-98-A8-00-25-18-18-73-36-A6-98-A4-19-6F-3A-A6-98-A8-00-25-19-17-73-36-A6-98-A4-17-6F-3A-A6-98-A8-00-25-19-19-73-36-A6-98-A4-1A-6F-3A-A6-98-A8-00-25-1A-17-73-36-A6-98-A4-1D-6F-3A-A6-98-A8-00-25-1A-1A-73-36-A6-98-A4-1B-6F-3A-A6-98-A8-00-25-1B-17-73-36-A6-98-A4-17-6F-3A-A6-98-A8-00-25-1B-18-73-36-A6-98-A4-1C-6F-3A-A6-98-A8-00-25-1B-1B-73-36-A6-98-A4-1A-6F-3A-A6-98-A8-00-25-1B-1C-73-36-A6-98-A4-19-6F-3A-A6-98-A8-00-25-1C-17-73-36-A6-98-A4-17-6F-3A-A6-98-A8-00-25-1C-19-73-36-A6-98-A4-1B-6F-3A-A6-98-A8-00-25-1C-1B-73-36-A6-98-A4-19-6F-3A-A6-98-A8-00-25-1C-1D-73-36-A6-98-A4-1A-6F-3A-A6-98-A8-00-25-1D-16-73-36-A6-98-A4-18-6F-3A-A6-98-A8-00-80-99-A7-98-A6-2A
[+] Rellocated Bytecode: 00-16-28-83-00-00-06-00-73-86-00-00-0A-25-16-16-73-8B-00-00-06-18-6F-87-00-00-0A-00-25-17-16-73-8B-00-00-06-18-6F-87-00-00-0A-00-25-18-17-73-8B-00-00-06-17-6F-87-00-00-0A-00-25-18-18-73-8B-00-00-06-19-6F-87-00-00-0A-00-25-19-17-73-8B-00-00-06-17-6F-87-00-00-0A-00-25-19-19-73-8B-00-00-06-1A-6F-87-00-00-0A-00-25-1A-17-73-8B-00-00-06-1D-6F-87-00-00-0A-00-25-1A-1A-73-8B-00-00-06-1B-6F-87-00-00-0A-00-25-1B-17-73-8B-00-00-06-17-6F-87-00-00-0A-00-25-1B-18-73-8B-00-00-06-1C-6F-87-00-00-0A-00-25-1B-1B-73-8B-00-00-06-1A-6F-87-00-00-0A-00-25-1B-1C-73-8B-00-00-06-19-6F-87-00-00-0A-00-25-1C-17-73-8B-00-00-06-17-6F-87-00-00-0A-00-25-1C-19-73-8B-00-00-06-1B-6F-87-00-00-0A-00-25-1C-1B-73-8B-00-00-06-19-6F-87-00-00-0A-00-25-1C-1D-73-8B-00-00-06-1A-6F-87-00-00-0A-00-25-1D-16-73-8B-00-00-06-18-6F-87-00-00-0A-00-80-24-01-00-04-2A
[+] Overwriting bytecode for flared_48: 204-6-194-225-91-191-26-38-191-255-208-213-8-214-114-227-179-249-69-49-154-227-210-77-28-57-74-167-12-206-62-18-187-137-208-29-119-152-167-111-222-101-172-27-166-5-170-6-227-57-205-133-40-165-166-232-52-116-196-33-116-114-26-240-192-189-26-127-5-84-107-27-81-213-82-53-55-183-166-22-143-67-195-210-1-185-233-21-226-232-232-2-211-133-251-108-75-187-90-232-235-43-1-143-206-178-51-82-82-113-176-124-205-174-145-48-174-71-238-7-212-4-156-29-107-104-71-204-218-230-233-123-93-190-43-100-66-52-4-79-133-150-195-113-55-108-53-37-244-202-189-4-205-83-20-230-142-227-35-101-106-103-119-108-135-53-31-15-130-45-238-121-67-159-129-61-65-0-229-255-51-34-215-16-41-229-174-9-170-69-213-94-17-158-229-30-31-86-233-2-76-37-162-198-219-67-192-46-209-214-164-99-254-35-50-71-143-103-67-162-134-21-100-61-87-143-104-165-185-99-30-234-65-227-179-13-128-17-52-229-36-128-56-211-160-114-96-237-107-157-142-183-19-71-123-54-192-100-111-76-219-27-116-110-184-185-34-26-111-36-199-126-50-93
[+] Offset found: 0xB6DC
[+] Decrypting flared_49 (flared_49) ...
[+] Generating hash from MethodInfo for: flared_49
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE08
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 5F-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE13+FLARE16FlareOn.Backdoor.FLARE08System.BooleanFlareOn.Backdoor.FLARE08FlareOn.Backdoor.FLARE08
[+] Value of bytes7: FlareOn.Backdoor.FLARE07
[+] Final SHA256: a4691056b72cb7feda735954953e6ea4b347d8e3735ace8612661d63e1785761
[+] Calculating method hash: a4691056b72cb7feda735954953e6ea4b347d8e3735ace8612661d63e1785761
[+] Loading PE Section: a4691056
[+] PE Section contents: 96-60-C1-D7-9C-87-F5-C4-9D-EE-D3-FF-E6-CE-54-A2-9E-93-F4-09-4E-28-D4-60-44-0B-FF-63-36-C0-86-64-20-42-1C-71-C8-37-6A-2D-76-79-1A-A4-A2-77-6B-63-18-75-BA-81-50-62-60-1C-75-F4-FB-3E-49-C2-9B-65-8F-76-65-84-7C-E1-E5-FA-1C-94-92-DF-AC-9C-62-A8-23-0B-F0-FE-F4-69-41-E0-C3-0E-0E-D7-8E-4F-3D
[+] Decrypted Bytecode: 00-28-3F-A6-98-A4-02-73-36-A6-98-A4-0A-7E-99-A7-98-A6-06-12-01-6F-35-A6-98-A8-16-FE-01-0C-08-2C-36-00-72-4E-A4-98-D2-28-3F-A6-98-A4-0D-12-03-FE-16-AE-A6-98-A0-6F-F9-A6-98-A8-72-A0-A5-98-D2-0F-00-FE-16-AF-A6-98-A0-6F-F9-A6-98-A8-28-ED-A6-98-A8-73-34-A6-98-A8-7A-07-13-04-2B-00-11-04-2A
[+] Rellocated Bytecode: 00-28-82-00-00-06-02-73-8B-00-00-06-0A-7E-24-01-00-04-06-12-01-6F-88-00-00-0A-16-FE-01-0C-08-2C-36-00-72-F3-02-00-70-28-82-00-00-06-0D-12-03-FE-16-13-00-00-02-6F-44-00-00-0A-72-1D-03-00-70-0F-00-FE-16-12-00-00-02-6F-44-00-00-0A-28-50-00-00-0A-73-89-00-00-0A-7A-07-13-04-2B-00-11-04-2A
[+] Overwriting bytecode for flared_49: 199-93-114-133-191-6-131-126-176-18-144-210-44-62-87-145-76-243-23-8-13-165-170-85-117-5-129-45-59-83-254-201-43-179-134-162-243-34-187-163-190-39-146-57-169-142-8-100-191-226-171-209-72-198-255-34-178-28-16-186-133-85-66-92-20-198-166-121-183-180-158-0-56-116-74-229-18-113-171-230-252-28-109-89-167-45-129-101-179-100-239-214-18-1-30
[+] Offset found: 0xB834
[+] Decrypting flared_50 (flared_50) ...
[+] Generating hash from MethodInfo for: flared_50
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE08
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 17-00-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE08
[+] Value of bytes7: FlareOn.Backdoor.FLARE07
[+] Final SHA256: 7cddb7c1f3d440dea183054eb4576dc8e1d1a4f7ca1fabb5f33fcb1a2a551e29
[+] Calculating method hash: 7cddb7c1f3d440dea183054eb4576dc8e1d1a4f7ca1fabb5f33fcb1a2a551e29
[+] Loading PE Section: 7cddb7c1
[+] PE Section contents: 96-4A-D6-4B-A2-BB-53-9F-95-EE-D3-FF-EC-98-F2-A3-9E-91-F8-30-4F-41-CB
[+] Decrypted Bytecode: 00-02-28-3A-A6-98-A4-28-3E-A6-98-A4-00-28-3F-A6-98-A4-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-02-28-87-00-00-06-28-83-00-00-06-00-28-82-00-00-06-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_50: 16-181-8-5-241-166-69-214-77-191-107-55-15-101-207-192-252-161-180-48-115-240-211
[+] Offset found: 0xB8E8
[+] Decrypting flared_51 (flared_51) ...
[+] Generating hash from MethodInfo for: flared_51
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.UInt32
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 42-00-00-00
[+] Value of bytes6: System.UInt32System.BooleanSystem.Int32System.BooleanSystem.UInt32
[+] Value of bytes7: System.String
[+] Final SHA256: db08afea48362227ed638d9657ac36f30eec90853f33fe4c68898b122260f989
[+] Calculating method hash: db08afea48362227ed638d9657ac36f30eec90853f33fe4c68898b122260f989
[+] Loading PE Section: db08afea
[+] PE Section contents: 96-5E-F4-73-10-DD-F4-BC-AC-64-64-5B-CC-75-50-19-87-3F-E4-17-64-51-E1-C4-D4-CC-62-3B-AF-64-88-29-36-D1-6F-3F-6D-F5-B2-05-41-C8-DA-0C-A7-67-07-14-A8-43-B4-E7-F4-00-90-97-30-5C-8F-8D-E8-71-49-7B-8B-A2
[+] Decrypted Bytecode: 00-16-0A-02-14-FE-03-0B-07-2C-2F-00-20-C5-9D-1C-81-0A-16-0C-2B-16-00-02-08-6F-8B-A6-98-A8-06-61-20-93-01-00-01-5A-0A-00-08-17-58-0C-08-02-6F-89-A6-98-A8-FE-04-0D-09-2D-DD-00-06-13-04-2B-00-11-04-2A
[+] Rellocated Bytecode: 00-16-0A-02-14-FE-03-0B-07-2C-2F-00-20-C5-9D-1C-81-0A-16-0C-2B-16-00-02-08-6F-36-00-00-0A-06-61-20-93-01-00-01-5A-0A-00-08-17-58-0C-08-02-6F-34-00-00-0A-FE-04-0D-09-2D-DD-00-06-13-04-2B-00-11-04-2A
[+] Overwriting bytecode for flared_51: 30-64-183-78-173-94-242-107-10-98-213-80-96-213-3-155-1-248-32-5-57-33-149-27-121-107-152-53-8-61-228-68-36-183-94-167-223-132-45-111-22-16-64-137-112-92-197-245-252-45-62-204-62-32-32-253-170-156-213-66-198-189-98-205-125-145
[+] Offset found: 0xB9D0
[+] Decrypting flared_52 (flared_52) ...
[+] Generating hash from MethodInfo for: flared_52
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 34-00-00-00
[+] Value of bytes6: System.BooleanSystem.Boolean
[+] Value of bytes7: System.ObjectSystem.Collections.Specialized.NotifyCollectionChangedEventArgs
[+] Final SHA256: 81e1a476823fefa6bcb79f32d479c6c07298cd32991be20324e6259e49f7d045
[+] Calculating method hash: 81e1a476823fefa6bcb79f32d479c6c07298cd32991be20324e6259e49f7d045
[+] Loading PE Section: 81e1a476
[+] PE Section contents: 96-4B-91-47-A2-BB-5F-A0-55-49-41-5D-C0-95-CD-7B-92-92-6A-BD-63-48-9F-47-7B-3B-4F-F2-06-6A-16-E0-00-BC-6F-14-6D-B9-B3-02-65-D7-82-28-84-C3-F0-39-0E-DB-1C-33
[+] Decrypted Bytecode: 00-03-6F-36-A6-98-A8-17-FE-01-0A-06-2C-25-00-7E-94-A7-98-A6-2C-0F-7E-81-A7-98-A6-6F-31-A6-98-A8-16-FE-01-2B-01-16-0B-07-2C-08-00-28-2B-A6-98-A4-00-00-00-2A
[+] Rellocated Bytecode: 00-03-6F-8B-00-00-0A-17-FE-01-0A-06-2C-25-00-7E-29-01-00-04-2C-0F-7E-3C-01-00-04-6F-8C-00-00-0A-16-FE-01-2B-01-16-0B-07-2C-08-00-28-96-00-00-06-00-00-00-2A
[+] Overwriting bytecode for flared_52: 241-82-4-187-2-61-224-90-88-159-132-212-21-32-56-77-34-0-149-171-254-123-214-115-180-88-144-85-212-58-86-24-211-202-230-148-245-247-8-228-81-21-165-224-149-0-249-20-31-220-137-179
[+] Offset found: 0xBAB0
[+] Decrypting flared_53 (flared_53) ...
[+] Generating hash from MethodInfo for: flared_53
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 1
[+] Value of bytes5: 1A-00-00-00
[+] Value of bytes6: System.Char[]System.String
[+] Value of bytes7: System.String
[+] Final SHA256: ede0bad0a05130663ac46fbc858f0376a5a753edd6a7111831e8951f0f537409
[+] Calculating method hash: ede0bad0a05130663ac46fbc858f0376a5a753edd6a7111831e8951f0f537409
[+] Loading PE Section: ede0bad0
[+] PE Section contents: 96-4A-91-41-A2-BB-5F-BD-AD-60-78-FD-74-18-CD-03-75-9F-54-83-E7-4C-CA-C6-DB-89
[+] Decrypted Bytecode: 00-02-6F-30-A6-98-A8-0A-06-28-33-A6-98-A8-00-06-73-AA-A6-98-A8-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-02-6F-8D-00-00-0A-0A-06-28-8E-00-00-0A-00-06-73-17-00-00-0A-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_53: 117-83-172-234-160-242-59-47-231-110-25-56-179-103-203-24-74-193-29-40-111-217-194-32-229-145
[+] Offset found: 0xBB34
[+] Decrypting flared_54 (flared_54) ...
[+] Generating hash from MethodInfo for: flared_54
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 6
[+] Value of bytes5: 81-00-00-00
[+] Value of bytes6: System.Byte[]System.Byte[]System.Byte[]System.StringSystem.IO.FileStream
[+] Value of bytes7:
[+] Final SHA256: 699fdcf2eb7d280a3bfaaf7e81a2eb138804737ab5f90ff369ecf8550b59da95
[+] Calculating method hash: 699fdcf2eb7d280a3bfaaf7e81a2eb138804737ab5f90ff369ecf8550b59da95
[+] Loading PE Section: 699fdcf2
[+] PE Section contents: 96-36-6B-D6-9C-85-DF-9E-0D-D0-EF-73-E8-16-55-A1-0C-4B-68-BC-D7-E1-8E-F4-7A-3B-41-96-30-CA-A6-75-B0-DA-CA-33-44-82-1E-9D-E1-F7-AE-A6-37-CD-6F-87-83-49-BA-81-53-28-49-38-4A-C4-2F-B6-C3-FC-D1-C2-A7-B5-D5-B3-7E-16-6B-33-7D-9A-22-E2-22-E9-6C-3D-82-60-DC-4F-1F-E8-9D-7F-78-19-21-D7-8E-4F-1F-A1-36-58-34-68-1C-BA-CA-2C-B8-CA-8E-F5-C4-70-E2-2F-6F-53-EF-17-30-89-11-5E-51-D1-DC-FA-67-94-0C-30-A0
[+] Decrypted Bytecode: 00-7E-95-A7-98-A6-28-29-A6-98-A4-28-04-A6-98-A4-0A-7E-9A-A7-98-A6-6F-32-A6-98-A8-0B-07-06-28-3D-A6-98-A4-0C-28-2D-A6-98-A8-28-2C-A6-98-A8-07-1A-8D-92-A6-98-A3-25-D0-82-A7-98-A6-28-2F-A6-98-A8-28-3D-A6-98-A4-6F-2E-A6-98-A8-28-95-A6-98-A8-0D-09-18-18-17-73-29-A6-98-A8-13-04-00-11-04-08-16-08-8E-69-6F-EE-A6-98-A8-00-00-DE-0D-11-04-2C-08-11-04-6F-FB-A6-98-A8-00-DC-09-28-28-A6-98-A8-26-2A
[+] Rellocated Bytecode: 00-7E-28-01-00-04-28-94-00-00-06-28-B9-00-00-06-0A-7E-27-01-00-04-6F-8F-00-00-0A-0B-07-06-28-80-00-00-06-0C-28-90-00-00-0A-28-91-00-00-0A-07-1A-8D-2F-00-00-01-25-D0-3F-01-00-04-28-92-00-00-0A-28-80-00-00-06-6F-93-00-00-0A-28-28-00-00-0A-0D-09-18-18-17-73-94-00-00-0A-13-04-00-11-04-08-16-08-8E-69-6F-53-00-00-0A-00-00-DE-0D-11-04-2C-08-11-04-6F-46-00-00-0A-00-DC-09-28-95-00-00-0A-26-2A
[+] Overwriting bytecode for flared_54: 76-65-115-250-28-124-116-134-119-72-60-143-176-75-118-90-199-215-8-134-74-190-101-139-26-79-125-109-176-85-35-158-198-155-40-212-244-69-91-2-73-61-18-243-35-79-229-198-47-156-237-71-191-44-111-141-219-231-223-204-254-7-214-34-36-157-201-20-34-161-102-129-123-5-60-12-172-114-103-203-105-183-61-19-103-220-222-154-44-155-249-12-102-143-3-66-103-240-206-134-133-209-163-142-54-107-203-186-239-98-225-105-128-20-98-71-202-194-187-72-190-47-232-135-168-89-27-236-2
[+] Offset found: 0xBBA0
[+] Decrypting flared_55 (flared_55) ...
[+] Generating hash from MethodInfo for: flared_55
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 57-00-00-00
[+] Value of bytes6: System.Boolean
[+] Value of bytes7: System.Int32System.String
[+] Final SHA256: 33d51cd2fbaef784d7acbc6d5e5cfcce1be1771d3524511a09712c9f541bd36d
[+] Calculating method hash: 33d51cd2fbaef784d7acbc6d5e5cfcce1be1771d3524511a09712c9f541bd36d
[+] Loading PE Section: 33d51cd2
[+] PE Section contents: 96-36-7F-D6-9C-85-98-86-0D-D0-E3-77-FA-CE-4C-A2-9E-93-E4-74-64-E1-79-6E-DE-83-11-9D-37-CC-EF-B6-17-69-6F-29-66-A9-94-23-49-A1-17-A7-37-C3-6B-B5-9B-7D-84-B1-70-98-3E-22-4B-22-08-39-74-FC-4B-4A-77-88-73-2B-BB-16-6F-33-7D-9A-2C-77-AF-79-C4-26-0B-EC-63-C0-CA-C1-11
[+] Decrypted Bytecode: 00-7E-81-A7-98-A6-6F-31-A6-98-A8-2C-16-7E-81-A7-98-A6-16-6F-2B-A6-98-A8-02-20-F8-00-00-00-61-FE-01-2B-01-16-0A-06-2C-26-00-7E-95-A7-98-A6-03-28-95-A6-98-A8-80-95-A7-98-A6-7E-81-A7-98-A6-02-20-F8-00-00-00-61-6F-2A-A6-98-A8-26-00-2B-08-00-16-80-94-A7-98-A6-00-2A
[+] Rellocated Bytecode: 00-7E-3C-01-00-04-6F-8C-00-00-0A-2C-16-7E-3C-01-00-04-16-6F-96-00-00-0A-02-20-F8-00-00-00-61-FE-01-2B-01-16-0A-06-2C-26-00-7E-28-01-00-04-03-28-28-00-00-0A-80-28-01-00-04-7E-3C-01-00-04-02-20-F8-00-00-00-61-6F-97-00-00-0A-26-00-2B-08-00-16-80-29-01-00-04-00-2A
[+] Overwriting bytecode for flared_55: 92-234-52-149-245-144-200-187-230-105-241-174-109-53-164-210-19-75-255-164-131-227-47-141-86-70-124-217-127-182-112-115-136-106-41-236-34-22-75-220-6-228-82-174-20-189-83-14-16-67-254-3-148-47-92-120-186-166-62-174-19-238-59-48-248-125-38-2-12-183-175-253-0-34-157-159-145-129-121-152-243-110-200-60-184-108-222
[+] Offset found: 0xBC78
[+] Decrypting flared_56 (flared_56) ...
[+] Generating hash from MethodInfo for: flared_56
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: FlareOn.Backdoor.FLARE07
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: 7F-02-00-00
[+] Value of bytes6: FlareOn.Backdoor.FLARE07System.BooleanFlareOn.Backdoor.FLARE14+<>c__DisplayClass14_0System.Byte[]System.Byte[]System.Byte[]System.BooleanSystem.StringSystem.Int32System.BooleanSystem.ExceptionFlareOn.Backdoor.FLARE14+<>c__DisplayClass14_1System.Threading.ThreadSystem.BooleanSystem.BooleanSystem.BooleanSystem.Byte[]System.BooleanSystem.BooleanSystem.ExceptionFlareOn.Backdoor.FLARE07
[+] Value of bytes7:
[+] Final SHA256: 4ea4cf8de819a44de373cd43d1dd3eedd2d85b497d2dc620e85aa350f264f787
[+] Calculating method hash: 4ea4cf8de819a44de373cd43d1dd3eedd2d85b497d2dc620e85aa350f264f787
[+] Loading PE Section: 4ea4cf8d
[+] PE Section contents: 96-5F-F4-71-7A-B4-50-2F-0D-27-6E-FD-74-18-DB-34-16-4B-65-BC-D7-E1-F7-A9-F8-05-71-35-23-32-8D-63-17-54-65-38-55-EC-BA-05-49-AC-A1-A6-37-C1-64-9D-70-4C-BB-81-56-1B-F6-9E-4B-C4-21-93-E4-53-5F-FB-F2-1E-D4-B3-7C-70-52-BD-5C-94-92-FE-AC-CA-62-A8-02-6B-C0-50-78-BC-AA-40-48-AC-2D-AC-09-EC-8F-11-21-89-73-0B-FA-67-C4-23-20-6C-4F-98-2B-75-E5-26-69-44-86-FD-90-28-3E-5E-8D-D8-F4-D2-C9-77-32-B1-12-DB-A0-B4-64-B8-C1-D5-C6-D1-A0-EE-C2-DD-A2-21-AE-F4-7A-1E-46-A9-56-07-DB-C6-E1-F7-16-EF-AD-D1-46-2E-8B-6E-9C-9E-A1-73-30-FA-FF-08-9B-97-B6-EF-B5-C2-10-F2-89-F1-83-F7-14-F1-01-26-E3-40-90-E5-F1-2C-55-C5-42-F3-44-4A-F4-52-5E-53-AF-A6-70-DA-8E-D0-5B-62-B8-4A-83-AD-8F-0C-F1-54-B0-B9-C7-37-34-8A-62-FC-B0-D8-CA-1C-9B-0F-E2-70-0B-2E-88-EE-F1-9B-28-01-90-02-1A-A0-C0-F7-EB-FD-15-16-35-3C-D2-17-7A-61-65-E4-08-99-D0-B6-A8-7A-30-8F-82-5E-44-DB-CE-15-DF-82-1C-8B-4B-39-2A-42-DD-26-02-85-02-59-43-51-2E-9F-FE-CB-E5-6E-63-C3-2C-45-3B-FC-F0-DA-A7-00-18-37-C6-3D-8A-6B-78-E0-7F-94-EB-12-87-50-49-FC-63-52-C3-71-62-2C-FA-F3-2F-74-46-E0-D7-C8-67-7E-D2-69-CB-E5-45-0F-63-3A-0C-2D-66-EA-C7-2D-1A-44-58-A2-CF-DD-53-37-43-B6-F3-FF-51-D6-94-1D-BC-A7-EF-88-F4-84-D2-D2-A9-75-B2-42-91-B3-61-5F-97-E0-81-49-E6-8C-27-7B-A5-37-E6-2B-D2-AF-40-A0-7B-8C-90-EC-5F-F5-F0-E3-AA-36-18-15-A5-EC-7D-08-AB-B4-95-34-98-72-EF-B8-2D-0C-F3-3B-51-AF-B1-44-9C-70-BE-81-BB-AB-CF-4A-31-C6-3B-9E-9B-04-41-67-33-6C-FC-78-B7-CD-DF-06-30-75-8D-8C-37-47-C9-02-84-22-13-23-2F-BE-61-86-4C-96-49-3F-66-7E-3C-AE-62-4B-73-96-D5-FE-63-29-F5-02-54-F3-7F-E1-E5-90-15-FE-74-C3-15-1B-85-46-45-57-82-58-C2-79-F3-4A-9F-EB-3B-8A-4B-6E-A0-04-CB-B8-25-8C-7E-44-2B-5B-A1-41-17-89-C2-16-D6-E3-DC-73-1D-3C-96-65-8C-5D-B2-68-CF-72-46-6A-42-7E-DE-AF-C1-06-94-D9-9A-60-53-95-F2-75-71-B7-46-B3-64-26-E7-56-AF-B7-6E-D2-C7-B2-A4-28-FF-8E-4C-C5-B6-83-08-D1-32-E3-3B-AD-36-FE-6D-BB-9B-81-5E-37-F3-B7-94-27-4E-C8-36-86-CE-FF-40-E3-AB-40-09-6A-7B-E7-0A-09-A7-75-30-3B-CB-19-AF-3A-9D-65-EB-A8-DE-BD-6E-88-95
[+] Decrypted Bytecode: 00-17-0A-00-7E-97-A7-98-A6-6F-25-A6-98-A8-16-31-10-7E-97-A7-98-A6-16-6F-24-A6-98-A8-14-FE-03-2B-01-16-0B-07-39-43-02-00-00-73-23-A6-98-A4-0C-00-7E-97-A7-98-A6-16-6F-24-A6-98-A8-0D-08-09-16-91-7D-96-A7-98-A6-09-17-28-B9-A6-98-89-28-BB-A6-98-89-13-04-08-14-7D-91-A7-98-A6-08-7B-96-A7-98-A6-1F-5F-2E-0C-08-7B-96-A7-98-A6-1F-60-FE-01-2B-01-17-13-06-11-06-39-87-00-00-00-00-00-08-7B-96-A7-98-A6-1F-60-FE-01-13-09-11-09-2C-0B-00-11-04-28-90-A6-98-A4-13-04-00-11-04-1F-7C-28-B6-A6-98-89-13-08-28-2C-A6-98-A8-11-04-11-08-28-B8-A6-98-89-28-BB-A6-98-89-6F-2E-A6-98-A8-11-04-11-08-17-58-28-B9-A6-98-89-28-BB-A6-98-89-28-26-A6-98-A8-00-72-9A-A5-98-D2-13-07-00-DE-0F-13-0A-00-11-0A-6F-21-A6-98-A8-13-07-00-DE-00-08-28-2C-A6-98-A8-11-07-6F-20-A6-98-A8-7D-91-A7-98-A6-00-38-9B-00-00-00-73-22-A6-98-A4-13-0B-11-0B-08-7D-93-A7-98-A6-00-11-0B-7B-93-A7-98-A6-7B-96-A7-98-A6-1F-47-FE-01-13-0D-11-0D-2C-0B-00-11-04-28-90-A6-98-A4-13-04-00-11-0B-28-2C-A6-98-A8-11-04-6F-2E-A6-98-A8-7D-90-A7-98-A6-11-0B-FE-06-1D-A6-98-A4-73-C4-A6-98-A8-73-C7-A6-98-A8-13-0C-11-0C-6F-C6-A6-98-A8-00-11-0C-7E-B1-A6-98-A6-6F-23-A6-98-A8-16-FE-01-13-0E-11-0E-2C-25-00-11-0C-6F-22-A6-98-A8-00-11-0B-7B-93-A7-98-A6-28-2C-A6-98-A8-72-90-A5-98-D2-6F-20-A6-98-A8-7D-91-A7-98-A6-00-00-08-7B-91-A7-98-A6-14-FE-03-13-0F-11-0F-2C-67-00-08-7B-91-A7-98-A6-28-96-A6-98-A4-13-10-11-10-8E-69-08-7B-91-A7-98-A6-8E-69-FE-04-13-11-11-11-2C-21-00-08-17-8D-92-A6-98-A3-25-16-1F-3D-9C-11-10-28-B1-A6-98-89-28-BB-A6-98-89-7D-91-A7-98-A6-00-2B-23-00-08-17-8D-92-A6-98-A3-25-16-1F-39-9C-08-7B-91-A7-98-A6-28-B1-A6-98-89-28-BB-A6-98-89-7D-91-A7-98-A6-00-00-08-7B-91-A7-98-A6-2C-0A-08-7B-91-A7-98-A6-8E-69-2B-01-16-8D-92-A6-98-A3-13-05-08-7B-91-A7-98-A6-14-FE-03-13-12-11-12-2C-1A-00-08-7B-91-A7-98-A6-16-11-05-16-08-7B-91-A7-98-A6-8E-69-28-D9-A6-98-A8-00-00-7E-97-A7-98-A6-16-6F-1C-A6-98-A8-00-1A-0A-11-05-28-FF-A6-98-A4-00-00-00-DE-08-13-13-00-17-0A-00-DE-00-06-13-14-2B-00-11-14-2A
[+] Rellocated Bytecode: 00-17-0A-00-7E-2A-01-00-04-6F-98-00-00-0A-16-31-10-7E-2A-01-00-04-16-6F-99-00-00-0A-14-FE-03-2B-01-16-0B-07-39-43-02-00-00-73-9E-00-00-06-0C-00-7E-2A-01-00-04-16-6F-99-00-00-0A-0D-08-09-16-91-7D-2B-01-00-04-09-17-28-04-00-00-2B-28-06-00-00-2B-13-04-08-14-7D-2C-01-00-04-08-7B-2B-01-00-04-1F-5F-2E-0C-08-7B-2B-01-00-04-1F-60-FE-01-2B-01-17-13-06-11-06-39-87-00-00-00-00-00-08-7B-2B-01-00-04-1F-60-FE-01-13-09-11-09-2C-0B-00-11-04-28-2D-00-00-06-13-04-00-11-04-1F-7C-28-0B-00-00-2B-13-08-28-91-00-00-0A-11-04-11-08-28-05-00-00-2B-28-06-00-00-2B-6F-93-00-00-0A-11-04-11-08-17-58-28-04-00-00-2B-28-06-00-00-2B-28-9B-00-00-0A-00-72-27-03-00-70-13-07-00-DE-0F-13-0A-00-11-0A-6F-9C-00-00-0A-13-07-00-DE-00-08-28-91-00-00-0A-11-07-6F-9D-00-00-0A-7D-2C-01-00-04-00-38-9B-00-00-00-73-9F-00-00-06-13-0B-11-0B-08-7D-2E-01-00-04-00-11-0B-7B-2E-01-00-04-7B-2B-01-00-04-1F-47-FE-01-13-0D-11-0D-2C-0B-00-11-04-28-2D-00-00-06-13-04-00-11-0B-28-91-00-00-0A-11-04-6F-93-00-00-0A-7D-2D-01-00-04-11-0B-FE-06-A0-00-00-06-73-79-00-00-0A-73-7A-00-00-0A-13-0C-11-0C-6F-7B-00-00-0A-00-11-0C-7E-0C-00-00-04-6F-9E-00-00-0A-16-FE-01-13-0E-11-0E-2C-25-00-11-0C-6F-9F-00-00-0A-00-11-0B-7B-2E-01-00-04-28-91-00-00-0A-72-2D-03-00-70-6F-9D-00-00-0A-7D-2C-01-00-04-00-00-08-7B-2C-01-00-04-14-FE-03-13-0F-11-0F-2C-67-00-08-7B-2C-01-00-04-28-2B-00-00-06-13-10-11-10-8E-69-08-7B-2C-01-00-04-8E-69-FE-04-13-11-11-11-2C-21-00-08-17-8D-2F-00-00-01-25-16-1F-3D-9C-11-10-28-0C-00-00-2B-28-06-00-00-2B-7D-2C-01-00-04-00-2B-23-00-08-17-8D-2F-00-00-01-25-16-1F-39-9C-08-7B-2C-01-00-04-28-0C-00-00-2B-28-06-00-00-2B-7D-2C-01-00-04-00-00-08-7B-2C-01-00-04-2C-0A-08-7B-2C-01-00-04-8E-69-2B-01-16-8D-2F-00-00-01-13-05-08-7B-2C-01-00-04-14-FE-03-13-12-11-12-2C-1A-00-08-7B-2C-01-00-04-16-11-05-16-08-7B-2C-01-00-04-8E-69-28-64-00-00-0A-00-00-7E-2A-01-00-04-16-6F-A1-00-00-0A-00-1A-0A-11-05-28-42-00-00-06-00-00-00-DE-08-13-13-00-17-0A-00-DE-00-06-13-14-2B-00-11-14-2A
[+] Overwriting bytecode for flared_56: 94-14-10-65-80-254-217-127-246-95-83-250-59-216-14-208-255-56-224-253-190-73-36-151-101-140-55-114-48-121-46-129-201-234-75-124-124-184-160-40-0-192-251-62-113-27-133-253-223-146-55-35-190-141-8-21-233-115-219-195-198-103-78-125-48-210-48-80-140-145-83-70-151-183-252-254-77-230-38-74-6-58-147-158-66-10-195-59-225-54-147-9-220-221-98-153-114-126-14-159-234-52-113-77-62-240-140-6-144-10-199-3-77-145-188-140-212-175-58-38-14-245-111-86-254-73-106-186-85-99-140-207-216-134-95-210-200-69-95-81-126-188-170-214-111-144-188-75-32-213-196-194-67-232-144-245-197-27-78-245-134-209-177-45-126-247-43-198-49-234-195-142-79-232-167-82-74-152-230-110-141-30-154-127-159-201-139-240-246-106-12-173-246-106-203-172-11-125-88-119-101-245-25-53-18-54-115-90-64-62-170-44-52-224-103-103-55-49-141-180-108-58-207-198-221-21-151-228-29-250-70-204-64-111-9-151-4-100-109-105-85-49-175-184-191-224-121-22-2-100-117-218-239-163-11-0-37-82-88-253-158-142-61-69-247-222-236-196-215-208-98-210-196-36-94-58-139-23-7-253-156-129-226-185-133-108-220-156-100-222-113-178-12-112-202-199-244-106-192-225-243-180-62-50-1-163-22-203-68-208-158-14-75-90-97-29-172-132-192-139-1-79-96-248-94-176-198-83-90-151-70-33-86-37-9-231-66-175-183-226-86-17-88-147-63-99-102-177-15-173-26-111-169-53-223-163-83-70-212-81-220-194-113-172-137-125-183-37-80-121-218-253-204-222-52-239-247-204-184-251-74-20-68-172-124-215-119-32-70-101-147-252-219-102-5-147-160-171-10-194-171-65-96-149-210-29-162-202-0-239-172-134-141-216-7-200-125-196-47-178-6-150-223-235-229-222-33-102-217-161-79-76-194-246-79-8-179-175-218-95-52-172-31-86-185-13-111-2-95-61-22-220-123-87-188-20-97-117-176-243-251-60-241-95-160-95-196-150-137-254-20-206-233-208-126-89-118-137-49-216-111-31-7-156-138-115-209-106-58-58-167-61-255-230-99-247-186-192-181-89-72-216-121-97-40-71-242-170-217-98-157-216-68-215-132-220-53-85-213-45-142-89-92-78-86-214-207-3-109-134-158-182-211-215-143-150-165-165-115-67-128-38-145-215-157-207-249-39-97-134-194-101-234-136-203-238-124-43-10-81-120-239-61-82-196-231-4-108-71-237-55-143-225-146-172-103-200-132-177-135-221-167-161-230-196-57-203-75-12-161-26-122-155-33-202-144-233-62-19-181-202-140-223-116-79-50-131-88-219-99-38-248-121-131-116-208-78-86-142-139-27-184-96-166-211-188-244-192-199-28-126-138-112-251-188-80-200-45-151
[+] Offset found: 0xBD28
[+] Decrypting flared_57 (flared_57) ...
[+] Generating hash from MethodInfo for: flared_57
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 33-00-00-00
[+] Value of bytes6: System.Diagnostics.StackTraceSystem.String
[+] Value of bytes7:
[+] Final SHA256: 310d4de08e81de33d5601d3d7912008f20b2b7749f06566e52db6a77e1f4bdc5
[+] Calculating method hash: 310d4de08e81de33d5601d3d7912008f20b2b7749f06566e52db6a77e1f4bdc5
[+] Loading PE Section: 310d4de0
[+] PE Section contents: 96-3B-E1-D7-9C-8B-FD-B1-BC-27-55-FD-74-18-A2-1C-A0-AD-5A-74-B6-E1-79-6E-DA-BB-86-83-91-54-26-27-0F-E4-F6-97-03-56-1E-9D-E1-F7-17-A6-37-CD-63-B6-0E-DC-36
[+] Decrypted Bytecode: 00-73-1F-A6-98-A8-0A-06-17-6F-1E-A6-98-A8-6F-19-A6-98-A8-6F-F9-A6-98-A8-06-18-6F-1E-A6-98-A8-6F-19-A6-98-A8-6F-F9-A6-98-A8-28-95-A6-98-A8-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-73-A2-00-00-0A-0A-06-17-6F-A3-00-00-0A-6F-A4-00-00-0A-6F-44-00-00-0A-06-18-6F-A3-00-00-0A-6F-A4-00-00-0A-6F-44-00-00-0A-28-28-00-00-0A-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_57: 180-177-8-229-192-71-4-209-153-198-102-146-248-22-38-181-197-30-130-169-235-233-135-220-139-71-108-144-199-114-221-234-245-157-247-83-92-56-89-239-195-15-147-187-106-150-69-35-205-136-105
[+] Offset found: 0xBFE8
[+] Decrypting flared_58 (flared_58) ...
[+] Generating hash from MethodInfo for: flared_58
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 71-00-00-00
[+] Value of bytes6: System.StringSystem.Int32System.StringFlareOn.Backdoor.FLARE11System.Int32System.Int32System.CharSystem.BooleanSystem.String
[+] Value of bytes7: System.Int32
[+] Final SHA256: 8d3a199fa17ab158db9c7b072881ce611fae801896acb5b18b8836147222feef
[+] Calculating method hash: 8d3a199fa17ab158db9c7b072881ce611fae801896acb5b18b8836147222feef
[+] Loading PE Section: 8d3a199f
[+] PE Section contents: 96-36-4D-D7-9C-85-FD-B1-C4-C1-ED-C3-44-BB-B3-91-A0-AD-5A-17-3C-84-47-5E-78-AE-EB-B5-FF-6A-16-EC-16-54-7D-3B-47-97-B8-13-4F-B0-0B-A6-37-CD-40-5B-A8-43-B8-0A-F5-05-9F-AB-E8-33-02-38-74-F2-5A-6C-9D-8E-5B-38-7C-E1-ED-BD-70-94-92-DF-88-77-D5-35-9C-17-D6-FE-F4-69-31-E7-C1-0E-32-8F-8C-4F-06-B3-39-28-59-14-F5-0D-55-A9-05-C2-43-F0-FE-74-DF-2F-54
[+] Decrypted Bytecode: 00-7E-B3-A6-98-A6-0A-06-6F-89-A6-98-A8-0B-7E-94-A6-98-A8-0C-73-C3-A6-98-A4-0D-02-28-C8-A6-98-A4-00-16-13-04-2B-38-00-16-06-6F-89-A6-98-A8-28-C6-A6-98-A4-13-05-08-06-11-05-6F-8B-A6-98-A8-13-06-12-06-28-13-A6-98-A8-28-95-A6-98-A8-0C-06-11-05-17-6F-12-A6-98-A8-0A-00-11-04-17-58-13-04-11-04-07-FE-04-13-07-11-07-2D-BD-08-13-08-2B-00-11-08-2A
[+] Rellocated Bytecode: 00-7E-0E-00-00-04-0A-06-6F-34-00-00-0A-0B-7E-29-00-00-0A-0C-73-7E-00-00-06-0D-02-28-75-00-00-06-00-16-13-04-2B-38-00-16-06-6F-34-00-00-0A-28-7B-00-00-06-13-05-08-06-11-05-6F-36-00-00-0A-13-06-12-06-28-AE-00-00-0A-28-28-00-00-0A-0C-06-11-05-17-6F-AF-00-00-0A-0A-00-11-04-17-58-13-04-11-04-07-FE-04-13-07-11-07-2D-BD-08-13-08-2B-00-11-08-2A
[+] Overwriting bytecode for flared_58: 146-203-43-97-70-31-228-159-133-212-59-86-255-170-77-142-203-248-137-31-163-82-39-165-138-3-195-105-247-186-232-4-232-35-27-160-66-233-143-78-123-30-144-213-242-105-143-242-212-177-239-17-200-141-60-63-164-134-214-67-92-122-167-202-235-54-109-219-143-172-76-226-104-59-163-132-193-81-178-32-115-208-149-70-203-215-59-90-230-219-251-187-18-76-241-1-119-197-234-188-252-180-99-39-101-13-168-141-233-184-125-83-212
[+] Offset found: 0x19714
[+] Decrypting flared_59 (flared_59) ...
[+] Generating hash from MethodInfo for: flared_59
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: 4C-00-00-00
[+] Value of bytes6: System.StringSystem.Int32System.CharSystem.BooleanSystem.String
[+] Value of bytes7: System.StringSystem.String
[+] Final SHA256: 1b8e223862dbfda65e539a98367650c1f80080f5470117c4cf5d77548d90debc
[+] Calculating method hash: 1b8e223862dbfda65e539a98367650c1f80080f5470117c4cf5d77548d90debc
[+] Loading PE Section: 1b8e2238
[+] PE Section contents: 96-36-6A-D7-9C-8B-FD-A1-A0-63-67-5B-EA-B3-B3-B6-A0-AD-54-19-48-28-6A-60-44-0B-86-90-91-54-26-27-9D-E4-F6-97-60-BD-BA-2D-5A-79-1A-A8-87-F0-CE-05-A6-D1-1C-1E-E7-55-92-BD-EF-33-00-38-74-F2-B7-6E-82-81-5E-EC-DC-6A-41-BE-E5-23-0E-5D
[+] Decrypted Bytecode: 00-7E-94-A6-98-A8-0A-16-0B-2B-2C-00-06-03-7E-B3-A6-98-A6-02-07-6F-8B-A6-98-A8-6F-0D-A6-98-A8-6F-8B-A6-98-A8-0C-12-02-28-13-A6-98-A8-28-95-A6-98-A8-0A-00-07-17-58-0B-07-02-6F-89-A6-98-A8-FE-04-0D-09-2D-C7-06-13-04-2B-00-11-04-2A
[+] Rellocated Bytecode: 00-7E-29-00-00-0A-0A-16-0B-2B-2C-00-06-03-7E-0E-00-00-04-02-07-6F-36-00-00-0A-6F-B0-00-00-0A-6F-36-00-00-0A-0C-12-02-28-AE-00-00-0A-28-28-00-00-0A-0A-00-07-17-58-0B-07-02-6F-34-00-00-0A-FE-04-0D-09-2D-C7-06-13-04-2B-00-11-04-2A
[+] Overwriting bytecode for flared_59: 190-1-46-51-155-27-155-129-106-82-212-146-24-112-183-30-22-200-149-174-169-113-95-100-147-139-12-124-91-194-121-138-81-135-239-148-158-37-249-4-144-58-88-69-102-0-57-130-116-14-82-116-113-18-4-77-161-202-159-16-14-31-37-168-217-73-64-144-129-34-127-241-207-145-30-111
[+] Offset found: 0x197DC
[+] Decrypting flared_60 (flared_60) ...
[+] Generating hash from MethodInfo for: flared_60
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 11-00-00-00
[+] Value of bytes6: System.String
[+] Value of bytes7: System.Int32
[+] Final SHA256: e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb
[+] Calculating method hash: e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb
[+] Loading PE Section: e712183a
[+] PE Section contents: 96-4A-80-C3-A2-BB-51-9F-BB-EE-D3-FF-E6-9B-CD-03-2C
[+] Decrypted Bytecode: 00-02-7E-B2-A6-98-A6-28-10-A6-98-A4-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-02-7E-0F-00-00-04-28-AD-00-00-06-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_60: 18-113-182-210-119-163-164-17-255-160-194-20-30-90-147-15-49
[+] Offset found: 0x1987C
[+] Decrypting flared_61 (flared_61) ...
[+] Generating hash from MethodInfo for: flared_61
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 11-00-00-00
[+] Value of bytes6: System.String
[+] Value of bytes7: System.Int32
[+] Final SHA256: e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb
[+] Calculating method hash: e712183aad38b4e510347e6968c89b0915acd954e66847b84cd34d687ac021cb
[+] Loading PE Section: e712183a
[+] PE Section contents: 96-4A-80-C3-A2-BB-51-9F-BB-EE-D3-FF-E6-9B-CD-03-2C
[+] Decrypted Bytecode: 00-02-7E-B2-A6-98-A6-28-10-A6-98-A4-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-02-7E-0F-00-00-04-28-AD-00-00-06-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_61: 0-78-150-238-74-25-77-29-105-120-55-55-62-199-10-245-99
[+] Offset found: 0x198E4
[+] Decrypting flared_62 (flared_62) ...
[+] Generating hash from MethodInfo for: flared_62
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Int32
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 12-00-00-00
[+] Value of bytes6: System.Int32
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: 69991a3e95c5119fa78d5cffeff4bd913768663e601fcf7fd028ec252aab1571
[+] Calculating method hash: 69991a3e95c5119fa78d5cffeff4bd913768663e601fcf7fd028ec252aab1571
[+] Loading PE Section: 69991a3e
[+] PE Section contents: 96-4A-D6-63-A2-BB-53-A1-83-44-ED-C3-44-BA-E6-05-00-1F
[+] Decrypted Bytecode: 00-02-28-12-A6-98-A4-16-28-0C-A6-98-A8-0A-2B-00-06-2A
[+] Rellocated Bytecode: 00-02-28-AF-00-00-06-16-28-B1-00-00-0A-0A-2B-00-06-2A
[+] Overwriting bytecode for flared_62: 29-80-173-5-140-180-213-73-143-16-119-63-186-10-169-82-200-157
[+] Offset found: 0x1994C
[+] Decrypting flared_63 (flared_63) ...
[+] Generating hash from MethodInfo for: flared_63
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 3D-00-00-00
[+] Value of bytes6: System.StringSystem.Int32System.CharSystem.BooleanSystem.String
[+] Value of bytes7: System.Int32System.String
[+] Final SHA256: 710b11bc609c76eddf0b9d50f342e8ba89479aff881fa83407a6262515f7f9f2
[+] Calculating method hash: 710b11bc609c76eddf0b9d50f342e8ba89479aff881fa83407a6262515f7f9f2
[+] Loading PE Section: 710b11bc
[+] PE Section contents: 96-36-6A-D7-9C-8B-FD-B4-C4-C1-ED-C3-44-BB-CD-06-04-32-AF-74-C4-E1-79-6E-D0-B1-EB-B5-24-6A-16-E0-10-6A-FB-99-F4-07-B2-07-4E-84-92-00-AF-67-7E-63-0C-D6-15-34-29-0B-8A-BE-C6-5C-98-9A-C6
[+] Decrypted Bytecode: 00-7E-94-A6-98-A8-0A-03-6F-89-A6-98-A8-0B-00-03-02-07-5D-6F-8B-A6-98-A8-0C-12-02-28-13-A6-98-A8-06-28-95-A6-98-A8-0A-02-07-5B-10-00-00-02-16-FE-02-0D-09-2D-D9-06-13-04-2B-00-11-04-2A
[+] Rellocated Bytecode: 00-7E-29-00-00-0A-0A-03-6F-34-00-00-0A-0B-00-03-02-07-5D-6F-36-00-00-0A-0C-12-02-28-AE-00-00-0A-06-28-28-00-00-0A-0A-02-07-5B-10-00-00-02-16-FE-02-0D-09-2D-D9-06-13-04-2B-00-11-04-2A
[+] Overwriting bytecode for flared_63: 76-35-120-121-110-230-5-76-122-245-29-51-202-245-143-220-117-249-129-126-130-71-106-56-236-209-151-233-37-52-123-191-205-64-232-4-40-196-199-39-121-183-227-177-144-113-43-6-109-125-169-26-227-35-185-4-185-64-141-157-79
[+] Offset found: 0x199B0
[+] Decrypting flared_64 (flared_64) ...
[+] Generating hash from MethodInfo for: flared_64
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Byte[]
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 3C-00-00-00
[+] Value of bytes6: System.BooleanSystem.Byte[]
[+] Value of bytes7: System.Byte[]
[+] Final SHA256: 807617625d41107bf8992c570a8669c792bf094237b2fdbbf2b63a0258fd77e2
[+] Calculating method hash: 807617625d41107bf8992c570a8669c792bf094237b2fdbbf2b63a0258fd77e2
[+] Loading PE Section: 80761762
[+] PE Section contents: 96-36-F1-D7-9C-8B-FD-B1-87-54-4B-59-C4-83-6B-9D-AE-35-F0-0C-C2-D5-47-5E-7F-8B-58-3B-AF-45-A6-F3-B0-DA-E7-34-47-BB-AF-88-DB-79-1A-A3-AD-4D-D9-3B-96-52-34-A2-56-95-10-B1-C6-5C-8E-B4
[+] Decrypted Bytecode: 00-7E-0F-A6-98-A8-0A-06-2C-1C-00-02-28-33-A6-98-A8-00-02-17-8D-92-A6-98-A3-28-B1-A6-98-89-28-BB-A6-98-89-0B-2B-14-17-8D-92-A6-98-A3-02-28-B1-A6-98-89-28-BB-A6-98-89-0B-2B-00-07-2A
[+] Rellocated Bytecode: 00-7E-B2-00-00-0A-0A-06-2C-1C-00-02-28-8E-00-00-0A-00-02-17-8D-2F-00-00-01-28-0C-00-00-2B-28-06-00-00-2B-0B-2B-14-17-8D-2F-00-00-01-02-28-0C-00-00-2B-28-06-00-00-2B-0B-2B-00-07-2A
[+] Overwriting bytecode for flared_64: 182-54-7-211-25-119-44-241-177-249-57-142-86-142-172-85-7-178-240-140-36-1-150-124-196-183-202-159-188-161-210-35-78-17-182-8-78-138-27-120-176-115-193-59-222-70-172-113-131-157-23-67-86-183-210-181-160-139-15-97
[+] Offset found: 0x19A4C
[+] Decrypting flared_65 (flared_65) ...
[+] Generating hash from MethodInfo for: flared_65
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Void
[+] Value of bytes3: Standard
[+] Value of bytes4: 2
[+] Value of bytes5: 67-00-00-00
[+] Value of bytes6: System.Int32System.Int32FlareOn.Backdoor.FLARE06+DTFlareOn.Backdoor.FLARE06+DT
[+] Value of bytes7: FlareOn.Backdoor.FLARE06+DT
[+] Final SHA256: 4951e5478e0781cc7c74837c1b3897c6beaefcf41f1f92686ee50f627f2ca36b
[+] Calculating method hash: 4951e5478e0781cc7c74837c1b3897c6beaefcf41f1f92686ee50f627f2ca36b
[+] Loading PE Section: 4951e547
[+] PE Section contents: 96-5F-F4-66-0F-21-FA-BE-A7-40-0E-5F-EC-B0-CD-07-06-35-F2-0B-4F-47-E1-D8-DC-A3-E9-B1-37-CC-8E-63-2E-3C-D0-99-F4-09-B2-7B-F0-79-1A-A6-A4-4E-42-E3-B6-7D-84-BF-FA-73-22-1C-75-FA-82-B5-F0-24-F3-CC-17-2E-79-55-6F-DF-DD-33-EE-19-04-09-30-D7-5C-96-81-06-73-FE-F4-67-30-CC-D0-0C-22-FF-50-ED-8F-13-16-16-FB-9F-5A-1C-78
[+] Decrypted Bytecode: 00-17-0A-17-0B-02-0D-09-0C-08-45-04-00-00-00-02-00-00-00-10-00-00-00-1E-00-00-00-2C-00-00-00-2B-38-7E-BE-A6-98-A6-0A-7E-B9-A6-98-A6-0B-2B-2A-7E-B8-A6-98-A6-0A-7E-BB-A6-98-A6-0B-2B-1C-7E-BA-A6-98-A6-0A-7E-B5-A6-98-A6-0B-2B-0E-7E-B4-A6-98-A6-0A-7E-B7-A6-98-A6-0B-2B-00-06-07-28-CF-A6-98-A4-28-C0-A6-98-A8-00-2A
[+] Rellocated Bytecode: 00-17-0A-17-0B-02-0D-09-0C-08-45-04-00-00-00-02-00-00-00-10-00-00-00-1E-00-00-00-2C-00-00-00-2B-38-7E-03-00-00-04-0A-7E-04-00-00-04-0B-2B-2A-7E-05-00-00-04-0A-7E-06-00-00-04-0B-2B-1C-7E-07-00-00-04-0A-7E-08-00-00-04-0B-2B-0E-7E-09-00-00-04-0A-7E-0A-00-00-04-0B-2B-00-06-07-28-72-00-00-06-28-7D-00-00-0A-00-2A
[+] Overwriting bytecode for flared_65: 170-214-52-191-232-74-180-49-176-164-32-71-7-199-21-97-175-242-54-126-103-222-205-225-159-203-48-186-166-71-253-140-9-213-124-46-69-217-29-102-52-177-28-38-62-235-183-227-161-253-221-208-66-127-46-204-9-83-32-29-26-249-139-104-166-148-62-49-74-230-27-213-213-208-74-181-193-166-162-179-20-76-25-169-106-45-74-138-167-175-36-242-185-0-76-59-38-180-128-170-173-133-153
[+] Offset found: 0x19AD8
[+] Decrypting flared_66 (flared_66) ...
[+] Method flared_66() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_66
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.String
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 0C-02-00-00
[+] Value of bytes6: System.Reflection.ModuleSystem.Reflection.MethodInfoSystem.Reflection.MethodBodySystem.StringSystem.StringSystem.Byte[]System.Byte[]System.Byte[]System.Byte[]System.Byte[]System.Byte[]System.Byte[]System.Security.Cryptography.IncrementalHashSystem.Byte[]System.Text.StringBuilderSystem.Reflection.MethodAttributesSystem.Reflection.CallingConventionsSystem.Reflection.ParameterInfo[]System.Int32System.Reflection.ParameterInfoSystem.Int32System.Collections.Generic.IEnumerator`1[System.Reflection.LocalVariableInfo]System.Reflection.LocalVariableInfoSystem.Int32System.BooleanSystem.String
[+] Value of bytes7: System.Int32
[+] Final SHA256: 37875be24378a8f648fac988941910ee9af9a5926e6ffbe1f5420bce034e00fb
[+] Removing SHA256 from list: 37875be24378a8f648fac988941910ee9af9a5926e6ffbe1f5420bce034e00fb
[+] Decrypting flared_67 (flared_67) ...
[+] Method flared_67() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_67
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Object
[+] Value of bytes3: Standard
[+] Value of bytes4: 5
[+] Value of bytes5: DC-0D-00-00
[+] Value of bytes6: System.Collections.Generic.Dictionary`2[System.UInt32,FlareOn.Backdoor.FLARE06+OT]System.UInt32System.UInt32System.Int32System.Reflection.ModuleSystem.Reflection.MethodBaseSystem.Reflection.MethodInfoSystem.Reflection.ParameterInfo[]System.Type[]System.Reflection.Emit.SignatureHelperSystem.TypeSystem.Reflection.Emit.DynamicMethodSystem.Reflection.Emit.DynamicILInfoSystem.Reflection.MethodBodySystem.Byte[]System.Int32System.BooleanSystem.Collections.Generic.IEnumerator`1[System.Reflection.LocalVariableInfo]System.Reflection.LocalVariableInfoSystem.Int32FlareOn.Backdoor.FLARE06+OTSystem.BooleanFlareOn.Backdoor.FLARE06+OTFlareOn.Backdoor.FLARE06+OTSystem.BooleanSystem.TypeSystem.Type[]System.Type[]System.Reflection.MemberInfoSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.BooleanSystem.Object
[+] Value of bytes7: System.Byte[]System.Int32System.Object[]
[+] Final SHA256: 8a966e195c4e8117f070d085b2dc6b9ab62eec402bab94a1e317802e2676cf72
[+] Removing SHA256 from list: 8a966e195c4e8117f070d085b2dc6b9ab62eec402bab94a1e317802e2676cf72
[+] Decrypting flared_68 (flared_68) ...
[+] Method flared_68() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_68
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Int32
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: 37-00-00-00
[+] Value of bytes6: System.Int32System.Int32
[+] Value of bytes7: System.Byte[]System.Int32
[+] Final SHA256: a537f738601625b8ae6a20e79b0c92c55738cc5d3f94e50b6c29bdfd698e9263
[+] Removing SHA256 from list: a537f738601625b8ae6a20e79b0c92c55738cc5d3f94e50b6c29bdfd698e9263
[+] Decrypting flared_69 (flared_69) ...
[+] Method flared_69() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_69
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Byte[]
[+] Value of bytes3: Standard
[+] Value of bytes4: 4
[+] Value of bytes5: AC-00-00-00
[+] Value of bytes6: System.StringFlareOn.Backdoor.FLARE09System.Byte[]System.IO.FileStreamFlareOn.Backdoor.FLARE09+IMAGE_SECTION_HEADER[]System.Int32FlareOn.Backdoor.FLARE09+IMAGE_SECTION_HEADERSystem.BooleanSystem.Byte[]
[+] Value of bytes7: System.String
[+] Final SHA256: 344f2938932f8a3dee33c33357b422ef5d1d8f9607104350f320534ae937e0f7
[+] Removing SHA256 from list: 344f2938932f8a3dee33c33357b422ef5d1d8f9607104350f320534ae937e0f7
[+] Decrypting flared_70 (flared_70) ...
[+] Method flared_70() decrypted already in the 1st layer. Skip.
[+] Generating hash from MethodInfo for: flared_70
[+] Value of bytes : PrivateScope, Public, Static, HideBySig
[+] Value of bytes2: System.Object
[+] Value of bytes3: Standard
[+] Value of bytes4: 3
[+] Value of bytes5: 55-00-00-00
[+] Value of bytes6: System.Diagnostics.StackTraceSystem.Int32System.StringSystem.Byte[]System.Byte[]System.ObjectSystem.Object
[+] Value of bytes7: System.InvalidProgramExceptionSystem.Object[]
[+] Final SHA256: 31d823800a33883a8529585dce3128d12fe50c05dca4e9df3cdb5c792d50777c
[+] Removing SHA256 from list: 31d823800a33883a8529585dce3128d12fe50c05dca4e9df3cdb5c792d50777c
[+] Leftovers In PESectionNames: 5aeb2b97, 94957fff, 0e5cf5d9
[+] Loading PE Section: 5aeb2b97
[+] Loading PE Section: 94957fff
[+] Loading PE Section: 0e5cf5d9
[+] Decrypted Bytecode: 00-14-0A-72-A2-A7-98-D2-73-82-A6-98-A8-0B-07-6F-FD-A6-98-A8-0A-72-AC-A6-98-D2-0C-00-06-6F-FC-A6-98-A8-0D-2B-21-09-6F-FF-A6-98-A8-74-FD-A6-98-A3-13-04-00-11-04-72-E6-A7-98-D2-6F-FE-A6-98-A8-6F-F9-A6-98-A8-0C-00-09-6F-F8-A6-98-A8-2D-D7-DE-0B-09-2C-07-09-6F-FB-A6-98-A8-00-DC-08-13-05-2B-00-11-05-2A
[+] Rellocated Bytecode: 00-14-0A-72-1F-01-00-70-73-3F-00-00-0A-0B-07-6F-40-00-00-0A-0A-72-11-00-00-70-0C-00-06-6F-41-00-00-0A-0D-2B-21-09-6F-42-00-00-0A-74-40-00-00-01-13-04-00-11-04-72-5B-01-00-70-6F-43-00-00-0A-6F-44-00-00-0A-0C-00-09-6F-45-00-00-0A-2D-D7-DE-0B-09-2C-07-09-6F-46-00-00-0A-00-DC-08-13-05-2B-00-11-05-2A
[+] Offset found: 0x9A9C
[+] Decrypted Bytecode: 00-72-CE-A7-98-D2-02-72-10-A7-98-D2-28-A6-A6-98-A8-73-FA-A6-98-A8-0A-06-6F-F5-A6-98-A8-00-06-72-0E-A7-98-D2-6F-FE-A6-98-A8-6F-F9-A6-98-A8-0B-06-6F-F4-A6-98-A8-00-07-0C-2B-00-08-2A
[+] Rellocated Bytecode: 00-72-73-01-00-70-02-72-AD-01-00-70-28-1B-00-00-0A-73-47-00-00-0A-0A-06-6F-48-00-00-0A-00-06-72-B3-01-00-70-6F-43-00-00-0A-6F-44-00-00-0A-0B-06-6F-49-00-00-0A-00-07-0C-2B-00-08-2A
[+] Offset found: 0x9B58
Program finished! Bye bye :)
*/
