using dnlib.DotNet;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;


namespace BackdoorDecryptor
{
	public class DecryptLayer1
	{
		// This the list of methods that need to be decrypted.
		public static dynamic EncryptedMethodsInfo = new List<Tuple<Dictionary<uint, int>, byte[], string, string>>
		{
			Tuple.Create(BackdoorConstants.pe_m,      BackdoorConstants.pe_b, "flared_35", "FLARE09"),
			Tuple.Create(BackdoorConstants.d_m,       BackdoorConstants.d_b,  "flared_47", "FLARE12"),
			Tuple.Create(BackdoorConstants.gh_m,      BackdoorConstants.gh_b, "flared_66", "FLARE15"),
			Tuple.Create(BackdoorConstants.cl_m,      BackdoorConstants.cl_b, "flared_67", "FLARE15"),
			Tuple.Create(new Dictionary<uint, int>(), BackdoorConstants.rt_b, "flared_68", "FLARE15"),
			Tuple.Create(BackdoorConstants.gs_m,      BackdoorConstants.gs_b, "flared_69", "FLARE15"),
			Tuple.Create(BackdoorConstants.wl_m,      BackdoorConstants.wl_b, "flared_70", "FLARE15")
		};

		/** Gets all encrypted methods from backdoor binary (using dnlib). */
		public static Dictionary<String, MethodDef> GetEncryptedMethods(ModuleDefMD module)
		{
			var encryptedMethods = new Dictionary<String, MethodDef>();

			// We use `mod.GetTypes()` to get all types, including the nested ones
			// (`mod.Types` only gets the non-nested types).
			foreach (var type in module.GetTypes())
			{
				Console.WriteLine("[+] Checking class: {0}", type.FullName);

				if (type.FullName.StartsWith("FlareOn.Backdoor.FLARE") ||
					type.FullName.StartsWith("FlareOn.Backdoor.Program"))
				{
					foreach (var method in type.Methods)
					{
						if (method.Name.StartsWith("flared_"))
						{
							Console.WriteLine("[+]    Encrypted method found: {0}", method.FullName);
							encryptedMethods[method.Name] = method;
						}
					}
				}
			}

			return encryptedMethods;
		}

		/** Applies code rellocations to the decrypted function. */
		public static List<byte> DoCodeRellocations(Module asmModule, MethodInfo methodInfo, byte[] bytecode, Dictionary<uint, int> patches)
		{
			// Do what flare_71() does, but simpler: flare_71() resolves function offsets at
			// runtime, as it relocates the function into memory and executes it.
			//
			// Here, there is no need to relocate, as we do static analysis. All we have to do, is 
			// to patch the metadata tokens into bytecode.
			List<byte> relocated_bytecode = new List<byte>(bytecode);

			foreach (KeyValuePair<uint, int> keyValuePair in patches)
			{
				int tokenFor = keyValuePair.Value;
				uint key = keyValuePair.Key;

				Console.WriteLine("[+] Patching {0} at 0x{1:03X} ~> 0x{2:X}", methodInfo.Name, key, tokenFor);
				relocated_bytecode[(int)key] = (byte)tokenFor;
				relocated_bytecode[(int)(key + 1U)] = (byte)(tokenFor >> 8);
				relocated_bytecode[(int)(key + 2U)] = (byte)(tokenFor >> 16);
				relocated_bytecode[(int)(key + 3U)] = (byte)(tokenFor >> 24);
			}

			return relocated_bytecode;
		}

		/** Finds all occurrences of `pattern` into `source`. */
		public static IEnumerable<int> FindAll(byte[] source, byte[] pattern)
		{
			for (int i = 0; i < source.Length; i++)
			{
				if (source.Skip(i).Take(pattern.Length).SequenceEqual(pattern))
				{
					yield return i;
				}
			}
		}

		/** Patches a decrypted bytecode into the buffer wit the executable. */ 
		public static void PatchCodeToFile(byte[] buff, MethodInfo methodInfo, List<byte> new_bytecode)
		{
			byte[] encrypted_il = methodInfo.GetMethodBody().GetILAsByteArray();
			Console.WriteLine("[+] Overwriting bytecode for {0}: {1}",
							  methodInfo.Name, String.Join("-", encrypted_il));
			
			int matched_index = 0;

			foreach (var idx in FindAll(buff, encrypted_il))
			{
				Console.WriteLine("[+] Offset found: 0x{0:X}", idx);
				matched_index = idx;
			}

			// Index found. Apply patch (we assume exactly 1 match is found).
			for (int i = 0; i < new_bytecode.Count; ++i)
			{
				buff[matched_index + i] = new_bytecode[i];
			}
		}

		/** Applies the 1st layer of decryption to the backdoor. */
		public static byte[] Decrypt(string backdoor_filename)
		{
			Console.WriteLine("[+] Applying 1st layer of decryption to: {0}", backdoor_filename);

			ModuleContext modCtx = ModuleDef.CreateModuleContext();
			ModuleDefMD module = ModuleDefMD.Load(backdoor_filename, modCtx);

			var asm = Assembly.LoadFile(backdoor_filename);
			var asmModule = asm.GetModule("FlareOn.Backdoor.exe");

			byte[] buff = File.ReadAllBytes(backdoor_filename);

			var encryptedMethods = GetEncryptedMethods(module);
			foreach (var tuple in EncryptedMethodsInfo)
			{
				Console.WriteLine("[+] Decrypting method: {1}.{0}()", tuple.Item3, tuple.Item4);

				var encMethod = encryptedMethods[tuple.Item3];

				Type type = asm.GetType("FlareOn.Backdoor." + tuple.Item4);
				MethodInfo methodInfo = type.GetMethod(tuple.Item3);

				Console.WriteLine("[+] MetaData Token: 0x{0} ({1}) ~> RVA: 0x{2:X}",
								  encMethod.MDToken, methodInfo.Name, encMethod.RVA);

				var bytecode = DoCodeRellocations(asmModule, methodInfo, tuple.Item2, tuple.Item1);

				Console.WriteLine("[+] Decrypted Bytecode: {0}", String.Join("-", bytecode));

				PatchCodeToFile(buff, methodInfo, bytecode);
			}

			return buff;
		}
	}
}
/*
[+] Applying 1st layer of decryption to: C:\Users\ispol\Desktop\reversing\FlareOn.Backdoor.exe
[+] Checking class: <Module>
[+] Checking class: FlareOn.Backdoor.FLARE01
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE01::flared_00(System.Byte[])
[+]    Encrypted method found: System.Char FlareOn.Backdoor.FLARE01::flared_01(System.Byte)
[+] Checking class: FlareOn.Backdoor.FLARE02
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE02::flared_02(System.String)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE02::flared_03(System.String)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE02::flared_04(System.String,System.String)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE02::flared_05(System.String)
[+] Checking class: FlareOn.Backdoor.FLARE02/<>c
[+] Checking class: FlareOn.Backdoor.FLARE03
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE03::flared_06()
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE03::flared_07(System.Int32)
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE03::flared_08()
[+]    Encrypted method found: System.Int32 FlareOn.Backdoor.FLARE03::flared_09()
[+]    Encrypted method found: System.Nullable`1<System.Int32> FlareOn.Backdoor.FLARE03::flared_10()
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE03::flared_11()
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE03::flared_12()
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE03::flared_13()
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE03::flared_14()
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE03::flared_15(System.String)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE03::flared_16()
[+] Checking class: FlareOn.Backdoor.FLARE04
[+]    Encrypted method found: System.Byte[] FlareOn.Backdoor.FLARE04::flared_17(System.Byte[])
[+]    Encrypted method found: System.Byte[] FlareOn.Backdoor.FLARE04::flared_18(System.Byte[])
[+] Checking class: FlareOn.Backdoor.FLARE05
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.FLARE05::flared_19()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.FLARE05::flared_20()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.FLARE05::flared_21()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.FLARE05::flared_22()
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_23(FlareOn.Backdoor.FLARE07&)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_24(FlareOn.Backdoor.FLARE07&)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_25(FlareOn.Backdoor.FLARE07&)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_26(FlareOn.Backdoor.FLARE07&)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_27()
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE05::flared_28(System.Byte[])
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE05::flared_29(FlareOn.Backdoor.FLARE06/DomT,System.String)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_30(System.Byte[]&)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_31(System.Func`1<System.Boolean>)
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_32(System.Byte[])
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_33(System.Byte[])
[+]    Encrypted method found: System.Boolean FlareOn.Backdoor.FLARE05::flared_34(System.Int32)
[+] Checking class: FlareOn.Backdoor.FLARE05/<>c__DisplayClass0_0
[+] Checking class: FlareOn.Backdoor.FLARE05/<>c__DisplayClass2_0
[+] Checking class: FlareOn.Backdoor.FLARE05/<>c__DisplayClass4_0
[+] Checking class: FlareOn.Backdoor.FLARE05/<>c__DisplayClass6_0
[+] Checking class: FlareOn.Backdoor.FLARE06
[+] Checking class: FlareOn.Backdoor.FLARE06/DomT
[+] Checking class: FlareOn.Backdoor.FLARE06/DT
[+] Checking class: FlareOn.Backdoor.FLARE06/TT
[+] Checking class: FlareOn.Backdoor.FLARE06/SR
[+] Checking class: FlareOn.Backdoor.FLARE06/OT
[+] Checking class: FlareOn.Backdoor.FLARE07
[+] Checking class: FlareOn.Backdoor.FLARE08
[+] Checking class: FlareOn.Backdoor.FLARE09
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE09::flared_35(System.String)
[+]    Encrypted method found: FlareOn.Backdoor.FLARE09 FlareOn.Backdoor.FLARE09::flared_36()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE09 FlareOn.Backdoor.FLARE09::flared_37()
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_DOS_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_DATA_DIRECTORY
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_OPTIONAL_HEADER32
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_OPTIONAL_HEADER64
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_FILE_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09/IMAGE_SECTION_HEADER
[+] Checking class: FlareOn.Backdoor.FLARE09/DataSectionFlags
[+] Checking class: FlareOn.Backdoor.Program
[+]    Encrypted method found: System.Void FlareOn.Backdoor.Program::flared_38(System.String[])
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.Program::flared_39()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.Program::flared_40()
[+] Checking class: FlareOn.Backdoor.Program/<>c
[+] Checking class: FlareOn.Backdoor.FLARE10
[+]    Encrypted method found: System.Int32 FlareOn.Backdoor.FLARE10::flared_41(System.Int32,System.Int32)
[+] Checking class: FlareOn.Backdoor.FLARE11
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE11::flared_42(System.UInt32)
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE11::flared_43()
[+]    Encrypted method found: System.UInt32 FlareOn.Backdoor.FLARE11::flared_44()
[+]    Encrypted method found: System.Int32 FlareOn.Backdoor.FLARE11::flared_45(System.Int32,System.Int32)
[+]    Encrypted method found: System.UInt32 FlareOn.Backdoor.FLARE11::flared_46(System.Int64)
[+] Checking class: FlareOn.Backdoor.FLARE12
[+]    Encrypted method found: System.Byte[] FlareOn.Backdoor.FLARE12::flared_47(System.Byte[],System.Byte[])
[+] Checking class: FlareOn.Backdoor.FLARE13
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE13::flared_48()
[+]    Encrypted method found: FlareOn.Backdoor.FLARE08 FlareOn.Backdoor.FLARE13::flared_49(FlareOn.Backdoor.FLARE07)
[+]    Encrypted method found: FlareOn.Backdoor.FLARE08 FlareOn.Backdoor.FLARE13::flared_50(FlareOn.Backdoor.FLARE07)
[+] Checking class: FlareOn.Backdoor.FLARE13/FLARE16
[+] Checking class: FlareOn.Backdoor.FLARE14
[+]    Encrypted method found: System.UInt32 FlareOn.Backdoor.FLARE14::flared_51(System.String)
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE14::flared_52(System.Object,System.Collections.Specialized.NotifyCollectionChangedEventArgs)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE14::flared_53(System.String)
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE14::flared_54()
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE14::flared_55(System.Int32,System.String)
[+]    Encrypted method found: FlareOn.Backdoor.FLARE07 FlareOn.Backdoor.FLARE14::flared_56()
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE14::flared_57()
[+] Checking class: FlareOn.Backdoor.FLARE14/<>c__DisplayClass14_0
[+] Checking class: FlareOn.Backdoor.FLARE14/<>c__DisplayClass14_1
[+] Checking class: FlareOn.Backdoor.FLARE15
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_58(System.Int32)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_59(System.String,System.String)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_60(System.Int32)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_61(System.Int32)
[+]    Encrypted method found: System.Int32 FlareOn.Backdoor.FLARE15::flared_62(System.Byte[])
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_63(System.Int32,System.String)
[+]    Encrypted method found: System.Byte[] FlareOn.Backdoor.FLARE15::flared_64(System.Byte[])
[+]    Encrypted method found: System.Void FlareOn.Backdoor.FLARE15::flared_65(FlareOn.Backdoor.FLARE06/DT)
[+]    Encrypted method found: System.String FlareOn.Backdoor.FLARE15::flared_66(System.Int32)
[+]    Encrypted method found: System.Object FlareOn.Backdoor.FLARE15::flared_67(System.Byte[],System.Int32,System.Object[])
[+]    Encrypted method found: System.Int32 FlareOn.Backdoor.FLARE15::flared_68(System.Byte[],System.Int32)
[+]    Encrypted method found: System.Byte[] FlareOn.Backdoor.FLARE15::flared_69(System.String)
[+]    Encrypted method found: System.Object FlareOn.Backdoor.FLARE15::flared_70(System.InvalidProgramException,System.Object[])
[+] Checking class: FlareOn.Backdoor.Properties.Resources
[+] Checking class: <PrivateImplementationDetails>
[+] Decrypting method: FLARE09.flared_35()
[+] MetaData Token: 0x06000058 (flared_35) ~> RVA: 0x00003BE0
[+] Patching flared_35 at 0x53X ~> 0xA000067
[+] Patching flared_35 at 0x133X ~> 0xA000068
[+] Patching flared_35 at 0x203X ~> 0x2B000007
[+] Patching flared_35 at 0x253X ~> 0x4000057
[+] Patching flared_35 at 0x313X ~> 0x4000057
[+] Patching flared_35 at 0x363X ~> 0x400007A
[+] Patching flared_35 at 0x433X ~> 0xA000056
[+] Patching flared_35 at 0x503X ~> 0xA000069
[+] Patching flared_35 at 0x573X ~> 0x2B000008
[+] Patching flared_35 at 0x623X ~> 0x4000058
[+] Patching flared_35 at 0x683X ~> 0x2B000009
[+] Patching flared_35 at 0x733X ~> 0x4000059
[+] Patching flared_35 at 0x783X ~> 0x4000058
[+] Patching flared_35 at 0x833X ~> 0x40000D9
[+] Patching flared_35 at 0x883X ~> 0x200001A
[+] Patching flared_35 at 0x933X ~> 0x400005B
[+] Patching flared_35 at 0x1033X ~> 0x400005B
[+] Patching flared_35 at 0x1103X ~> 0x2B00000A
[+] Patching flared_35 at 0x1153X ~> 0x200001A
[+] Patching flared_35 at 0x1263X ~> 0x400005B
[+] Patching flared_35 at 0x1483X ~> 0xA000046
[+] Decrypted Bytecode: 0-2-25-23-115-103-0-0-10-10-0-6-115-104-0-0-10-11-7-40-7-0-0-43-128-87-0-0-4-6-127-87-0-0-4-123-122-0-0-4-110-22-111-86-0-0-10-38-7-111-105-0-0-10-12-7-40-8-0-0-43-128-88-0-0-4-7-40-9-0-0-43-128-89-0-0-4-127-88-0-0-4-123-217-0-0-4-141-26-0-0-2-128-91-0-0-4-22-13-43-23-0-126-91-0-0-4-9-7-40-10-0-0-43-164-26-0-0-2-0-9-23-88-13-9-126-91-0-0-4-142-105-254-4-19-4-17-4-45-217-0-222-11-6-44-7-6-111-70-0-0-10-0-220-42
[+] Overwriting bytecode for flared_35: 152-222-23-12-87-160-182-212-67-100-46-233-194-163-90-227-168-48-50-136-242-116-29-190-28-64-18-148-245-85-43-167-222-163-241-221-249-60-237-15-25-104-93-51-12-250-197-208-180-85-174-108-167-204-186-36-192-88-240-23-142-33-222-238-56-134-10-30-178-124-234-108-66-35-110-138-23-234-178-33-123-65-224-159-166-190-0-17-233-205-28-160-75-214-129-248-137-110-250-133-239-166-30-55-107-66-41-131-94-47-12-214-166-206-155-76-65-62-72-121-134-248-53-229-96-73-32-108-162-118-0-169-239-45-50-212-35-168-52-99-149-124-179-185-192-70-250-125-59-52-182-75-37-128-254
[+] Offset found: 0xABEC
[+] Decrypting method: FLARE12.flared_47()
[+] MetaData Token: 0x0600007F (flared_47) ~> RVA: 0x00004574
[+] Patching flared_47 at 0x73X ~> 0x100003A
[+] Patching flared_47 at 0x193X ~> 0x100003A
[+] Patching flared_47 at 0x293X ~> 0x100002F
[+] Decrypted Bytecode: 0-32-0-1-0-0-141-58-0-0-1-19-5-32-0-1-0-0-141-58-0-0-1-19-6-3-142-105-141-47-0-0-1-19-7-22-11-43-22-0-17-5-7-2-7-2-142-105-93-145-158-17-6-7-7-158-0-7-23-88-11-7-32-0-1-0-0-254-4-19-8-17-8-45-220-22-37-11-12-43-44-0-8-17-6-7-148-88-17-5-7-148-88-32-0-1-0-0-93-12-17-6-7-148-19-4-17-6-7-17-6-8-148-158-17-6-8-17-4-158-0-7-23-88-11-7-32-0-1-0-0-254-4-19-9-17-9-45-198-22-37-11-37-12-10-43-82-0-6-23-88-10-6-32-0-1-0-0-93-10-8-17-6-6-148-88-12-8-32-0-1-0-0-93-12-17-6-6-148-19-4-17-6-6-17-6-8-148-158-17-6-8-17-4-158-17-6-17-6-6-148-17-6-8-148-88-32-0-1-0-0-93-148-13-17-7-7-3-7-145-9-97-210-156-0-7-23-88-11-7-3-142-105-254-4-19-10-17-10-45-162-17-7-19-11-43-0-17-11-42
[+] Overwriting bytecode for flared_47: 227-34-20-65-218-62-67-179-101-117-108-230-95-38-181-151-194-232-195-207-121-104-95-36-21-125-68-156-112-116-148-253-232-7-249-104-9-193-111-107-52-156-214-159-233-143-233-38-99-186-199-216-220-6-4-123-194-239-43-93-249-167-67-241-225-111-253-88-45-76-141-0-120-87-154-220-146-191-58-134-148-29-56-181-172-187-33-225-2-126-165-25-149-18-114-141-89-228-190-122-146-145-249-22-44-198-96-132-107-40-232-2-180-165-201-220-111-141-68-38-78-27-85-174-167-116-106-102-229-13-130-173-1-191-243-3-35-33-137-229-91-156-117-218-149-163-101-240-73-149-30-204-159-152-44-118-59-75-111-184-92-249-159-94-165-59-1-244-177-197-184-77-4-94-202-178-165-123-25-3-14-122-29-79-239-182-13-104-147-125-199-216-177-208-137-97-252-23-52-90-161-112-62-131-221-208-200-65-205-122-208-191-49-107-169-225-220-80-110-238-45-153-97-52-253-223-156-51-212-105-181-142-70-191-98-158-59-153-113-31-237-204-154-25-172-8-167-69-38-168
[+] Offset found: 0xB580
[+] Decrypting method: FLARE15.flared_66()
[+] MetaData Token: 0x060000B2 (flared_66) ~> RVA: 0x00012B84
[+] Patching flared_66 at 0x23X ~> 0x200001C
[+] Patching flared_66 at 0x73X ~> 0xA00006C
[+] Patching flared_66 at 0x123X ~> 0xA0000B3
[+] Patching flared_66 at 0x223X ~> 0x70000011
[+] Patching flared_66 at 0x283X ~> 0x70000011
[+] Patching flared_66 at 0x373X ~> 0xA0000B4
[+] Patching flared_66 at 0x423X ~> 0x100006C
[+] Patching flared_66 at 0x493X ~> 0xA0000B5
[+] Patching flared_66 at 0x553X ~> 0xA0000A5
[+] Patching flared_66 at 0x613X ~> 0xA0000B6
[+] Patching flared_66 at 0x713X ~> 0x100006F
[+] Patching flared_66 at 0x763X ~> 0xA000044
[+] Patching flared_66 at 0x813X ~> 0xA00009D
[+] Patching flared_66 at 0x883X ~> 0xA0000A5
[+] Patching flared_66 at 0x943X ~> 0xA0000B7
[+] Patching flared_66 at 0x993X ~> 0xA000044
[+] Patching flared_66 at 0x1043X ~> 0xA00009D
[+] Patching flared_66 at 0x1113X ~> 0xA0000A5
[+] Patching flared_66 at 0x1173X ~> 0xA0000B8
[+] Patching flared_66 at 0x1273X ~> 0x1000070
[+] Patching flared_66 at 0x1323X ~> 0xA000044
[+] Patching flared_66 at 0x1373X ~> 0xA00009D
[+] Patching flared_66 at 0x1463X ~> 0xA0000B9
[+] Patching flared_66 at 0x1703X ~> 0xA0000BA
[+] Patching flared_66 at 0x1823X ~> 0xA000044
[+] Patching flared_66 at 0x1873X ~> 0xA000028
[+] Patching flared_66 at 0x2093X ~> 0xA0000A5
[+] Patching flared_66 at 0x2153X ~> 0xA0000BB
[+] Patching flared_66 at 0x2243X ~> 0xA00003B
[+] Patching flared_66 at 0x2293X ~> 0xA00009D
[+] Patching flared_66 at 0x2373X ~> 0xA0000BC
[+] Patching flared_66 at 0x2443X ~> 0xA0000BD
[+] Patching flared_66 at 0x2533X ~> 0xA0000BE
[+] Patching flared_66 at 0x2583X ~> 0xA0000BF
[+] Patching flared_66 at 0x2693X ~> 0xA0000C0
[+] Patching flared_66 at 0x2803X ~> 0xA0000C1
[+] Patching flared_66 at 0x2923X ~> 0xA000044
[+] Patching flared_66 at 0x2973X ~> 0xA000028
[+] Patching flared_66 at 0x3063X ~> 0xA0000C2
[+] Patching flared_66 at 0x3213X ~> 0xA000046
[+] Patching flared_66 at 0x3283X ~> 0xA0000A5
[+] Patching flared_66 at 0x3343X ~> 0xA00009D
[+] Patching flared_66 at 0x3413X ~> 0xA0000A5
[+] Patching flared_66 at 0x3483X ~> 0xA00009D
[+] Patching flared_66 at 0x3553X ~> 0xA000081
[+] Patching flared_66 at 0x3603X ~> 0xA000082
[+] Patching flared_66 at 0x3713X ~> 0xA0000A6
[+] Patching flared_66 at 0x3813X ~> 0xA0000A6
[+] Patching flared_66 at 0x3913X ~> 0xA0000A6
[+] Patching flared_66 at 0x4013X ~> 0xA0000A6
[+] Patching flared_66 at 0x4113X ~> 0xA0000A6
[+] Patching flared_66 at 0x4213X ~> 0xA0000A6
[+] Patching flared_66 at 0x4313X ~> 0xA0000A6
[+] Patching flared_66 at 0x4393X ~> 0xA00008F
[+] Patching flared_66 at 0x4523X ~> 0xA0000C3
[+] Patching flared_66 at 0x4703X ~> 0x100002F
[+] Patching flared_66 at 0x4753X ~> 0x70003050
[+] Patching flared_66 at 0x4803X ~> 0xA0000C4
[+] Patching flared_66 at 0x4853X ~> 0xA0000C5
[+] Patching flared_66 at 0x5133X ~> 0xA000044
[+] Decrypted Bytecode: 0-208-28-0-0-2-40-108-0-0-10-111-179-0-0-10-10-20-11-20-12-114-17-0-0-112-13-114-17-0-0-112-19-4-6-2-111-180-0-0-10-116-108-0-0-1-11-7-111-181-0-0-10-12-40-165-0-0-10-7-111-182-0-0-10-19-15-18-15-254-22-111-0-0-1-111-68-0-0-10-111-157-0-0-10-19-5-40-165-0-0-10-7-111-183-0-0-10-111-68-0-0-10-111-157-0-0-10-19-6-40-165-0-0-10-7-111-184-0-0-10-19-16-18-16-254-22-112-0-0-1-111-68-0-0-10-111-157-0-0-10-19-7-0-7-111-185-0-0-10-19-17-22-19-18-43-43-17-17-17-18-154-19-19-0-17-4-17-19-111-186-0-0-10-37-45-4-38-20-43-5-111-68-0-0-10-40-40-0-0-10-19-4-0-17-18-23-88-19-18-17-18-17-17-142-105-50-205-40-165-0-0-10-8-111-187-0-0-10-19-20-18-20-40-59-0-0-10-111-157-0-0-10-19-8-8-111-188-0-0-10-142-105-40-189-0-0-10-19-9-0-8-111-190-0-0-10-111-191-0-0-10-19-21-43-37-17-21-111-192-0-0-10-19-22-0-9-17-22-111-193-0-0-10-37-45-4-38-20-43-5-111-68-0-0-10-40-40-0-0-10-13-0-17-21-111-194-0-0-10-45-210-222-13-17-21-44-8-17-21-111-70-0-0-10-0-220-40-165-0-0-10-9-111-157-0-0-10-19-10-40-165-0-0-10-17-4-111-157-0-0-10-19-11-40-129-0-0-10-40-130-0-0-10-19-12-17-12-17-9-111-166-0-0-10-0-17-12-17-5-111-166-0-0-10-0-17-12-17-6-111-166-0-0-10-0-17-12-17-8-111-166-0-0-10-0-17-12-17-10-111-166-0-0-10-0-17-12-17-11-111-166-0-0-10-0-17-12-17-7-111-166-0-0-10-0-17-12-111-143-0-0-10-19-13-17-13-142-105-24-90-115-195-0-0-10-19-14-22-19-23-43-33-17-14-17-13-17-23-143-47-0-0-1-114-80-48-0-112-40-196-0-0-10-111-197-0-0-10-38-17-23-23-88-19-23-17-23-17-13-142-105-254-4-19-24-17-24-45-209-17-14-111-68-0-0-10-19-25-43-0-17-25-42
[+] Overwriting bytecode for flared_66: 2-76-214-62-246-215-46-216-130-154-72-14-127-197-199-2-67-55-30-47-185-250-160-174-202-241-34-28-76-12-101-120-131-40-210-46-160-148-158-77-37-212-233-32-244-175-113-180-175-88-162-192-142-25-254-8-172-40-115-5-180-18-140-118-52-207-139-87-243-153-97-174-153-208-9-229-17-127-186-26-128-110-108-244-105-165-234-105-41-201-129-120-32-152-153-19-72-114-236-36-36-25-192-22-246-244-39-190-15-25-246-44-110-89-133-70-165-151-12-142-229-33-45-41-23-233-141-0-55-246-156-158-147-149-245-102-173-86-254-117-126-44-89-15-211-85-10-199-19-82-109-177-101-93-63-3-236-151-255-13-102-39-134-25-125-87-152-216-100-31-152-79-153-151-16-185-200-29-86-194-223-198-236-228-137-235-57-54-86-241-122-22-87-240-15-86-165-64-146-123-188-49-98-244-185-30-23-206-76-133-58-206-64-61-45-159-58-162-144-146-30-98-130-114-164-130-247-168-136-186-20-136-139-219-5-173-99-248-0-106-211-106-233-208-183-172-213-26-194-111-28-3-175-0-92-89-175-240-79-55-38-110-70-146-113-178-66-101-55-128-60-65-119-37-190-180-120-177-187-248-172-221-229-25-157-16-216-139-126-172-254-115-169-243-67-100-36-87-95-4-105-112-226-66-51-219-139-138-65-168-224-253-52-86-138-73-137-44-245-96-218-183-230-139-130-200-151-132-226-89-143-33-82-183-143-60-251-163-230-194-133-77-73-214-203-0-63-83-104-250-219-247-98-254-41-177-137-87-192-106-67-7-168-231-25-191-171-125-198-77-78-230-70-50-219-140-109-16-192-129-136-68-27-231-126-152-191-83-141-221-178-163-226-123-126-125-165-98-189-11-85-193-140-27-172-245-176-47-34-157-67-121-151-62-226-255-235-192-104-128-0-87-240-232-154-170-3-203-180-93-230-11-83-180-44-198-183-0-59-137-231-143-48-240-154-57-12-164-153-126-145-228-249-60-11-253-209-163-128-2-242-228-122-196-182-56-37-226-18-27-72-235-133-223-153-112-38-255-78-97-157-95-50-53-204-1-18-23-169-46-244-19-128-56-150-2-20-108-57-98-20-0-145-125-54-166-95-25-162-154-214-210-85-31-100-147-178-69-248-180-37-13-57-227
[+] Offset found: 0x19B90
[+] Decrypting method: FLARE15.flared_67()
[+] MetaData Token: 0x060000B4 (flared_67) ~> RVA: 0x00012E00
[+] Patching flared_67 at 0x23X ~> 0xA0000C6
[+] Patching flared_67 at 0x113X ~> 0xA0000C7
[+] Patching flared_67 at 0x243X ~> 0xA0000C7
[+] Patching flared_67 at 0x373X ~> 0xA0000C7
[+] Patching flared_67 at 0x473X ~> 0xA0000C7
[+] Patching flared_67 at 0x603X ~> 0xA0000C7
[+] Patching flared_67 at 0x703X ~> 0xA0000C7
[+] Patching flared_67 at 0x803X ~> 0xA0000C7
[+] Patching flared_67 at 0x903X ~> 0xA0000C7
[+] Patching flared_67 at 0x1003X ~> 0xA0000C7
[+] Patching flared_67 at 0x1103X ~> 0xA0000C7
[+] Patching flared_67 at 0x1203X ~> 0xA0000C7
[+] Patching flared_67 at 0x1303X ~> 0xA0000C7
[+] Patching flared_67 at 0x1403X ~> 0xA0000C7
[+] Patching flared_67 at 0x1503X ~> 0xA0000C7
[+] Patching flared_67 at 0x1603X ~> 0xA0000C7
[+] Patching flared_67 at 0x1703X ~> 0xA0000C7
[+] Patching flared_67 at 0x1803X ~> 0xA0000C7
[+] Patching flared_67 at 0x1903X ~> 0xA0000C7
[+] Patching flared_67 at 0x2003X ~> 0xA0000C7
[+] Patching flared_67 at 0x2103X ~> 0xA0000C7
[+] Patching flared_67 at 0x2203X ~> 0xA0000C7
[+] Patching flared_67 at 0x2303X ~> 0xA0000C7
[+] Patching flared_67 at 0x2403X ~> 0xA0000C7
[+] Patching flared_67 at 0x2503X ~> 0xA0000C7
[+] Patching flared_67 at 0x2603X ~> 0xA0000C7
[+] Patching flared_67 at 0x2733X ~> 0xA0000C7
[+] Patching flared_67 at 0x2833X ~> 0xA0000C7
[+] Patching flared_67 at 0x2933X ~> 0xA0000C7
[+] Patching flared_67 at 0x3023X ~> 0xA0000C7
[+] Patching flared_67 at 0x3123X ~> 0xA0000C7
[+] Patching flared_67 at 0x3223X ~> 0xA0000C7
[+] Patching flared_67 at 0x3323X ~> 0xA0000C7
[+] Patching flared_67 at 0x3423X ~> 0xA0000C7
[+] Patching flared_67 at 0x3523X ~> 0xA0000C7
[+] Patching flared_67 at 0x3623X ~> 0xA0000C7
[+] Patching flared_67 at 0x3723X ~> 0xA0000C7
[+] Patching flared_67 at 0x3823X ~> 0xA0000C7
[+] Patching flared_67 at 0x3953X ~> 0xA0000C7
[+] Patching flared_67 at 0x4083X ~> 0xA0000C7
[+] Patching flared_67 at 0x4213X ~> 0xA0000C7
[+] Patching flared_67 at 0x4343X ~> 0xA0000C7
[+] Patching flared_67 at 0x4473X ~> 0xA0000C7
[+] Patching flared_67 at 0x4603X ~> 0xA0000C7
[+] Patching flared_67 at 0x4733X ~> 0xA0000C7
[+] Patching flared_67 at 0x4863X ~> 0xA0000C7
[+] Patching flared_67 at 0x4963X ~> 0xA0000C7
[+] Patching flared_67 at 0x5063X ~> 0xA0000C7
[+] Patching flared_67 at 0x5163X ~> 0xA0000C7
[+] Patching flared_67 at 0x5263X ~> 0xA0000C7
[+] Patching flared_67 at 0x5393X ~> 0xA0000C7
[+] Patching flared_67 at 0x5523X ~> 0xA0000C7
[+] Patching flared_67 at 0x5653X ~> 0xA0000C7
[+] Patching flared_67 at 0x5783X ~> 0xA0000C7
[+] Patching flared_67 at 0x5913X ~> 0xA0000C7
[+] Patching flared_67 at 0x6043X ~> 0xA0000C7
[+] Patching flared_67 at 0x6173X ~> 0xA0000C7
[+] Patching flared_67 at 0x6303X ~> 0xA0000C7
[+] Patching flared_67 at 0x6433X ~> 0xA0000C7
[+] Patching flared_67 at 0x6563X ~> 0xA0000C7
[+] Patching flared_67 at 0x6693X ~> 0xA0000C7
[+] Patching flared_67 at 0x6823X ~> 0xA0000C7
[+] Patching flared_67 at 0x6953X ~> 0xA0000C7
[+] Patching flared_67 at 0x7083X ~> 0xA0000C7
[+] Patching flared_67 at 0x7213X ~> 0xA0000C7
[+] Patching flared_67 at 0x7343X ~> 0xA0000C7
[+] Patching flared_67 at 0x7473X ~> 0xA0000C7
[+] Patching flared_67 at 0x7603X ~> 0xA0000C7
[+] Patching flared_67 at 0x7733X ~> 0xA0000C7
[+] Patching flared_67 at 0x7863X ~> 0xA0000C7
[+] Patching flared_67 at 0x7963X ~> 0xA0000C7
[+] Patching flared_67 at 0x8063X ~> 0xA0000C7
[+] Patching flared_67 at 0x8163X ~> 0xA0000C7
[+] Patching flared_67 at 0x8293X ~> 0xA0000C7
[+] Patching flared_67 at 0x8423X ~> 0xA0000C7
[+] Patching flared_67 at 0x8553X ~> 0xA0000C7
[+] Patching flared_67 at 0x8653X ~> 0xA0000C7
[+] Patching flared_67 at 0x8753X ~> 0xA0000C7
[+] Patching flared_67 at 0x8883X ~> 0xA0000C7
[+] Patching flared_67 at 0x8983X ~> 0xA0000C7
[+] Patching flared_67 at 0x9083X ~> 0xA0000C7
[+] Patching flared_67 at 0x9183X ~> 0xA0000C7
[+] Patching flared_67 at 0x9283X ~> 0xA0000C7
[+] Patching flared_67 at 0x9413X ~> 0xA0000C7
[+] Patching flared_67 at 0x9543X ~> 0xA0000C7
[+] Patching flared_67 at 0x9673X ~> 0xA0000C7
[+] Patching flared_67 at 0x9803X ~> 0xA0000C7
[+] Patching flared_67 at 0x9903X ~> 0xA0000C7
[+] Patching flared_67 at 0x10003X ~> 0xA0000C7
[+] Patching flared_67 at 0x10133X ~> 0xA0000C7
[+] Patching flared_67 at 0x10223X ~> 0xA0000C7
[+] Patching flared_67 at 0x10313X ~> 0xA0000C7
[+] Patching flared_67 at 0x10403X ~> 0xA0000C7
[+] Patching flared_67 at 0x10493X ~> 0xA0000C7
[+] Patching flared_67 at 0x10593X ~> 0xA0000C7
[+] Patching flared_67 at 0x10723X ~> 0xA0000C7
[+] Patching flared_67 at 0x10823X ~> 0xA0000C7
[+] Patching flared_67 at 0x10923X ~> 0xA0000C7
[+] Patching flared_67 at 0x11023X ~> 0xA0000C7
[+] Patching flared_67 at 0x11123X ~> 0xA0000C7
[+] Patching flared_67 at 0x11223X ~> 0xA0000C7
[+] Patching flared_67 at 0x11323X ~> 0xA0000C7
[+] Patching flared_67 at 0x11423X ~> 0xA0000C7
[+] Patching flared_67 at 0x11523X ~> 0xA0000C7
[+] Patching flared_67 at 0x11623X ~> 0xA0000C7
[+] Patching flared_67 at 0x11723X ~> 0xA0000C7
[+] Patching flared_67 at 0x11823X ~> 0xA0000C7
[+] Patching flared_67 at 0x11923X ~> 0xA0000C7
[+] Patching flared_67 at 0x12023X ~> 0xA0000C7
[+] Patching flared_67 at 0x12123X ~> 0xA0000C7
[+] Patching flared_67 at 0x12223X ~> 0xA0000C7
[+] Patching flared_67 at 0x12323X ~> 0xA0000C7
[+] Patching flared_67 at 0x12453X ~> 0xA0000C7
[+] Patching flared_67 at 0x12583X ~> 0xA0000C7
[+] Patching flared_67 at 0x12713X ~> 0xA0000C7
[+] Patching flared_67 at 0x12843X ~> 0xA0000C7
[+] Patching flared_67 at 0x12973X ~> 0xA0000C7
[+] Patching flared_67 at 0x13103X ~> 0xA0000C7
[+] Patching flared_67 at 0x13233X ~> 0xA0000C7
[+] Patching flared_67 at 0x13363X ~> 0xA0000C7
[+] Patching flared_67 at 0x13493X ~> 0xA0000C7
[+] Patching flared_67 at 0x13623X ~> 0xA0000C7
[+] Patching flared_67 at 0x13753X ~> 0xA0000C7
[+] Patching flared_67 at 0x13883X ~> 0xA0000C7
[+] Patching flared_67 at 0x14013X ~> 0xA0000C7
[+] Patching flared_67 at 0x14113X ~> 0xA0000C7
[+] Patching flared_67 at 0x14213X ~> 0xA0000C7
[+] Patching flared_67 at 0x14343X ~> 0xA0000C7
[+] Patching flared_67 at 0x14443X ~> 0xA0000C7
[+] Patching flared_67 at 0x14543X ~> 0xA0000C7
[+] Patching flared_67 at 0x14643X ~> 0xA0000C7
[+] Patching flared_67 at 0x14743X ~> 0xA0000C7
[+] Patching flared_67 at 0x14843X ~> 0xA0000C7
[+] Patching flared_67 at 0x14943X ~> 0xA0000C7
[+] Patching flared_67 at 0x15043X ~> 0xA0000C7
[+] Patching flared_67 at 0x15143X ~> 0xA0000C7
[+] Patching flared_67 at 0x15243X ~> 0xA0000C7
[+] Patching flared_67 at 0x15343X ~> 0xA0000C7
[+] Patching flared_67 at 0x15443X ~> 0xA0000C7
[+] Patching flared_67 at 0x15573X ~> 0xA0000C7
[+] Patching flared_67 at 0x15703X ~> 0xA0000C7
[+] Patching flared_67 at 0x15793X ~> 0xA0000C7
[+] Patching flared_67 at 0x15883X ~> 0xA0000C7
[+] Patching flared_67 at 0x15973X ~> 0xA0000C7
[+] Patching flared_67 at 0x16073X ~> 0xA0000C7
[+] Patching flared_67 at 0x16173X ~> 0xA0000C7
[+] Patching flared_67 at 0x16303X ~> 0xA0000C7
[+] Patching flared_67 at 0x16403X ~> 0xA0000C7
[+] Patching flared_67 at 0x16503X ~> 0xA0000C7
[+] Patching flared_67 at 0x16603X ~> 0xA0000C7
[+] Patching flared_67 at 0x16703X ~> 0xA0000C7
[+] Patching flared_67 at 0x16803X ~> 0xA0000C7
[+] Patching flared_67 at 0x16903X ~> 0xA0000C7
[+] Patching flared_67 at 0x17033X ~> 0xA0000C7
[+] Patching flared_67 at 0x17163X ~> 0xA0000C7
[+] Patching flared_67 at 0x17293X ~> 0xA0000C7
[+] Patching flared_67 at 0x17423X ~> 0xA0000C7
[+] Patching flared_67 at 0x17553X ~> 0xA0000C7
[+] Patching flared_67 at 0x17683X ~> 0xA0000C7
[+] Patching flared_67 at 0x17783X ~> 0xA0000C7
[+] Patching flared_67 at 0x17913X ~> 0xA0000C7
[+] Patching flared_67 at 0x18043X ~> 0xA0000C7
[+] Patching flared_67 at 0x18143X ~> 0xA0000C7
[+] Patching flared_67 at 0x18273X ~> 0xA0000C7
[+] Patching flared_67 at 0x18373X ~> 0xA0000C7
[+] Patching flared_67 at 0x18503X ~> 0xA0000C7
[+] Patching flared_67 at 0x18593X ~> 0xA0000C7
[+] Patching flared_67 at 0x18693X ~> 0xA0000C7
[+] Patching flared_67 at 0x18793X ~> 0xA0000C7
[+] Patching flared_67 at 0x18893X ~> 0xA0000C7
[+] Patching flared_67 at 0x19023X ~> 0xA0000C7
[+] Patching flared_67 at 0x19153X ~> 0xA0000C7
[+] Patching flared_67 at 0x19283X ~> 0xA0000C7
[+] Patching flared_67 at 0x19413X ~> 0xA0000C7
[+] Patching flared_67 at 0x19543X ~> 0xA0000C7
[+] Patching flared_67 at 0x19673X ~> 0xA0000C7
[+] Patching flared_67 at 0x19803X ~> 0xA0000C7
[+] Patching flared_67 at 0x19933X ~> 0xA0000C7
[+] Patching flared_67 at 0x20063X ~> 0xA0000C7
[+] Patching flared_67 at 0x20193X ~> 0xA0000C7
[+] Patching flared_67 at 0x20323X ~> 0xA0000C7
[+] Patching flared_67 at 0x20423X ~> 0xA0000C7
[+] Patching flared_67 at 0x20523X ~> 0xA0000C7
[+] Patching flared_67 at 0x20623X ~> 0xA0000C7
[+] Patching flared_67 at 0x20753X ~> 0xA0000C7
[+] Patching flared_67 at 0x20853X ~> 0xA0000C7
[+] Patching flared_67 at 0x20953X ~> 0xA0000C7
[+] Patching flared_67 at 0x21053X ~> 0xA0000C7
[+] Patching flared_67 at 0x21183X ~> 0xA0000C7
[+] Patching flared_67 at 0x21313X ~> 0xA0000C7
[+] Patching flared_67 at 0x21413X ~> 0xA0000C7
[+] Patching flared_67 at 0x21543X ~> 0xA0000C7
[+] Patching flared_67 at 0x21673X ~> 0xA0000C7
[+] Patching flared_67 at 0x21803X ~> 0xA0000C7
[+] Patching flared_67 at 0x21933X ~> 0xA0000C7
[+] Patching flared_67 at 0x22063X ~> 0xA0000C7
[+] Patching flared_67 at 0x22193X ~> 0xA0000C7
[+] Patching flared_67 at 0x22323X ~> 0xA0000C7
[+] Patching flared_67 at 0x22453X ~> 0xA0000C7
[+] Patching flared_67 at 0x22583X ~> 0xA0000C7
[+] Patching flared_67 at 0x22683X ~> 0xA0000C7
[+] Patching flared_67 at 0x22813X ~> 0xA0000C7
[+] Patching flared_67 at 0x22913X ~> 0xA0000C7
[+] Patching flared_67 at 0x23013X ~> 0xA0000C7
[+] Patching flared_67 at 0x23113X ~> 0xA0000C7
[+] Patching flared_67 at 0x23213X ~> 0xA0000C7
[+] Patching flared_67 at 0x23313X ~> 0xA0000C7
[+] Patching flared_67 at 0x23413X ~> 0xA0000C7
[+] Patching flared_67 at 0x23513X ~> 0xA0000C7
[+] Patching flared_67 at 0x23643X ~> 0xA0000C7
[+] Patching flared_67 at 0x23743X ~> 0xA0000C7
[+] Patching flared_67 at 0x23843X ~> 0xA0000C7
[+] Patching flared_67 at 0x23943X ~> 0xA0000C7
[+] Patching flared_67 at 0x24043X ~> 0xA0000C7
[+] Patching flared_67 at 0x24143X ~> 0xA0000C7
[+] Patching flared_67 at 0x24273X ~> 0xA0000C7
[+] Patching flared_67 at 0x24403X ~> 0xA0000C7
[+] Patching flared_67 at 0x24503X ~> 0xA0000C7
[+] Patching flared_67 at 0x24633X ~> 0xA0000C7
[+] Patching flared_67 at 0x24763X ~> 0xA0000C7
[+] Patching flared_67 at 0x24863X ~> 0xA0000C7
[+] Patching flared_67 at 0x24993X ~> 0xA0000C7
[+] Patching flared_67 at 0x25093X ~> 0xA0000C7
[+] Patching flared_67 at 0x25223X ~> 0xA0000C7
[+] Patching flared_67 at 0x25323X ~> 0xA0000C7
[+] Patching flared_67 at 0x25453X ~> 0xA0000C7
[+] Patching flared_67 at 0x25583X ~> 0xA0000C7
[+] Patching flared_67 at 0x25683X ~> 0xA0000C7
[+] Patching flared_67 at 0x25813X ~> 0x200001C
[+] Patching flared_67 at 0x25863X ~> 0xA00006C
[+] Patching flared_67 at 0x25913X ~> 0xA0000B3
[+] Patching flared_67 at 0x26013X ~> 0xA0000B4
[+] Patching flared_67 at 0x26103X ~> 0x100006C
[+] Patching flared_67 at 0x26193X ~> 0xA0000B9
[+] Patching flared_67 at 0x26303X ~> 0x1000052
[+] Patching flared_67 at 0x26373X ~> 0xA0000C8
[+] Patching flared_67 at 0x26593X ~> 0xA0000BA
[+] Patching flared_67 at 0x26883X ~> 0xA0000C9
[+] Patching flared_67 at 0x26953X ~> 0x70000011
[+] Patching flared_67 at 0x27023X ~> 0xA0000B7
[+] Patching flared_67 at 0x27123X ~> 0xA0000CA
[+] Patching flared_67 at 0x27213X ~> 0xA0000CB
[+] Patching flared_67 at 0x27303X ~> 0xA0000B5
[+] Patching flared_67 at 0x27403X ~> 0xA0000BE
[+] Patching flared_67 at 0x27453X ~> 0xA0000BF
[+] Patching flared_67 at 0x27563X ~> 0xA0000C0
[+] Patching flared_67 at 0x27683X ~> 0xA0000C1
[+] Patching flared_67 at 0x27733X ~> 0xA0000CC
[+] Patching flared_67 at 0x27823X ~> 0xA0000C2
[+] Patching flared_67 at 0x27973X ~> 0xA000046
[+] Patching flared_67 at 0x28063X ~> 0xA0000CD
[+] Patching flared_67 at 0x28173X ~> 0xA0000CE
[+] Patching flared_67 at 0x28813X ~> 0xA0000CF
[+] Patching flared_67 at 0x29943X ~> 0x60000B7
[+] Patching flared_67 at 0x30133X ~> 0x60000B7
[+] Patching flared_67 at 0x30583X ~> 0xA0000D0
[+] Patching flared_67 at 0x30633X ~> 0xA0000D1
[+] Patching flared_67 at 0x30783X ~> 0xA0000C9
[+] Patching flared_67 at 0x30933X ~> 0xA0000D2
[+] Patching flared_67 at 0x31023X ~> 0xA0000D3
[+] Patching flared_67 at 0x31183X ~> 0xA0000D4
[+] Patching flared_67 at 0x31273X ~> 0xA0000D5
[+] Patching flared_67 at 0x31363X ~> 0xA0000D6
[+] Patching flared_67 at 0x31523X ~> 0xA0000D7
[+] Patching flared_67 at 0x31613X ~> 0xA0000B3
[+] Patching flared_67 at 0x31713X ~> 0xA0000D8
[+] Patching flared_67 at 0x31803X ~> 0xA0000D9
[+] Patching flared_67 at 0x31853X ~> 0xA0000DA
[+] Patching flared_67 at 0x31903X ~> 0x70003056
[+] Patching flared_67 at 0x31953X ~> 0xA00004A
[+] Patching flared_67 at 0x32113X ~> 0x100007A
[+] Patching flared_67 at 0x32163X ~> 0xA0000DB
[+] Patching flared_67 at 0x32233X ~> 0x100007A
[+] Patching flared_67 at 0x32283X ~> 0xA0000C9
[+] Patching flared_67 at 0x32333X ~> 0x100007B
[+] Patching flared_67 at 0x32383X ~> 0xA0000DC
[+] Patching flared_67 at 0x32433X ~> 0xA0000DD
[+] Patching flared_67 at 0x32573X ~> 0xA0000D9
[+] Patching flared_67 at 0x32623X ~> 0xA0000DA
[+] Patching flared_67 at 0x32673X ~> 0x7000306E
[+] Patching flared_67 at 0x32723X ~> 0xA00004A
[+] Patching flared_67 at 0x32883X ~> 0x100007B
[+] Patching flared_67 at 0x32933X ~> 0xA0000DC
[+] Patching flared_67 at 0x32983X ~> 0xA0000DE
[+] Patching flared_67 at 0x33123X ~> 0xA0000DA
[+] Patching flared_67 at 0x33173X ~> 0x70003086
[+] Patching flared_67 at 0x33223X ~> 0xA00004A
[+] Patching flared_67 at 0x33313X ~> 0xA0000DA
[+] Patching flared_67 at 0x33363X ~> 0x70003092
[+] Patching flared_67 at 0x33413X ~> 0xA00004A
[+] Patching flared_67 at 0x33603X ~> 0x100007C
[+] Patching flared_67 at 0x33653X ~> 0xA0000DF
[+] Patching flared_67 at 0x33723X ~> 0x100007C
[+] Patching flared_67 at 0x33773X ~> 0xA0000C9
[+] Patching flared_67 at 0x33823X ~> 0x100007B
[+] Patching flared_67 at 0x33873X ~> 0xA0000DC
[+] Patching flared_67 at 0x33923X ~> 0xA0000E0
[+] Patching flared_67 at 0x34063X ~> 0x100006C
[+] Patching flared_67 at 0x34113X ~> 0xA0000DF
[+] Patching flared_67 at 0x34183X ~> 0x100006C
[+] Patching flared_67 at 0x34233X ~> 0xA0000C9
[+] Patching flared_67 at 0x34283X ~> 0x100007B
[+] Patching flared_67 at 0x34333X ~> 0xA0000DC
[+] Patching flared_67 at 0x34383X ~> 0xA0000E0
[+] Patching flared_67 at 0x35223X ~> 0xA0000BB
[+] Patching flared_67 at 0x35273X ~> 0xA0000E1
[+] Patching flared_67 at 0x35373X ~> 0xA0000E2
[+] Decrypted Bytecode: 0-115-198-0-0-10-37-31-88-22-111-199-0-0-10-0-37-32-214-0-0-0-22-111-199-0-0-10-0-37-32-215-0-0-0-22-111-199-0-0-10-0-37-31-95-22-111-199-0-0-10-0-37-32-0-254-0-0-22-111-199-0-0-10-0-37-31-59-25-111-199-0-0-10-0-37-31-46-24-111-199-0-0-10-0-37-31-60-25-111-199-0-0-10-0-37-31-47-24-111-199-0-0-10-0-37-31-65-25-111-199-0-0-10-0-37-31-52-24-111-199-0-0-10-0-37-31-61-25-111-199-0-0-10-0-37-31-48-24-111-199-0-0-10-0-37-31-66-25-111-199-0-0-10-0-37-31-53-24-111-199-0-0-10-0-37-31-62-25-111-199-0-0-10-0-37-31-49-24-111-199-0-0-10-0-37-31-67-25-111-199-0-0-10-0-37-31-54-24-111-199-0-0-10-0-37-31-63-25-111-199-0-0-10-0-37-31-50-24-111-199-0-0-10-0-37-31-68-25-111-199-0-0-10-0-37-31-55-24-111-199-0-0-10-0-37-31-64-25-111-199-0-0-10-0-37-31-51-24-111-199-0-0-10-0-37-32-140-0-0-0-23-111-199-0-0-10-0-37-31-56-25-111-199-0-0-10-0-37-31-43-24-111-199-0-0-10-0-37-23-22-111-199-0-0-10-0-37-31-57-25-111-199-0-0-10-0-37-31-44-24-111-199-0-0-10-0-37-31-58-25-111-199-0-0-10-0-37-31-45-24-111-199-0-0-10-0-37-31-40-23-111-199-0-0-10-0-37-31-41-23-111-199-0-0-10-0-37-31-111-23-111-199-0-0-10-0-37-31-116-23-111-199-0-0-10-0-37-32-1-254-0-0-22-111-199-0-0-10-0-37-32-2-254-0-0-22-111-199-0-0-10-0-37-32-3-254-0-0-22-111-199-0-0-10-0-37-32-195-0-0-0-22-111-199-0-0-10-0-37-32-4-254-0-0-22-111-199-0-0-10-0-37-32-5-254-0-0-22-111-199-0-0-10-0-37-32-22-254-0-0-23-111-199-0-0-10-0-37-32-211-0-0-0-22-111-199-0-0-10-0-37-31-103-22-111-199-0-0-10-0-37-31-104-22-111-199-0-0-10-0-37-31-105-22-111-199-0-0-10-0-37-31-106-22-111-199-0-0-10-0-37-32-212-0-0-0-22-111-199-0-0-10-0-37-32-138-0-0-0-22-111-199-0-0-10-0-37-32-179-0-0-0-22-111-199-0-0-10-0-37-32-130-0-0-0-22-111-199-0-0-10-0-37-32-181-0-0-0-22-111-199-0-0-10-0-37-32-131-0-0-0-22-111-199-0-0-10-0-37-32-183-0-0-0-22-111-199-0-0-10-0-37-32-132-0-0-0-22-111-199-0-0-10-0-37-32-185-0-0-0-22-111-199-0-0-10-0-37-32-133-0-0-0-22-111-199-0-0-10-0-37-32-213-0-0-0-22-111-199-0-0-10-0-37-32-139-0-0-0-22-111-199-0-0-10-0-37-32-180-0-0-0-22-111-199-0-0-10-0-37-32-134-0-0-0-22-111-199-0-0-10-0-37-32-182-0-0-0-22-111-199-0-0-10-0-37-32-135-0-0-0-22-111-199-0-0-10-0-37-32-184-0-0-0-22-111-199-0-0-10-0-37-32-136-0-0-0-22-111-199-0-0-10-0-37-32-186-0-0-0-22-111-199-0-0-10-0-37-32-137-0-0-0-22-111-199-0-0-10-0-37-31-118-22-111-199-0-0-10-0-37-31-107-22-111-199-0-0-10-0-37-31-108-22-111-199-0-0-10-0-37-32-224-0-0-0-22-111-199-0-0-10-0-37-32-210-0-0-0-22-111-199-0-0-10-0-37-32-209-0-0-0-22-111-199-0-0-10-0-37-31-109-22-111-199-0-0-10-0-37-31-110-22-111-199-0-0-10-0-37-32-23-254-0-0-22-111-199-0-0-10-0-37-31-112-23-111-199-0-0-10-0-37-31-91-22-111-199-0-0-10-0-37-31-92-22-111-199-0-0-10-0-37-31-37-22-111-199-0-0-10-0-37-32-17-254-0-0-22-111-199-0-0-10-0-37-32-220-0-0-0-22-111-199-0-0-10-0-37-32-24-254-0-0-22-111-199-0-0-10-0-37-32-21-254-0-0-23-111-199-0-0-10-0-37-31-117-23-111-199-0-0-10-0-37-31-39-23-111-199-0-0-10-0-37-32-9-254-0-0-27-111-199-0-0-10-0-37-24-22-111-199-0-0-10-0-37-25-22-111-199-0-0-10-0-37-26-22-111-199-0-0-10-0-37-27-22-111-199-0-0-10-0-37-31-14-26-111-199-0-0-10-0-37-32-10-254-0-0-27-111-199-0-0-10-0-37-31-15-26-111-199-0-0-10-0-37-31-32-28-111-199-0-0-10-0-37-31-22-22-111-199-0-0-10-0-37-31-23-22-111-199-0-0-10-0-37-31-24-22-111-199-0-0-10-0-37-31-25-22-111-199-0-0-10-0-37-31-26-22-111-199-0-0-10-0-37-31-27-22-111-199-0-0-10-0-37-31-28-22-111-199-0-0-10-0-37-31-29-22-111-199-0-0-10-0-37-31-30-22-111-199-0-0-10-0-37-31-21-22-111-199-0-0-10-0-37-31-31-26-111-199-0-0-10-0-37-31-33-29-111-199-0-0-10-0-37-31-34-28-111-199-0-0-10-0-37-31-35-29-111-199-0-0-10-0-37-32-163-0-0-0-23-111-199-0-0-10-0-37-32-151-0-0-0-22-111-199-0-0-10-0-37-32-144-0-0-0-22-111-199-0-0-10-0-37-32-146-0-0-0-22-111-199-0-0-10-0-37-32-148-0-0-0-22-111-199-0-0-10-0-37-32-150-0-0-0-22-111-199-0-0-10-0-37-32-152-0-0-0-22-111-199-0-0-10-0-37-32-153-0-0-0-22-111-199-0-0-10-0-37-32-154-0-0-0-22-111-199-0-0-10-0-37-32-145-0-0-0-22-111-199-0-0-10-0-37-32-147-0-0-0-22-111-199-0-0-10-0-37-32-149-0-0-0-22-111-199-0-0-10-0-37-32-143-0-0-0-23-111-199-0-0-10-0-37-31-123-23-111-199-0-0-10-0-37-31-124-23-111-199-0-0-10-0-37-32-6-254-0-0-23-111-199-0-0-10-0-37-31-77-22-111-199-0-0-10-0-37-31-70-22-111-199-0-0-10-0-37-31-72-22-111-199-0-0-10-0-37-31-74-22-111-199-0-0-10-0-37-31-76-22-111-199-0-0-10-0-37-31-78-22-111-199-0-0-10-0-37-31-79-22-111-199-0-0-10-0-37-31-80-22-111-199-0-0-10-0-37-31-71-22-111-199-0-0-10-0-37-31-73-22-111-199-0-0-10-0-37-31-75-22-111-199-0-0-10-0-37-32-142-0-0-0-22-111-199-0-0-10-0-37-32-12-254-0-0-27-111-199-0-0-10-0-37-28-22-111-199-0-0-10-0-37-29-22-111-199-0-0-10-0-37-30-22-111-199-0-0-10-0-37-31-9-22-111-199-0-0-10-0-37-31-17-26-111-199-0-0-10-0-37-32-13-254-0-0-27-111-199-0-0-10-0-37-31-18-26-111-199-0-0-10-0-37-31-20-22-111-199-0-0-10-0-37-31-113-23-111-199-0-0-10-0-37-31-126-23-111-199-0-0-10-0-37-31-127-23-111-199-0-0-10-0-37-31-114-23-111-199-0-0-10-0-37-32-208-0-0-0-23-111-199-0-0-10-0-37-32-7-254-0-0-23-111-199-0-0-10-0-37-32-221-0-0-0-25-111-199-0-0-10-0-37-32-222-0-0-0-24-111-199-0-0-10-0-37-32-15-254-0-0-22-111-199-0-0-10-0-37-32-198-0-0-0-23-111-199-0-0-10-0-37-31-90-22-111-199-0-0-10-0-37-32-216-0-0-0-22-111-199-0-0-10-0-37-32-217-0-0-0-22-111-199-0-0-10-0-37-31-101-22-111-199-0-0-10-0-37-32-141-0-0-0-23-111-199-0-0-10-0-37-31-115-23-111-199-0-0-10-0-37-32-25-254-0-0-26-111-199-0-0-10-0-37-22-22-111-199-0-0-10-0-37-31-102-22-111-199-0-0-10-0-37-31-96-22-111-199-0-0-10-0-37-31-38-22-111-199-0-0-10-0-37-32-254-0-0-0-22-111-199-0-0-10-0-37-32-253-0-0-0-22-111-199-0-0-10-0-37-32-252-0-0-0-22-111-199-0-0-10-0-37-32-251-0-0-0-22-111-199-0-0-10-0-37-32-250-0-0-0-22-111-199-0-0-10-0-37-32-249-0-0-0-22-111-199-0-0-10-0-37-32-248-0-0-0-22-111-199-0-0-10-0-37-32-255-0-0-0-22-111-199-0-0-10-0-37-32-30-254-0-0-22-111-199-0-0-10-0-37-32-29-254-0-0-22-111-199-0-0-10-0-37-32-194-0-0-0-23-111-199-0-0-10-0-37-31-93-22-111-199-0-0-10-0-37-31-94-22-111-199-0-0-10-0-37-31-42-22-111-199-0-0-10-0-37-32-26-254-0-0-22-111-199-0-0-10-0-37-31-98-22-111-199-0-0-10-0-37-31-99-22-111-199-0-0-10-0-37-31-100-22-111-199-0-0-10-0-37-32-28-254-0-0-23-111-199-0-0-10-0-37-32-11-254-0-0-27-111-199-0-0-10-0-37-31-16-26-111-199-0-0-10-0-37-32-164-0-0-0-23-111-199-0-0-10-0-37-32-155-0-0-0-22-111-199-0-0-10-0-37-32-156-0-0-0-22-111-199-0-0-10-0-37-32-157-0-0-0-22-111-199-0-0-10-0-37-32-158-0-0-0-22-111-199-0-0-10-0-37-32-159-0-0-0-22-111-199-0-0-10-0-37-32-160-0-0-0-22-111-199-0-0-10-0-37-32-161-0-0-0-22-111-199-0-0-10-0-37-32-162-0-0-0-22-111-199-0-0-10-0-37-31-125-23-111-199-0-0-10-0-37-32-223-0-0-0-22-111-199-0-0-10-0-37-31-82-22-111-199-0-0-10-0-37-31-83-22-111-199-0-0-10-0-37-31-84-22-111-199-0-0-10-0-37-31-85-22-111-199-0-0-10-0-37-31-86-22-111-199-0-0-10-0-37-31-87-22-111-199-0-0-10-0-37-31-81-22-111-199-0-0-10-0-37-32-14-254-0-0-27-111-199-0-0-10-0-37-31-10-22-111-199-0-0-10-0-37-31-11-22-111-199-0-0-10-0-37-31-12-22-111-199-0-0-10-0-37-31-13-22-111-199-0-0-10-0-37-31-19-26-111-199-0-0-10-0-37-32-129-0-0-0-23-111-199-0-0-10-0-37-32-128-0-0-0-23-111-199-0-0-10-0-37-31-89-22-111-199-0-0-10-0-37-32-218-0-0-0-22-111-199-0-0-10-0-37-32-219-0-0-0-22-111-199-0-0-10-0-37-31-69-30-111-199-0-0-10-0-37-32-20-254-0-0-22-111-199-0-0-10-0-37-31-122-22-111-199-0-0-10-0-37-32-18-254-0-0-26-111-199-0-0-10-0-37-31-121-23-111-199-0-0-10-0-37-32-165-0-0-0-23-111-199-0-0-10-0-37-32-19-254-0-0-22-111-199-0-0-10-0-37-31-97-22-111-199-0-0-10-0-10-22-11-22-12-22-13-208-28-0-0-2-40-108-0-0-10-111-179-0-0-10-19-4-17-4-3-111-180-0-0-10-19-5-17-5-116-108-0-0-1-19-6-17-6-111-185-0-0-10-19-7-17-7-142-105-141-82-0-0-1-19-8-40-200-0-0-10-19-9-22-19-15-43-23-0-17-8-17-15-17-7-17-15-154-111-186-0-0-10-162-0-17-15-23-88-19-15-17-15-17-8-142-105-254-4-19-16-17-16-45-219-17-5-111-201-0-0-10-19-10-114-17-0-0-112-17-6-111-183-0-0-10-17-8-17-10-23-115-202-0-0-10-19-11-17-11-111-203-0-0-10-19-12-17-6-111-181-0-0-10-19-13-0-17-13-111-190-0-0-10-111-191-0-0-10-19-17-43-26-17-17-111-192-0-0-10-19-18-0-17-9-17-18-111-193-0-0-10-111-204-0-0-10-0-0-17-17-111-194-0-0-10-45-221-222-13-17-17-44-8-17-17-111-70-0-0-10-0-220-17-9-111-205-0-0-10-19-14-17-12-17-14-111-206-0-0-10-0-22-19-19-56-158-2-0-0-0-2-17-19-145-32-254-0-0-0-254-1-19-21-17-21-44-23-0-32-0-254-0-0-2-17-19-23-88-145-88-11-17-19-23-88-19-19-0-43-7-0-2-17-19-145-11-0-6-7-111-207-0-0-10-19-20-17-19-23-88-19-19-17-20-19-23-17-23-19-22-17-22-69-9-0-0-0-27-0-0-0-65-0-0-0-5-0-0-0-16-0-0-0-5-0-0-0-35-2-0-0-16-0-0-0-32-0-0-0-43-0-0-0-56-38-2-0-0-17-19-23-88-19-19-56-27-2-0-0-17-19-26-88-19-19-56-16-2-0-0-56-11-2-0-0-17-19-30-88-19-19-56-0-2-0-0-17-19-26-2-17-19-40-183-0-0-6-26-90-88-88-19-19-56-234-1-0-0-2-17-19-40-183-0-0-6-12-8-32-189-166-152-162-97-12-8-32-0-0-0-112-55-10-8-32-255-255-0-112-254-5-43-1-22-19-24-17-24-44-23-0-17-12-17-4-8-111-208-0-0-10-111-209-0-0-10-13-0-56-115-1-0-0-0-17-6-111-201-0-0-10-19-25-20-19-26-20-19-27-17-25-111-210-0-0-10-45-9-17-25-111-211-0-0-10-43-1-23-19-29-17-29-44-9-17-25-111-212-0-0-10-19-26-17-6-111-213-0-0-10-45-9-17-6-111-214-0-0-10-43-1-23-19-30-17-30-44-9-17-6-111-215-0-0-10-19-27-17-25-111-179-0-0-10-8-17-26-17-27-111-216-0-0-10-19-28-17-28-111-217-0-0-10-111-218-0-0-10-114-86-48-0-112-40-74-0-0-10-19-31-17-31-44-49-0-17-12-17-28-116-122-0-0-1-111-219-0-0-10-17-28-116-122-0-0-1-111-201-0-0-10-116-123-0-0-1-111-220-0-0-10-111-221-0-0-10-13-0-56-190-0-0-0-17-28-111-217-0-0-10-111-218-0-0-10-114-110-48-0-112-40-74-0-0-10-19-32-17-32-44-27-0-17-12-17-28-116-123-0-0-1-111-220-0-0-10-111-222-0-0-10-13-0-56-135-0-0-0-17-28-111-218-0-0-10-114-134-48-0-112-40-74-0-0-10-45-19-17-28-111-218-0-0-10-114-146-48-0-112-40-74-0-0-10-43-1-23-19-33-17-33-44-46-0-17-12-17-28-116-124-0-0-1-111-223-0-0-10-17-28-116-124-0-0-1-111-201-0-0-10-116-123-0-0-1-111-220-0-0-10-111-224-0-0-10-13-0-43-44-0-17-12-17-28-116-108-0-0-1-111-223-0-0-10-17-28-116-108-0-0-1-111-201-0-0-10-116-123-0-0-1-111-220-0-0-10-111-224-0-0-10-13-0-0-2-17-19-9-210-156-2-17-19-23-88-9-30-99-210-156-2-17-19-24-88-9-31-16-99-210-156-2-17-19-25-88-9-31-24-99-210-156-17-19-26-88-19-19-43-8-17-19-24-88-19-19-43-0-0-17-19-2-142-105-254-4-19-34-17-34-58-82-253-255-255-17-12-2-17-13-111-187-0-0-10-111-225-0-0-10-0-17-11-20-4-111-226-0-0-10-19-35-43-0-17-35-42
[+] Overwriting bytecode for flared_67: 109-16-106-216-134-20-104-199-228-155-155-255-51-244-186-66-21-112-243-127-188-97-199-29-60-173-79-46-134-193-152-9-222-110-176-106-29-127-148-62-214-62-253-147-214-228-123-218-111-96-217-174-81-254-18-11-72-77-156-216-197-58-64-35-2-146-33-197-67-79-37-149-219-181-168-125-100-52-70-87-50-117-191-37-231-234-183-223-92-164-33-207-227-188-121-156-254-218-144-68-194-182-150-31-59-68-210-155-85-148-167-20-6-68-165-79-122-26-59-24-218-65-104-159-46-85-177-30-60-12-127-138-164-2-149-124-222-160-234-163-23-28-138-200-253-13-200-159-23-41-33-227-158-119-106-128-77-247-241-230-146-180-94-72-20-28-111-4-175-41-112-218-48-152-1-189-183-160-161-32-140-18-7-19-235-156-235-44-152-20-47-231-174-3-16-99-189-65-179-224-157-196-239-238-184-70-178-6-118-172-201-172-85-208-89-127-172-75-93-120-49-67-108-154-249-137-43-44-135-157-0-117-237-192-131-200-34-25-90-164-233-229-182-236-75-130-145-222-170-145-182-114-228-59-175-90-88-85-244-47-26-133-126-216-172-83-191-149-76-145-92-146-240-184-142-75-140-128-79-119-247-76-130-245-231-141-145-178-16-41-111-205-37-43-138-100-102-221-64-247-195-252-146-24-53-35-129-43-172-99-205-216-6-125-55-205-2-136-241-30-193-13-132-35-33-142-109-196-46-0-228-174-64-87-179-251-186-106-192-195-11-102-5-173-92-151-199-168-243-188-97-222-236-33-53-182-119-111-246-166-182-189-252-130-126-30-151-174-201-60-19-152-199-46-18-91-7-215-198-137-199-197-208-114-200-6-194-30-33-253-131-75-115-26-13-78-105-130-46-61-255-25-222-183-169-201-22-190-15-218-174-159-168-108-222-240-236-138-186-120-92-121-140-203-184-199-36-173-33-195-241-133-169-136-137-174-230-25-201-254-240-3-14-71-79-227-163-6-59-28-98-223-200-181-225-134-141-19-255-225-165-104-157-76-232-41-246-31-227-48-9-210-193-187-136-88-107-68-123-212-35-29-113-4-97-18-188-243-166-3-33-211-26-231-89-135-102-194-94-38-237-131-35-11-18-143-29-12-45-137-26-72-151-0-189-135-246-152-234-214-108-3-120-223-15-54-184-217-98-0-241-168-230-85-230-160-250-102-241-209-244-176-197-29-232-217-60-239-41-210-144-205-215-136-186-234-11-67-252-220-214-67-170-45-151-113-97-66-67-29-141-144-166-24-225-188-61-91-247-53-250-201-176-144-111-35-209-94-155-252-148-182-106-21-251-176-5-152-133-118-119-250-171-11-68-0-38-190-166-254-173-175-76-198-226-13-147-25-189-116-160-3-166-71-137-214-37-145-29-48-182-164-213-128-190-255-30-164-75-111-252-18-183-157-79-228-105-164-51-238-29-235-219-17-214-116-83-100-130-109-218-149-161-118-71-8-217-204-7-226-238-238-206-78-119-141-75-9-247-164-109-129-94-47-18-202-201-196-170-73-172-185-34-221-149-103-113-64-85-71-10-157-156-80-255-46-29-141-154-72-41-73-108-221-0-88-55-114-99-125-62-21-34-190-53-53-204-240-185-15-27-10-180-176-153-207-229-13-47-228-172-60-0-97-32-99-77-68-220-60-47-255-220-215-8-245-123-222-27-202-98-44-211-138-44-30-148-188-68-49-115-0-66-127-208-2-234-192-157-210-231-135-20-124-224-27-46-221-168-164-84-7-242-101-129-128-104-160-52-2-206-145-0-171-201-5-189-92-6-5-10-186-64-72-226-219-24-87-170-16-239-183-19-159-220-108-56-221-254-80-153-74-140-155-3-86-134-104-179-218-94-209-215-162-153-154-199-169-130-166-103-17-245-35-18-23-125-96-207-92-205-224-94-181-107-191-46-164-68-140-84-175-163-207-178-30-224-113-6-66-164-143-90-88-233-136-85-104-137-236-216-37-153-86-13-126-114-33-54-217-107-34-100-246-81-183-109-37-113-243-55-12-90-140-184-62-133-6-204-227-106-197-26-88-179-47-22-77-194-52-172-190-58-44-214-130-0-100-6-49-27-47-247-149-181-204-202-12-158-207-248-107-84-83-110-166-7-11-67-33-161-32-99-61-71-120-210-46-182-53-19-33-0-155-199-59-206-132-162-230-100-9-174-242-59-64-105-230-189-48-122-31-33-228-143-250-203-186-78-61-249-156-86-104-188-215-107-185-139-51-215-130-104-92-189-151-113-112-1-6-14-236-112-133-187-244-255-27-11-205-112-20-54-101-237-200-179-69-54-99-212-176-90-138-88-247-182-197-39-248-136-90-184-72-46-13-43-208-172-200-215-80-173-190-194-195-76-3-110-244-228-44-58-158-49-94-145-230-44-196-61-58-243-19-68-21-91-238-54-223-156-226-152-110-139-132-2-155-199-149-170-178-86-50-19-92-32-26-22-208-124-68-163-232-138-157-92-154-122-173-103-94-204-143-88-1-147-203-18-173-91-246-31-151-25-139-228-193-255-231-245-65-215-102-99-87-63-176-228-238-40-104-33-26-46-76-229-198-218-17-201-85-8-105-117-134-37-12-206-254-184-155-154-146-184-38-134-102-44-0-194-226-231-35-133-243-212-4-105-205-165-29-230-237-30-159-56-110-241-221-50-50-225-229-53-140-205-142-98-7-197-127-154-218-79-230-110-229-228-129-177-32-162-1-89-155-180-172-116-24-237-24-117-79-206-143-1-1-237-248-37-70-162-97-8-37-131-12-158-55-49-83-138-111-43-17-143-224-140-154-216-33-25-73-26-173-9-74-11-191-229-108-247-236-91-106-126-65-248-51-23-167-13-61-230-153-141-6-35-189-255-32-117-83-31-4-45-89-71-91-28-56-1-223-82-196-92-158-19-193-146-78-231-88-130-49-19-220-99-128-31-3-39-78-191-196-247-164-204-87-61-37-249-157-23-223-166-46-235-33-61-239-242-98-0-177-57-28-208-237-241-81-245-198-60-24-17-178-32-141-205-183-209-188-131-109-84-74-65-163-139-228-240-65-67-48-17-196-36-14-139-219-211-223-101-236-47-51-97-254-206-243-14-93-84-133-29-54-222-188-92-238-218-45-97-12-96-180-131-12-7-76-142-18-2-241-228-242-86-151-62-33-233-66-213-152-214-146-237-189-18-218-230-103-177-156-0-166-125-89-139-122-175-85-247-129-101-252-91-98-161-43-223-71-125-58-5-152-88-201-53-205-199-197-249-44-101-38-96-101-241-61-117-252-11-196-113-147-75-83-51-218-55-138-28-231-250-159-233-119-150-104-78-179-35-190-179-234-91-202-27-62-155-245-113-99-182-227-59-185-200-114-77-5-150-91-149-61-169-18-49-198-60-233-207-136-239-193-216-77-16-135-56-128-55-244-62-66-24-184-49-23-99-48-174-36-27-72-28-200-40-118-64-73-153-85-1-178-37-232-115-244-10-238-168-65-58-204-205-162-28-83-36-240-225-26-98-12-58-171-109-166-165-15-36-154-70-238-231-225-243-139-28-48-68-60-12-117-135-108-234-78-123-122-172-212-82-80-104-126-242-245-120-122-122-205-79-250-201-14-250-75-229-235-174-144-55-243-171-164-13-237-132-205-192-31-43-0-99-79-72-246-134-104-239-254-19-161-181-119-237-18-172-121-114-158-104-143-203-28-157-94-164-195-113-5-112-170-185-91-161-36-151-121-197-4-196-124-252-176-124-149-62-52-182-251-65-11-91-34-182-156-95-71-178-234-81-194-247-234-141-105-231-90-214-201-122-50-179-109-218-235-146-26-159-7-32-112-12-118-196-100-78-151-164-5-197-79-199-219-178-1-133-18-35-19-174-228-94-237-128-14-87-238-72-202-9-68-168-170-201-225-182-128-38-40-26-80-181-209-4-0-107-215-186-216-102-128-247-140-89-59-18-30-246-181-12-96-79-218-251-128-167-28-17-209-75-4-236-250-248-93-47-141-233-85-162-128-51-112-100-136-77-27-81-142-207-151-138-112-27-186-0-218-213-131-130-79-198-232-140-97-148-252-147-251-12-133-53-161-19-140-44-223-117-114-50-140-202-131-2-180-122-123-222-61-93-84-183-101-210-83-185-74-227-3-243-80-136-85-129-74-98-233-93-143-141-33-101-98-81-246-132-66-230-215-230-25-30-85-158-184-205-207-207-191-210-226-251-113-126-225-3-117-2-184-82-144-30-79-176-60-238-84-20-219-206-119-100-12-28-218-50-50-183-200-124-147-26-157-188-171-37-243-227-111-242-15-64-45-133-85-250-207-165-98-202-121-186-243-240-91-125-239-84-164-175-209-189-57-60-191-118-128-146-4-22-250-112-165-232-191-55-54-134-199-224-98-140-85-254-3-216-38-172-96-45-53-158-63-191-33-81-6-241-198-223-121-60-161-75-207-8-20-11-49-36-71-105-141-195-77-69-104-59-56-230-79-212-50-214-225-92-48-230-199-110-48-68-192-231-102-38-235-10-47-250-196-26-123-60-230-204-16-124-114-219-232-203-184-224-143-165-10-202-106-115-215-46-68-194-243-2-168-166-93-39-89-94-11-62-34-53-88-245-239-20-75-180-115-235-133-100-139-224-88-193-27-32-160-188-34-149-214-184-72-227-35-106-31-75-130-138-191-122-189-90-77-21-218-85-39-35-186-89-61-142-118-200-78-155-11-57-190-79-27-140-94-159-172-11-240-224-149-40-104-250-165-17-34-253-115-6-69-74-148-255-218-124-123-185-108-91-28-131-63-72-204-112-95-48-251-173-104-206-101-71-142-145-240-66-233-101-166-80-39-4-243-115-187-27-178-225-35-242-158-149-196-17-233-31-46-52-177-241-1-198-158-119-228-77-113-72-140-57-208-7-180-204-91-59-85-88-181-67-126-26-138-117-47-208-131-124-168-208-20-180-180-181-78-97-102-124-143-110-170-105-85-234-34-151-224-248-182-173-202-213-127-109-114-231-59-40-71-20-201-244-159-187-36-27-82-254-125-249-212-217-201-71-153-21-197-159-82-151-239-139-198-250-6-62-53-70-67-102-37-61-52-122-164-181-201-153-198-7-69-226-122-188-217-240-11-56-212-93-34-156-214-175-37-62-46-164-181-229-229-12-187-22-211-151-165-79-162-227-75-43-217-75-82-12-16-9-33-22-51-253-113-229-68-137-103-133-85-101-134-36-227-224-33-56-38-100-232-66-75-188-149-240-18-246-194-138-92-24-46-36-131-159-178-232-154-213-210-74-47-32-250-61-93-38-71-248-41-26-230-172-32-223-202-118-103-129-211-77-198-220-40-60-55-98-161-68-45-57-158-80-145-158-18-43-194-87-147-235-175-201-97-66-50-130-3-163-212-59-128-24-2-132-131-82-247-189-6-250-132-3-203-240-123-149-26-130-204-159-179-15-238-231-158-252-123-229-10-181-94-253-111-241-184-133-78-13-27-191-51-5-81-152-103-171-254-113-198-156-103-129-214-52-136-113-0-26-230-134-215-17-178-81-156-135-147-217-56-246-70-13-102-13-108-174-190-85-128-242-253-10-31-109-77-220-38-59-105-70-90-52-38-148-231-33-82-0-251-224-24-37-56-207-86-90-26-201-200-217-179-213-153-244-136-205-242-68-4-191-96-88-111-241-156-18-230-210-37-74-91-190-89-160-217-215-209-79-23-242-194-93-114-144-147-133-154-50-11-26-47-14-251-60-127-192-182-71-51-67-116-72-164-126-126-244-123-249-26-177-251-162-44-17-253-3-229-223-93-23-119-180-198-10-26-77-194-29-33-25-33-137-27-211-126-121-184-243-17-158-9-161-24-90-30-140-225-234-62-124-218-215-234-28-204-192-129-153-100-49-50-94-216-0-143-114-135-88-147-131-74-242-205-190-13-214-155-107-235-141-107-215-222-164-63-73-158-255-7-190-247-31-143-224-108-171-201-23-202-172-5-137-86-186-49-231-10-44-14-245-36-21-173-214-197-90-127-51-192-70-211-135-80-213-139-0-99-236-82-98-13-132-161-63-136-226-129-36-114-87-62-114-241-17-154-226-114-184-26-17-43-149-87-132-216-126-56-129-46-7-132-30-218-172-232-159-116-109-78-227-217-91-192-104-7-97-150-62-58-169-184-170-209-64-54-119-45-29-102-10-169-255-245-107-211-32-151-68-41-250-109-4-106-55-55-208-213-238-124-119-231-249-70-132-78-217-76-153-117-113-114-87-7-68-58-217-101-84-149-230-201-81-21-64-60-180-64-154-8-101-161-62-160-238-34-176-185-112-29-250-211-254-207-183-135-22-253-38-253-93-106-128-89-149-174-150-227-6-72-154-153-178-144-16-208-51-182-24-33-137-32-245-55-155-18-203-130-94-184-37-183-25-157-171-250-32-229-10-64-139-204-178-39-131-96-32-109-191-231-83-95-228-4-115-61-117-73-190-130-227-20-132-77-35-227-127-21-229-21-175-78-172-215-150-189-109-205-179-58-241-93-194-119-101-197-210-21-41-109-133-214-39-135-93-119-71-101-4-160-225-11-135-169-56-5-179-13-110-181-207-168-150-131-145-133-81-13-232-93-16-105-235-119-144-216-39-36-122-31-117-8-201-19-89-230-213-24-63-96-18-197-167-116-158-220-64-163-246-215-37-58-125-167-143-119-31-16-25-95-221-143-146-79-64-198-223-130-0-170-176-56-206-136-75-75-194-119-216-179-151-131-45-163-249-59-138-33-132-225-199-197-255-223-130-131-50-88-51-216-253-190-120-76-38-236-107-245-92-67-181-167-55-102-200-89-97-239-85-5-60-189-254-73-227-235-57-238-5-199-24-105-67-0-181-217-11-225-124-12-207-149-197-64-44-31-141-152-22-40-34-67-2-46-156-64-191-47-104-59-179-124-239-148-0-75-100-54-177-239-78-127-114-73-53-166-247-189-28-196-94-161-215-221-165-213-103-21-100-116-25-219-120-65-89-82-165-49-22-225-187-86-231-39-217-162-209-185-248-245-73-2-18-164-221-18-165-17-238-85-227-78-210-60-213-115-6-49-240-227-0-197-167-59-9-7-186-176-4-3-4-173-28-111-43-23-200-212-99-70-173-148-67-192-253-108-132-170-82-102-156-159-201-21-244-132-90-215-155-213-87-244-13-235-81-54-50-99-17-190-170-50-205-169-53-108-129-231-62-156-131-15-93-158-102-100-228-6-122-167-188-241-56-141-239-184-134-88-111-199-57-32-153-148-187-106-209-32-223-135-2-115-153-254-82-72-151-110-132-236-81-44-232-106-1-185-249-64-186-125-229-41-120-118-98-98-118-201-226-252-147-196-38-242-164-73-87-57-59-166-33-24-211-130-117-13-56-46-147-2-112-145-102-98-162-216-251-34-155-239-209-206-140-135-89-141-5-245-197-183-97-192-4-19-92-205-85-245-1-85-0-72-53-223-140-1-94-195-80-204-78-53-157-75-213-82-139-75-40-231-8-66-105-219-161-176-140-82-6-212-130-5-32-70-197-137-152-173-251-88-47-65-164-248-105-43-34-184-61-9-66-10-205-25-76-231-222-89-61-219-116-11-189-124-73-72-20-86-134-76-186-222-79-208-184-198-158-112-114-117-142-212-21-253-146-120-56-7-249-221-170-62-111-32-227-36-132-40-175-32-23-203-49-241-78-100-186-253-97-134-73-110-231-199-77-160-246-191-234-209-16-13-93-168-161-124-110-47-236-148-66-118-193-81-94-194-162-35-174-45-190-59-166-115-148-60-86-167-210-66-46-196-61-221-16-9-110-137-79-210-245-138-16-205-67-210-173-149-104-138-254-210-16-188-19-213-102-233-19-101-37-198-92-169-101-126-56-227-64-84-84-25-211-220-56-51-0-217-47-194-142-193-62-71-68-91-179-128-202-59-163-132-117-234
[+] Offset found: 0x19E0C
[+] Decrypting method: FLARE15.flared_68()
[+] MetaData Token: 0x060000B6 (flared_68) ~> RVA: 0x00013C50
[+] Decrypted Bytecode: 0-22-10-2-3-25-88-145-32-0-0-0-1-90-10-6-2-3-24-88-145-32-0-0-1-0-90-88-10-6-2-3-23-88-145-32-0-1-0-0-90-88-10-6-2-3-145-88-10-6-11-43-0-7-42
[+] Overwriting bytecode for flared_68: 117-183-8-248-234-116-145-27-50-242-76-217-177-166-136-39-98-134-128-160-250-176-62-253-199-158-173-102-230-194-19-134-218-197-77-168-245-235-190-64-172-117-149-26-89-207-247-166-6-173-127-119-142-47-227
[+] Offset found: 0x1AC5C
[+] Decrypting method: FLARE15.flared_69()
[+] MetaData Token: 0x060000B8 (flared_69) ~> RVA: 0x00013CEC
[+] Patching flared_69 at 0x23X ~> 0xA0000E3
[+] Patching flared_69 at 0x73X ~> 0xA00006B
[+] Patching flared_69 at 0x133X ~> 0x6000065
[+] Patching flared_69 at 0x203X ~> 0x6000059
[+] Patching flared_69 at 0x313X ~> 0xA000067
[+] Patching flared_69 at 0x403X ~> 0x6000063
[+] Patching flared_69 at 0x563X ~> 0x200001A
[+] Patching flared_69 at 0x673X ~> 0x40000DF
[+] Patching flared_69 at 0x723X ~> 0xA000017
[+] Patching flared_69 at 0x773X ~> 0xA0000E4
[+] Patching flared_69 at 0x913X ~> 0x40000E0
[+] Patching flared_69 at 0x963X ~> 0x100002F
[+] Patching flared_69 at 0x1053X ~> 0x40000E3
[+] Patching flared_69 at 0x1123X ~> 0xA000056
[+] Patching flared_69 at 0x1233X ~> 0x40000E0
[+] Patching flared_69 at 0x1283X ~> 0xA000057
[+] Patching flared_69 at 0x1583X ~> 0xA000046
[+] Decrypted Bytecode: 0-40-227-0-0-10-111-107-0-0-10-10-115-101-0-0-6-11-6-40-89-0-0-6-0-20-12-6-25-23-115-103-0-0-10-13-0-0-7-111-99-0-0-6-19-4-22-19-5-43-91-17-4-17-5-163-26-0-0-2-19-6-0-2-17-6-123-223-0-0-4-115-23-0-0-10-111-228-0-0-10-19-7-17-7-44-48-0-17-6-123-224-0-0-4-141-47-0-0-1-12-9-17-6-123-227-0-0-4-110-22-111-86-0-0-10-38-9-8-22-17-6-123-224-0-0-4-111-87-0-0-10-38-43-15-0-17-5-23-88-19-5-17-5-17-4-142-105-50-157-0-222-11-9-44-7-9-111-70-0-0-10-0-220-8-19-8-43-0-17-8-42
[+] Overwriting bytecode for flared_69: 173-160-172-0-5-110-110-37-41-198-242-237-234-39-251-214-122-168-2-233-105-139-177-92-251-224-206-166-180-170-148-175-252-73-49-68-114-39-77-244-155-96-225-65-118-170-38-25-49-86-183-248-204-158-55-34-238-79-4-36-159-200-113-127-50-67-240-161-246-183-99-83-91-14-78-9-169-112-229-81-186-181-116-93-242-155-226-93-17-14-85-34-35-40-84-210-238-98-15-51-185-132-34-121-243-100-157-190-80-45-120-126-105-178-106-234-84-19-140-150-96-147-144-232-98-65-47-51-185-123-27-71-97-178-152-53-146-250-106-141-254-35-13-227-149-215-184-112-190-106-125-219-213-120-210-38-244-57-23-177-53-106-5-212-18-49-28-183-26-52-87-90
[+] Offset found: 0x1ACF8
[+] Decrypting method: FLARE15.flared_70()
[+] MetaData Token: 0x060000BA (flared_70) ~> RVA: 0x00013E04
[+] Patching flared_70 at 0x33X ~> 0xA0000E5
[+] Patching flared_70 at 0x113X ~> 0xA0000A3
[+] Patching flared_70 at 0x163X ~> 0xA0000A4
[+] Patching flared_70 at 0x213X ~> 0xA0000E6
[+] Patching flared_70 at 0x283X ~> 0x60000B3
[+] Patching flared_70 at 0x353X ~> 0x60000B9
[+] Patching flared_70 at 0x423X ~> 0x100002F
[+] Patching flared_70 at 0x483X ~> 0x4000140
[+] Patching flared_70 at 0x533X ~> 0xA000092
[+] Patching flared_70 at 0x593X ~> 0x6000080
[+] Patching flared_70 at 0x703X ~> 0x60000B5
[+] Decrypted Bytecode: 0-2-115-229-0-0-10-10-6-22-111-163-0-0-10-111-164-0-0-10-111-230-0-0-10-11-7-40-179-0-0-6-12-8-40-185-0-0-6-13-26-141-47-0-0-1-37-208-64-1-0-4-40-146-0-0-10-9-40-128-0-0-6-19-4-17-4-7-3-40-181-0-0-6-19-5-17-5-19-6-43-0-17-6-42
[+] Overwriting bytecode for flared_70: 145-168-12-201-255-214-235-118-235-80-1-222-23-180-58-73-97-196-109-198-102-60-52-238-141-209-9-27-204-6-33-253-221-224-199-126-86-211-227-91-217-153-102-241-238-50-224-69-55-140-20-228-184-104-228-84-115-30-59-45-204-208-169-228-46-3-1-55-237-187-242-142-224-17-237-205-213-67-255-90-241-195-228-64-242
[+] Offset found: 0x1AE10
*/
