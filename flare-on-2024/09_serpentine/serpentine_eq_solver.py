#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Flare-On 2024: 09 - serpentine
# ----------------------------------------------------------------------------------------
import z3


# ----------------------------------------------------------------------------------------
def crack_key_mod_0():
    a1, a2, a3, a4, a5, a6, a7, a8 = [z3.BitVec(f'a{i}', 64) for i in range(8)]
    b1, b2, b3, b4, b5, b6, b7, b8 = [z3.BitVec(f'b{i}', 64) for i in range(8)]
    c1, c2, c3, c4, c5, c6, c7, c8 = [z3.BitVec(f'c{i}', 64) for i in range(8)]
    d1, d2, d3, d4, d5, d6, d7, d8 = [z3.BitVec(f'd{i}', 64) for i in range(8)]
    e1, e2, e3, e4, e5, e6, e7, e8 = [z3.BitVec(f'e{i}', 64) for i in range(8)]
    f1, f2, f3, f4, f5, f6, f7, f8 = [z3.BitVec(f'f{i}', 64) for i in range(8)]
    g1, g2, g3, g4, g5, g6, g7, g8 = [z3.BitVec(f'g{i}', 64) for i in range(8)]
    h1, h2, h3, h4, h5, h6, h7, h8 = [z3.BitVec(f'h{i}', 64) for i in range(8)]

    smt = z3.Solver()

    # If there's a mistake in an equation, use the sample key as the only valid
    # key, then get the generated values from unicorn and use them as the expected
    # values in the intermediate variables (`a7`, `a8`, etc.). Thus you can quickly
    # find which equation is wrong, because the result will be `unsat`.
    # 
    # NOTE: The numbers in the comment in the last equations `a8`, `b8`, etc.
    # are the expected numbers for the sample key.
    #
    #
    # SAMPLE_KEY = b'ABCDEFGHIJKLMNOPQRSTUVWXYZ012345'
    # for i in range(32):
    #     smt.add( key[i] == SAMPLE_KEY[i] )

    key = [z3.BitVec('key_%d' % i, 64) for i in range(32)]
    for c in key:
        smt.add( z3.And(c >= 0x20, c <= 0x7e) )

    smt.add(a1 == (key[4] * 0xEF7A8C) + 0x9d865d8d)
    smt.add(a2 == (a1 - key[24]  * 0x45B53C) + 0x18baee57)
    smt.add(a3 == (a2 - key[0]   * 0xE4CF8B) - 0x913fbbde)
    smt.add(a4 == (a3 - key[8]   * 0xF5C990) + 0x6bfaa656)
    smt.add(a5 == (a4 ^ (key[20] * 0x733178)) ^ 0x61e3db3b)
    smt.add(a6 == (a5 ^ (key[16] * 0x9A17B8)) - 0xca2804b1)
    smt.add(a7 == (a6 ^ (key[12] * 0x773850)) ^ 0x5a6f68be)
    smt.add(a8 == (a7 ^ (key[28] * 0xE21D3D)) ^ 0x5c911d23)
    smt.add(a8 == 0xffffffff81647a79) # + 0x96f8a75)

    smt.add(b1 == (key[12] * 0x640BA9) + 0x0000516C7A5C)
    smt.add(b2 == (b1 - key[0]  * 0xF1D9E5) + 0x00008B424D6B)
    smt.add(b3 == (b2 + key[28] * 0xD3E2F8) + 0x003802BE78)
    smt.add(b4 == (b3 + key[24] * 0xB558CE) - 0x0033418C8E)
    smt.add(b5 == (b4 - key[8]  * 0x2F03A7) ^ 0x00E050B170)
    smt.add(b6 == (b5 + key[16] * 0xB8FA61) ^ 0x001FC22DF6)
    smt.add(b7 == (b6 - key[20] * 0xE0C507) ^ 0x00D8376E57)
    smt.add(b8 == (b7 + key[4]  * 0x8E354E) - 0x00d2cb3108)
    smt.add(b8 == 0x100e79080) # + 0xFFFFFFFF584C4381)

    smt.add(c1 == (key[28] * 0xAC70B9) + 0x0000DAE0A932)
    smt.add(c2 == (c1 ^ (key[4] * 0xC42B6F)) ^ 0xBC03104C)
    smt.add(c3 == (c2 - key[0] * 0x867193) + 0x0000DC48C63A)
    smt.add(c4 == (c3 - key[12] * 0x6D31FE) ^ 0x00004BAEB6D0)
    smt.add(c5 == (c4 - key[16] * 0xAAAE58) - 0xcd7121f8) 
    smt.add(c6 == (c5 + key[20] * 0x9FAA7A) + 0x000000BE0A2C9C)
    smt.add(c7 == (c6 + key[24] * 0x354AC6) ^ 0x00D8AD17F1)
    smt.add(c8 == (c7 - key[8] * 0x3F2ACB) - 0x8d6b7d89)    
    smt.add(c8 == 0x261c13793) # + 0xFFFFFFFE8FCEEE3A)
                  
    smt.add(d1 == (key[16] * 0x336E91) + 0x0000A1EB20E3)
    smt.add(d2 == (d1 - key[4] * 0xD45DE9) - 0x381AC71A)
    smt.add(d3 == (d2 + key[8] * 0x76C8F8) ^ 0x000000D8CAA2CD)
    smt.add(d4 == (d3 - key[20] * 0x945339) + 0x00000000524D7EFA)
    smt.add(d5 == (d4 + key[12] * 0x4474EC) - 0xE47E82CD)
    smt.add(d6 == (d5 ^ (key[0] * 0x51054F)) ^ 0x00003321C9B1)
    smt.add(d7 == (d6 - key[24] * 0xD7EB3B) + 0x0036F6829D)
    smt.add(d8 == (d7 - key[28] * 0xAD52E1) ^ 0x00006CE2181A)
    smt.add(d8 == 0xFFFFFFFFF39B4443) # + 0xFFFFFFFFA7392A05)
    
    smt.add(e1 == (key[16] * 0xBAE081) + 0x0000002359766F)
    smt.add(e2 == (e1 ^ (key[24] * 0xC2483B)) + 0x000000EA986A57)
    smt.add(e3 == (e2 - key[28] * 0x520EE2) ^ 0x000000A6FF8114)
    smt.add(e4 == (e3 + key[8] * 0x9864BA) + 0x00000042833507)
    smt.add(e5 == (e4 - key[0] * 0x7CD278) ^ 0x0000360BE811)
    smt.add(e6 == (e5 ^ (key[4] * 0xBE6605)) - 0x4C927A8D)
    smt.add(e7 == (e6 + key[20] * 0x3BD2E8) + 0x000000B790CFD3)
    smt.add(e8 == (e7 - key[12] * 0x548C2B) + 0x2a0e04cc)
    smt.add(e8 == 0x0221328792) # + 0xFFFFFFFF17E225CC)
    
    smt.add(f1 == (key[24] * 0xB74A52) ^ 0x008354D4E8)
    smt.add(f2 == (f1 ^ (key[4] * 0xF22ECD)) - 0x34CBF23B)
    smt.add(f3 == (f2 + key[20] * 0xBEF4BE) ^ 0x0060A6C39A)
    smt.add(f4 == (f3 ^ key[8] * 0x7FE215) + 0x0000B14A7317)
    smt.add(f5 == (f4 - key[16] * 0xDB9F48) - 0xBCA905F2)
    smt.add(f6 == (f5 - key[28] * 0xBB4276) - 0x0000920E2248) # ?
    smt.add(f7 == (f6 ^(key[0] * 0xA3FBEF)) + 0x00004C22D2D3)
    smt.add(f8 == (f7 ^ (key[12] * 0xC5E883)) ^ 0x000050A6E5C9)
    smt.add(f8 == 0xFFFFFFFFD8E5BDC6) # + 0xFB12E870)

    smt.add(g1 == (key[4] * 0xF56C62) ^ 0x6C7D1F41)
    smt.add(g2 == (g1 + key[16] * 0x615605) + 0x0000005B52F6EE)
    smt.add(g3 == (g2 + key[20] * 0x828456) ^ 0x6F059759)
    smt.add(g4 == (g3 -key[28] * 0x50484B) + 0x0000000084E222AF)
    smt.add(g5 == (g4 ^ (key[8] * 0x89D640)) + 0x00FD21345B)
    smt.add(g6 == (g5 - key[24] * 0xE4B191) + 0x00FE15A789)
    smt.add(g7 == (g6 ^ (key[0] * 0x8C58C1)) ^ 0x4C49099F)
    smt.add(g8 == (g7 + key[12] * 0xA13C4C) ^ 0x0027C5288E)
    smt.add(g8 == 0x30098db0b) # + 0xFFFFFFFFF7B7BB92)

    # Grab g8 from the solution: 
    #   hex((0x2f850969d - 0xFFFFFFFFF7B7BB92) & 0xffffffffffffffff) = 0x30098db0b

    smt.add(h1 == (key[0] * 0x53A4E0) - 0x6061803E)
    smt.add(h2 == (h1 - key[16] * 0x9BBFDA) + 0x69B383F1)
    smt.add(h3 == (h2 - key[24] * 0x6B38AA) - 0x0000971317A0)
    smt.add(h4 == (h3 + key[20] * 0x5D266F) + 0x00005A4B0E60)
    smt.add(h5 == (h4 - key[8] * 0xEDC3D3) ^ 0x00000093E59AF6)
    smt.add(h6 == (h5 - key[4] * 0xB1F16C) ^ 0x000000E8D2B9A9)
    smt.add(h7 == (h6 + key[12] * 0x1C8E5B) - 0x68839283)
    smt.add(h8 == (h7 + key[28] * 0x78F67B) - 0xf53dd889)    
    smt.add(h8 == 0xfffffffe4eab225d) # + 0xFFFFFFFFA0DE7F50)

    # print(smt)
    if smt.check() == z3.sat:
        mdl = smt.model()
        flag = ''
        for i in range(32):
            c = mdl.evaluate(key[i]).as_long()
            flag += chr(c)
        
        print('[+] FLAG found:', flag)
        return flag
    else:
        raise Exception('No solution found :(')


# ----------------------------------------------------------------------------------------
def crack_key_mod_1():
    a1, a2, a3, a4, a5, a6, a7, a8 = [z3.BitVec(f'a{i}', 64) for i in range(8)]
    b1, b2, b3, b4, b5, b6, b7, b8 = [z3.BitVec(f'b{i}', 64) for i in range(8)]
    c1, c2, c3, c4, c5, c6, c7, c8 = [z3.BitVec(f'c{i}', 64) for i in range(8)]
    d1, d2, d3, d4, d5, d6, d7, d8 = [z3.BitVec(f'd{i}', 64) for i in range(8)]
    e1, e2, e3, e4, e5, e6, e7, e8 = [z3.BitVec(f'e{i}', 64) for i in range(8)]
    f1, f2, f3, f4, f5, f6, f7, f8 = [z3.BitVec(f'f{i}', 64) for i in range(8)]
    g1, g2, g3, g4, g5, g6, g7, g8 = [z3.BitVec(f'g{i}', 64) for i in range(8)]
    h1, h2, h3, h4, h5, h6, h7, h8 = [z3.BitVec(f'h{i}', 64) for i in range(8)]


    smt = z3.Solver()
    key = [z3.BitVec('key_%d' % i, 64) for i in range(32)]
    for c in key:
        smt.add( z3.And(c >= 0x20, c <= 0x7e) )

    smt.add(a1 == (key[17] * 0x99AA81) - 0x74EDEA51)
    smt.add(a2 == (a1 ^ key[5] * 0x4ABA22) + 0x000000598015BF)
    smt.add(a3 == (a2 ^ key[21] * 0x91A68A) ^ 0x006DF18E52)
    smt.add(a4 == (a3 ^ key[1] * 0x942FDE) + 0x00000015C825EE)
    smt.add(a5 == (a4 - key[13] * 0xFE2FBE) + 0x000000D5682B64)
    smt.add(a6 == (a5 - key[29] * 0xD7E52F) + 0x0000798BD018)
    smt.add(a7 == (a6 ^ key[25] * 0xE44F6A) - 0xE66D523E)
    smt.add(a8 == (a7 + key[9] * 0xAF71D) + 0x921122d3)
    #smt.add(a8 == 0xb1891234 + 0x33D70BE6)  # 0xe1148bae ??
    smt.add(a8 == 0xa40b0107)

    smt.add(b1 == (key[17] * 0xA9B448) ^ 0x00009F938499)
    smt.add(b2 == (b1 + key[5] * 0x906550) + 0x0000407021AF)
    smt.add(b3 == (b2 ^ key[13] * 0xAA5AD2) ^ 0x000077CF83A7)
    smt.add(b4 == (b3 ^ key[29] * 0xC49349) ^ 0x00003067F4E7)
    smt.add(b5 == (b4 + key[9] * 0x314F8E) + 0x00000000CD975F3B)
    smt.add(b6 == (b5 ^ key[21] * 0x81968B) + 0x0000893D2E0B)
    smt.add(b7 == (b6 - key[25] * 0x5FFBAC) ^ 0x0000F3378E3A)
    smt.add(b8 == (b7 - key[1] * 0xF63C8E)  - 0x1c1d882b)
    smt.add(b8 == 0x28e5eb48d ) #+ 0xFFFFFFFF859EB719)                  
    
    # IMPORTANT: Don't forget to check indices. Example:
    #
    #   normal 0/1 array
    #   [+] off: Ch, array at: 0x14008BAC0 ~> 0/1: 0x14, Cyclic: -   , Sub:-
    #   [+] off: Ch, array at: 0x14008B9C0 ~> 0/1: -   , Cyclic: 0xec, Sub:0xec
    #   access index: 2 0
    #   normal 0/1 array
    #   [+] off:5Eh, array at: 0x140035EC0 ~> 0/1: 0xd8, Cyclic: -   , Sub:-
    #   [+] off:5Eh, array at: 0x140035DC0 ~> 0/1: -   , Cyclic: 0x28, Sub:0x28
    #   access index: 3 2
    #   normal 0/1 array
    #   
    # We go to index 2 so, number is 0x442800ec and not 0x4428ec.
    smt.add(c1 == (key[29] * 0xE9D18A) ^ 0x000000CB5557EA)
    smt.add(c2 == (c1 ^ key[25] * 0x8AA5B9) ^ 0x00009125A906)
    smt.add(c3 == (c2 - key[17] * 0x241997) + 0x6E46FCB8)
    smt.add(c4 == (c3 + key[5] * 0xE3DA0F) + 0x442800ec) 
    smt.add(c5 == (c4 + key[13] * 0xA5F9EB) + 0x0000BDE8F9AF)
    smt.add(c6 == (c5 + key[21] * 0xD6E0FB) - 0xC9D97243)
    smt.add(c7 == (c6 + key[1] * 0x8DC36E) + 0x00C54B7D21)
    smt.add(c8 == (c7 ^ key[9] * 0xB072EE) - 0x2a1ab0c1)
    smt.add(c8 == 0x2bf2044db ) #+ 0xFFFFFFFFC7F3C165)
    
    smt.add(d1 == (key[29] * 0x725059) ^ 0x0000A8B69F6B)
    smt.add(d2 == (d1 + key[17] * 0x6DCFE7) ^ 0x0000653C249A)
    smt.add(d3 == (d2 + key[1] * 0x8F4C44) ^ 0x00000068E87685)
    smt.add(d4 == (d3 - key[9] * 0xD2F4CE) - 0x87238DC5)
    smt.add(d5 == (d4 ^ key[13] * 0xE99D3F) + 0x000000ED16797A)
    smt.add(d6 == (d5 + key[5] * 0xADA536) - 0x95A05AA9)
    smt.add(d7 == (d6 - key[25] * 0xE0B352) ^ 0x0000000043C00020) # index jump!! (not 0x43C020)
    smt.add(d8 == (d7 + key[21] * 0x8675B6) + 0x34a29213)
    smt.add(d8 == 0x20196a7e ) #+ 0xFFFFFFFFF3588894)
  
    smt.add(e1 == (key[17] * 0xFB213B) - 0x6773D643)
    smt.add(e2 == (e1 ^ key[9] * 0xDE6876) ^ 0x008649FDE3)
    smt.add(e3 == (e2 ^ key[29] * 0x629FF7) ^ 0x00A0EEB203)
    smt.add(e4 == (e3 - key[25] * 0xDBB107) ^ 0x000094AA6B62)
    smt.add(e5 == (e4 - key[1] * 0x262675) - 0xDFCF5488)
    smt.add(e6 == (e5 + key[5] * 0xD691C5) - 0x5b3ee746) # ?
    smt.add(e7 == (e6 - key[13] * 0xCAFC93) - 0x0000111BDE22) # ?
    smt.add(e8 == (e7 - key[21] * 0x81F945) - 0x90033b08)
    smt.add(e8 == 0xfffffffd6349d7cf)# + 0x4CAE6E8B)

    smt.add(f1 == (key[13] * 0x4B2D02) ^ 0x0000004B59B93A)
    smt.add(f2 == (f1 - key[9] * 0x84BB2C) ^ 0x000042D5652C)
    smt.add(f3 == (f2 ^ key[25] * 0x6F2D21) + 0x00001020133A)
    smt.add(f4 == (f3 + key[29] * 0x5FE38F) - 0x000062807B20)
    smt.add(f5 == (f4 + key[21] * 0xEA20A5) ^ 0x000060779CEB)
    smt.add(f6 == (f5 ^ key[17] * 0x5C17AA) ^ 0x00001AAF8A2D)
    smt.add(f7 == (f6 - key[5] * 0xB9FEB0) - 0x0000ADBE02FB) # ?
    smt.add(f8 == (f7 - key[1] * 0x782F79) - 0xCFC12836)
    smt.add(f8 == 0xfffffffe488d6b06 )#+ 0xFFFFFFFFEDC33C66)

    smt.add(g1 == (key[1] * 0x73AAF0) ^ 0x000000A04E34F1)
    smt.add(g2 == (g1 + key[29] * 0xF61E43) + 0x000000D09B66F3)
    smt.add(g3 == (g2 + key[25] * 0x8CB5F0) + 0x000000C11C9B4B)
    smt.add(g4 == (g3 ^ key[17] * 0x4F53A8) - 0x00006465672E) # ?
    smt.add(g5 == (g4 + key[9] * 0xB2E1FA) ^ 0x0077C07FD8)
    smt.add(g6 == (g5 - key[21] * 0xB8B7B3) - 0x882C1521)
    smt.add(g7 == (g6 + key[13] * 0x13B807) ^ 0x000000758DD142)
    smt.add(g8 == (g7 ^ key[5] * 0xDD40C4) - 0x449786e6)
    smt.add(g8 == 0x1b05dd93c ) #+ 0xFFFFFFFF117129AD) # ERROR: Add 01

    smt.add(h1 == (key[17] * 0x87184C) - 0x72A15AD8)
    smt.add(h2 == (h1 ^ key[25] * 0xF6372E) + 0x000016AD4F89)
    smt.add(h3 == (h2 - key[21] * 0xD7355C) - 0xBB20FE35)
    smt.add(h4 == (h3 ^ key[5] * 0x471DC1) ^ 0x0000572C95F4)
    smt.add(h5 == (h4 - key[1] * 0x8C4D98) - 0x94650C74)
    smt.add(h6 == (h5 - key[13] * 0x5CEEA1) ^ 0x000000F703DCC1)
    smt.add(h7 == (h6 - key[29] * 0xEB0863) + 0x0000AD3BC09D)
    smt.add(h8 == (h7 ^ key[9] * 0xB6227F) - 0x46ae6a17)  
    smt.add(h8 == 0xffffffff315e8118 )#+ 0xFFFFFFFFB95829FC)

    # print(smt)
    if smt.check() == z3.sat:
        mdl = smt.model()
        flag = ''
        for i in range(32):
            c = mdl.evaluate(key[i]).as_long()
            flag += chr(c)
        
        print('[+] FLAG found:', flag)
        return flag
    else:
        raise Exception('No solution found :(')


# ----------------------------------------------------------------------------------------
def crack_key_mod_2():
    a1, a2, a3, a4, a5, a6, a7, a8 = [z3.BitVec(f'a{i}', 64) for i in range(8)]
    b1, b2, b3, b4, b5, b6, b7, b8 = [z3.BitVec(f'b{i}', 64) for i in range(8)]
    c1, c2, c3, c4, c5, c6, c7, c8 = [z3.BitVec(f'c{i}', 64) for i in range(8)]
    d1, d2, d3, d4, d5, d6, d7, d8 = [z3.BitVec(f'd{i}', 64) for i in range(8)]
    e1, e2, e3, e4, e5, e6, e7, e8 = [z3.BitVec(f'e{i}', 64) for i in range(8)]
    f1, f2, f3, f4, f5, f6, f7, f8 = [z3.BitVec(f'f{i}', 64) for i in range(8)]
    g1, g2, g3, g4, g5, g6, g7, g8 = [z3.BitVec(f'g{i}', 64) for i in range(8)]
    h1, h2, h3, h4, h5, h6, h7, h8 = [z3.BitVec(f'h{i}', 64) for i in range(8)]

    smt = z3.Solver()
    key = [z3.BitVec('key_%d' % i, 64) for i in range(32)]
    for c in key:
        smt.add( z3.And(c >= 0x20, c <= 0x7e) )

    smt.add(a1 == (key[10] * 0x48C500) - 0x8fdaa1bc)
    smt.add(a2 == (a1 - key[30] * 0x152887) + 0x000065F04E48)
    smt.add(a3 == (a2 - key[14] * 0xAA4247) ^ 0x00003D63EC69)
    smt.add(a4 == (a3 ^ key[22] * 0x38D82D) ^ 0x000000872ECA8F)
    smt.add(a5 == (a4 ^ key[26] * 0xF120AC) + 0x00803DBDCF)
    smt.add(a6 == (a5 + key[2] * 0x254DEF) ^ 0x0000EE380DB3)
    smt.add(a7 == (a6 ^ key[18] * 0x9EF3E7) - 0x6deaa90b)
    smt.add(a8 == (a7 + key[6] * 0x69C573) - 0xc9ac5c5d)
    smt.add(a8 == 0xfffffffdf3ba3f0d) # + 0xF0F75D0)
    
    smt.add(b1 == (key[22] * 0xA6EDF9) ^ 0x00000077C58017)
    smt.add(b2 == (b1 - key[18] * 0xE87BF4) - 0x999BD740)
    smt.add(b3 == (b2 - key[2] * 0x19864D) - 0x41884BED)
    smt.add(b4 == (b3 + key[6] * 0x901524) ^ 0x0000247BF095)
    smt.add(b5 == (b4 ^ key[10] * 0xC897CC) ^ 0x0000EFF7EEA8)
    smt.add(b6 == (b5 ^ key[14] * 0x731197) + 0x000067A0D262)
    smt.add(b7 == (b6 + key[30] * 0x5F591C) + 0x00316661F9)  
    smt.add(b8 == (b7 + key[26] * 0x579D0E) - 0x3427fa1c)
    smt.add(b8 == 0x900d744b) # + 0xFFFFFFFF91261AB8)  

    smt.add(c1 == (key[30] * 0xD14F3E) ^ 0x00A06C215B)
    smt.add(c2 == (c1 - key[26] * 0xC5ECBF) + 0x0000B197C5C0)
    smt.add(c3 == (c2 ^ key[6] * 0x19FF9C) ^ 0x000066E7D06C)
    smt.add(c4 == (c3 + key[2] * 0xE3288B) ^ 0x0000000080AF4325)
    smt.add(c5 == (c4 ^ key[10] * 0xCFB18C) - 0xe13c8393) # ?
    smt.add(c6 == (c5 ^ key[18] * 0xD208E5) + 0x000000F96D2B51)
    smt.add(c7 == (c6 + key[14] * 0x42240F) - 0x8732273d) # ?
    smt.add(c8 == (c7 - key[22] * 0x1C6098) - 0xd3d45c5a) 
    smt.add(c8 == 0x0b3d7e5b) # + 0x6FBE1CD)
    
    smt.add(d1 == (key[2] * 0x4A5E95) + 0x00005ED7A1F1)
    smt.add(d2 == (d1 + key[22] * 0x3A7B49) ^ 0x0087A91310)
    smt.add(d3 == (d2 - key[6] * 0xF27038) ^ 0x00000000F64A0F19)
    smt.add(d4 == (d3 + key[30] * 0xA187D0) - 0xbbcc735d) #?
    smt.add(d5 == (d4 - key[18] * 0xFC991A) ^ 0x00000000F9DDD08F)
    smt.add(d6 == (d5 - key[26] * 0x4E947A) - 0x59a9172e) # ?
    smt.add(d7 == (d6 ^ key[14] * 0x324EAD) - 0x969a7a64) #?
    smt.add(d8 == (d7 - key[10] * 0x656B1B) + 0x8c112543)
    smt.add(d8 == 0xfffffffdc1db45c7 ) #+ 0x4BC2377C)

    smt.add(e1 == (key[10] * 0x52F44D) ^ 0x0033B3D0E4)
    smt.add(e2 == (e1 ^ key[30] * 0xE6E66E) - 0x275D79B0)
    smt.add(e3 == (e2 - key[6] * 0xF98017) ^ 0x0000456E6C1D)
    smt.add(e4 == (e3 - key[14] * 0x34FCB0) ^ 0x000028709CD8)
    smt.add(e5 == (e4 ^ key[2] * 0x4D8BA9) + 0x0000B5482F53)
    smt.add(e6 == (e5 ^ key[18] * 0x6C7E92) + 0x00002AF1D741)
    smt.add(e7 == (e6 + key[22] * 0xA4711E) ^ 0x0000000022E79AF6)
    smt.add(e8 == (e7 + key[26] * 0x33D374) - 0x117efc0e)
    smt.add(e8 == 0x9379438e) # + 0x2AA64EAE)

    smt.add(f1 == (key[6] * 0x608D19) - 0x2EEE62EC)
    smt.add(f2 == (f1 - key[14] * 0xBE18F4) ^ 0x000000B86F9B72)
    smt.add(f3 == (f2 ^ key[30] * 0x88DEC9) + 0x000000AF5CD797)
    smt.add(f4 == (f3 ^ key[18] * 0xB68150) - 0x3d073ba5) # ?
    smt.add(f5 == (f4 + key[22] * 0x4D166C) + 0x00BB1E1039)
    smt.add(f6 == (f5 - key[2] * 0x495E3F) + 0x0000E727B98E)
    smt.add(f7 == (f6 - key[10] * 0x5CABA1) - 0x00001A3CF6C1) #?
    smt.add(f8 == (f7 + key[26] * 0x183A4D) - 0xca0397e1)
    smt.add(f8 == 0x6684a31d) # + 0x59E4237)

    smt.add(g1 == (key[14] * 0xCA894B) + 0x00A34FE406)
    smt.add(g2 == (g1 + key[18] * 0x11552B) + 0x003764ECD4)
    smt.add(g3 == (g2 ^ key[22] * 0x7DC36B) + 0x00B45E777B)
    smt.add(g4 == (g3 ^ key[26] * 0xCEC5A6) ^ 0x00002D59BC15)
    smt.add(g5 == (g4 + key[30] * 0xB6E30D) ^ 0x0000FAB9788C)
    smt.add(g6 == (g5 ^ key[10] * 0x859C14) + 0x41868E54)
    smt.add(g7 == (g6 + key[6] * 0xD178D3) + 0x00958B0BE3)
    smt.add(g8 == (g7 ^ key[2] * 0x61645C) + 0x9dc814cf)
    smt.add(g8 == 0x47b801542 ) #+ 0x20B166E6)

    smt.add(h1 == (key[30] * 0x8C6412) ^ 0x0000C08C361C)
    smt.add(h2 == (h1 ^ key[14] * 0xB253C4) + 0x00000021BB1147)
    smt.add(h3 == (h2 + key[2] * 0x8F0579) - 0xFA691186)
    smt.add(h4 == (h3 - key[22] * 0x7AC48A) + 0x0000BB787DD5)
    smt.add(h5 == (h4 + key[10] * 0x2737E6) ^ 0x00A2BB7683)
    smt.add(h6 == (h5 - key[18] * 0x4363B9) ^ 0x00000088C45378)
    smt.add(h7 == (h6 ^ key[6] * 0xB38449) - 0x209DC078)
    smt.add(h8 == (h7 + key[26] * 0x6E1316) + 0x1343dee9)
    smt.add(h8 == 0xe3699527 ) #+ 0xFFFFFFFFFCB12DB6)

    # print(smt)
    if smt.check() == z3.sat:
        mdl = smt.model()
        flag = ''
        for i in range(32):            
            c = mdl.evaluate(key[i]).as_long()        
            flag += chr(c)
        
        print('[+] FLAG found:', flag)     
        return flag
    else:
        raise Exception('No solution found :(')
    
# ----------------------------------------------------------------------------------------
def crack_key_mod_3():
    a1, a2, a3, a4, a5, a6, a7, a8 = [z3.BitVec(f'a{i}', 64) for i in range(8)]
    b1, b2, b3, b4, b5, b6, b7, b8 = [z3.BitVec(f'b{i}', 64) for i in range(8)]
    c1, c2, c3, c4, c5, c6, c7, c8 = [z3.BitVec(f'c{i}', 64) for i in range(8)]
    d1, d2, d3, d4, d5, d6, d7, d8 = [z3.BitVec(f'd{i}', 64) for i in range(8)]
    e1, e2, e3, e4, e5, e6, e7, e8 = [z3.BitVec(f'e{i}', 64) for i in range(8)]
    f1, f2, f3, f4, f5, f6, f7, f8 = [z3.BitVec(f'f{i}', 64) for i in range(8)]
    g1, g2, g3, g4, g5, g6, g7, g8 = [z3.BitVec(f'g{i}', 64) for i in range(8)]
    h1, h2, h3, h4, h5, h6, h7, h8 = [z3.BitVec(f'h{i}', 64) for i in range(8)]
    
    smt = z3.Solver()
    key = [z3.BitVec('key_%d' % i, 64) for i in range(32)]
    for c in key:
        smt.add( z3.And(c >= 0x20, c <= 0x7e) )

    smt.add(a1 == (key[11] * 0x67DDA4) + 0x00F4753AFC)
    smt.add(a2 == (a1 + key[31] * 0x5BB860) ^ 0x00000000C1D47FC9)
    smt.add(a3 == (a2 ^ key[23] * 0xAB0CE5) + 0x0000544FF977)
    smt.add(a4 == (a3 + key[7] * 0x148E94) - 0x9CB3E419)
    smt.add(a5 == (a4 - key[15] * 0x9E06AE) - 0xADC62064)
    smt.add(a6 == (a5 ^ key[3] * 0xFB9DE1) ^ 0x4E3633F7)
    smt.add(a7 == (a6 - key[27] * 0xA8A511) ^ 0x00A61F9208)
    smt.add(a8 == (a7 + key[19] * 0xD3468D) + 0x4a5d7b48)
    smt.add(a8 == 0xffffffffef6412a2 ) #+ 0xD1844BB5)
    
    smt.add(b1 == (key[23] * 0x9AFAF6) ^ 0x000000DB895413)
    smt.add(b2 == (b1 + key[19] * 0x7D1A12) - 0xc679fc44) # ?
    smt.add(b3 == (b2 + key[11] * 0x4D84B1) + 0x00000000A30387DC)
    smt.add(b4 == (b3 - key[15] * 0x552B78) ^ 0x00F54A725E)
    smt.add(b5 == (b4 ^ key[7] * 0xF372A1) - 0x4C5103AD)
    smt.add(b6 == (b5 + key[31] * 0xB40EB5) ^ 0x16FA70D2)
    smt.add(b7 == (b6 ^ key[3] * 0x9E5C18) + 0x000038784353)
    smt.add(b8 == (b7 ^ key[27] * 0xF2513B) + 0xa1fc09f0)
    smt.add(b8 == 0x101d6e408) # + 0x104298C9) 
    
    smt.add(c1 == (key[11] * 0x3768CC) ^ 0x0019F61419)
    smt.add(c2 == (c1 - key[3] * 0x43BE16) + 0x000000566CC6A8)
    smt.add(c3 == (c2 ^ key[15] * 0xB7CCA5) + 0x00006DB0599E)
    smt.add(c4 == (c3 + key[27] * 0xF6419F) ^ 0x0000BD613538)
    smt.add(c5 == (c4 ^ key[19] * 0xAE52FC) + 0x0000717A44DD)
    smt.add(c6 == (c5 - key[23] * 0x5EEB81) + 0x0000DD02182D)
    smt.add(c7 == (c6 ^ key[7] * 0xEC1845) ^ 0x00EF8E5416)
    smt.add(c8 == (c7 + key[31] * 0x61A3BE) ^ 0x00009288D4FA)
    smt.add(c8 == 0x00000281BDBE05) # + 0xFFFFFFFF8FF1C639)
    
    smt.add(d1 == (key[11] * 0x251B86) + 0x0000A751192C)
    smt.add(d2 == (d1 - key[7] * 0x743927) ^ 0x00F851DA43)
    smt.add(d3 == (d2 ^ key[31] * 0x9A3479) ^ 0x0000335087A5)
    smt.add(d4 == (d3 ^ key[3] * 0x778A0D) ^ 0x00004BFD30D3)
    smt.add(d5 == (d4 - key[27] * 0x7E04B5) - 0x5d540495) # ?
    smt.add(d6 == (d5 ^ key[19] * 0xF1C3EE) + 0x00000000460C48A6)
    smt.add(d7 == (d6 + key[15] * 0x883B8A) + 0x0000007B2FFBDC)
    smt.add(d8 == (d7 + key[23] * 0x993DB1) + 0xa98b28fa)
    smt.add(d8 == 0x222087cd4 ) #+ 0xFFFFFFFF7B55360E)

    smt.add(e1 == (key[27] * 0x65AC37) + 0x000015E586B0)
    smt.add(e2 == (e1 ^ key[31] * 0xC6DDE0) ^ 0x0000002354CAD4)
    smt.add(e3 == (e2 ^ key[15] * 0x154ABD) ^ 0x00FEE57FD5)
    smt.add(e4 == (e3 ^ key[19] * 0xA5E467) + 0x000000315624EF)
    smt.add(e5 == (e4 ^ key[23] * 0xB6BED6) - 0x5285b0a5) # ?
    smt.add(e6 == (e5 - key[7] * 0x832AE7) + 0x000000E961BEDD)
    smt.add(e7 == (e6 + key[11] * 0xC46330) - 0x4A9E1D65)
    smt.add(e8 == (e7 ^ key[3] * 0x3F8467) ^ 0x00000095A6A1C4)
    smt.add(e8 == 0x1110e3519 ) #+ 0xFFFFFFFFF641BF83)

    smt.add(f1 == (key[11] * 0xFFD0CA) - 0x8F26CEE8)
    smt.add(f2 == (f1 ^ key[7] * 0xBF2B59) + 0x00C76BAD6E)
    smt.add(f3 == (f2 + key[23] * 0x29DF01) + 0x00EEF034A2)
    smt.add(f4 == (f3 ^ key[27] * 0xBBDA1D) + 0x5923194E)
    smt.add(f5 == (f4 - key[31] * 0x5D24A5) - 0x81100799) # ?
    smt.add(f6 == (f5 + key[15] * 0x3DC505) - 0x69BAEE91)
    smt.add(f7 == (f6 ^ key[19] * 0x4E25A6) + 0x00002468B30A)
    smt.add(f8 == (f7 - key[3] * 0xAE1920) ^ 0x00D3DB6142)
    smt.add(f8 == 0x1bb7af00f ) #+ 0xFFFFFFFEAD422519)

    smt.add(g1 == (key[27] * 0x7239E9) - 0x760E5ADA)
    smt.add(g2 == (g1 - key[3] * 0xF1C3D1) - 0xEF28A068)
    smt.add(g3 == (g2 ^ key[11] * 0x1B1367) ^ 0x0000000031E00D5A)
    smt.add(g4 == (g3 ^ key[19] * 0x8038B3) + 0x00B5163447)
    smt.add(g5 == (g4 + key[31] * 0x65FAC9) + 0x0000E04A889A)
    smt.add(g6 == (g5 - key[23] * 0xD845CA) - 0xab7d1c58) # ?
    smt.add(g7 == (g6 + key[15] * 0xB2BBBC) ^ 0x3A017B92)
    smt.add(g8 == (g7 ^ key[7] * 0x33C8BD) + 0x540376e3)
    smt.add(g8 == 0xffffffffb0e80c93 )#+ 0x7A4DDFD)

    smt.add(h1 == (key[19] * 0x390B78) + 0x0000007D5DEEA4)
    smt.add(h2 == (h1 - key[15] * 0x70E6C8) - 0x6EA339E2)
    smt.add(h3 == (h2 ^ key[27] * 0xD8A292) - 0x288D6EC5)
    smt.add(h4 == (h3 - key[23] * 0x978C71) - 0xe5d85ed8) # ?
    smt.add(h5 == (h4 + key[31] * 0x9A14D4) - 0xB69670CC)
    smt.add(h6 == (h5 ^ key[7] * 0x995144) - 0xd2e77342) # ?
    smt.add(h7 == (h6 ^ key[11] * 0x811C39) - 0x2dd03565) # ?
    smt.add(h8 == (h7 ^ key[3] * 0x9953D7) ^ 0x0080877669)
    smt.add(h8 == 0xfffffffdf9422478 ) #+ 0xFFFFFFFE652ED9F5)

    # print(smt)
    if smt.check() == z3.sat:
        mdl = smt.model()
        flag = ''
        for i in range(32):
            c = mdl.evaluate(key[i]).as_long()
            flag += chr(c)
        
        print('[+] FLAG found:', flag)
        return flag
    else:
        raise Exception('No solution found :(')
    

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print(f'[+] Serpentine eq solver started.')

    flag0 = crack_key_mod_0()
    flag1 = crack_key_mod_1()
    flag2 = crack_key_mod_2()
    flag3 = crack_key_mod_3()

    flag = ''
    for i in range(32):
        flag += eval(f'flag{i % 4}[i]')

    print(f'[+] Final FLAG: {flag}@flare-on.com')

# ----------------------------------------------------------------------------------------
r"""
┌─[02:08:27]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/09_serpentine]
└──> time ./serpentine_eq_solver.py
[+] Serpentine eq solver started.
[+] FLAG found: $  @l @@5 @ e@@ o @ g  @d@@@v@@@
[+] FLAG found:  $ @@w   _@@@p   v@@@_@@@_   i @
[+] FLAG found: @ _  @a   k @ _@  1@@ a@ @m @ n 
[+] FLAG found:  @ 4   y @ 3 @ m  @n@ @n @@0@@@g
[+] Final FLAG: $$_4lway5_k3ep_mov1ng_and_m0ving@flare-on.com

real    0m2.276s
user    0m2.225s
sys 0m0.049s
"""
# ----------------------------------------------------------------------------------------
