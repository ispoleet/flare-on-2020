## Flare-On 2024 - #3 aray
___

### Description: 

*And now for something completely different.*
*I'm pretty sure you know how to write Yara rules, but can you reverse them?*

`7-zip password: flare`
___

### Solution:

In the third challenge we are given a huge yara rule that verifies the flag:
```
import "hash"

rule aray
{
    meta:
        description = "Matches on b7dc94ca98aa58dabb5404541c812db2"
    condition:
        filesize == 85 and hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and filesize ^ uint8(11) != 107 and
        /* ... MANY MORE CHECKS ... */ and
        uint8(8) > 3
}
```

The flag is in a file which is **85** bytes long and its **MD5** checksum is
`b7dc94ca98aa58dabb5404541c812db2`. There are also many conditions that check individual aspects
of the flag file. There is an `and` keyword between each check, so we can split them into multiple
lines (so we have one check per line) and then sort them:
```c
 filesize == 85 and
 filesize ^ uint8(0) != 16 and
 filesize ^ uint8(0) != 41 and
 filesize ^ uint8(10) != 205 and
 filesize ^ uint8(10) != 44 and
 filesize ^ uint8(1) != 0 and
 filesize ^ uint8(11) != 107 and
 filesize ^ uint8(11) != 33 and
 filesize ^ uint8(12) != 116 and
 filesize ^ uint8(12) != 226 and
 filesize ^ uint8(1) != 232 and
 filesize ^ uint8(13) != 219 and
 filesize ^ uint8(13) != 42 and
 filesize ^ uint8(14) != 161 and
 filesize ^ uint8(14) != 99 and
 filesize ^ uint8(15) != 205 and
 filesize ^ uint8(15) != 27 and
 filesize ^ uint8(16) != 144 and
 filesize ^ uint8(16) != 7 and
 filesize ^ uint8(17) != 16 and
 filesize ^ uint8(17) != 208 and
 filesize ^ uint8(18) != 234 and
 filesize ^ uint8(18) != 33 and
 filesize ^ uint8(19) != 222 and
 filesize ^ uint8(19) != 31 and
 filesize ^ uint8(20) != 17 and
 filesize ^ uint8(20) != 83 and
 filesize ^ uint8(21) != 188 and
 filesize ^ uint8(21) != 27 and
 filesize ^ uint8(2) != 205 and
 filesize ^ uint8(22) != 191 and
 filesize ^ uint8(22) != 31 and
 filesize ^ uint8(23) != 18 and
 filesize ^ uint8(23) != 242 and
 filesize ^ uint8(24) != 217 and
 filesize ^ uint8(24) != 94 and
 filesize ^ uint8(25) != 224 and
 filesize ^ uint8(25) != 47 and
 filesize ^ uint8(2) != 54 and
 filesize ^ uint8(26) != 161 and
 filesize ^ uint8(26) != 44 and
 filesize ^ uint8(27) != 244 and
 filesize ^ uint8(27) != 43 and
 filesize ^ uint8(28) != 12 and
 filesize ^ uint8(28) != 238 and
 filesize ^ uint8(29) != 158 and
 filesize ^ uint8(29) != 37 and
 filesize ^ uint8(30) != 18 and
 filesize ^ uint8(30) != 249 and
 filesize ^ uint8(31) != 32 and
 filesize ^ uint8(3) != 147 and
 filesize ^ uint8(31) != 5 and
 filesize ^ uint8(32) != 30 and
 filesize ^ uint8(32) != 77 and
 filesize ^ uint8(33) != 157 and
 filesize ^ uint8(33) != 27 and
 filesize ^ uint8(34) != 115 and
 filesize ^ uint8(34) != 39 and
 filesize ^ uint8(3) != 43 and
 filesize ^ uint8(35) != 120 and
 filesize ^ uint8(35) != 18 and
 filesize ^ uint8(36) != 6 and
 filesize ^ uint8(36) != 95 and
 filesize ^ uint8(37) != 141 and
 filesize ^ uint8(37) != 37 and
 filesize ^ uint8(38) != 84 and
 filesize ^ uint8(38) != 8 and
 filesize ^ uint8(39) != 18 and
 filesize ^ uint8(39) != 49 and
 filesize ^ uint8(40) != 230 and
 filesize ^ uint8(40) != 49 and
 filesize ^ uint8(41) != 233 and
 filesize ^ uint8(41) != 74 and
 filesize ^ uint8(42) != 1 and
 filesize ^ uint8(4) != 23 and
 filesize ^ uint8(4) != 253 and
 filesize ^ uint8(42) != 91 and
 filesize ^ uint8(43) != 251 and
 filesize ^ uint8(43) != 33 and
 filesize ^ uint8(44) != 17 and
 filesize ^ uint8(44) != 96 and
 filesize ^ uint8(45) != 146 and
 filesize ^ uint8(45) != 19 and
 filesize ^ uint8(46) != 186 and
 filesize ^ uint8(46) != 18 and
 filesize ^ uint8(47) != 119 and
 filesize ^ uint8(47) != 11 and
 filesize ^ uint8(48) != 29 and
 filesize ^ uint8(48) != 99 and
 filesize ^ uint8(49) != 10 and
 filesize ^ uint8(49) != 156 and
 filesize ^ uint8(50) != 219 and
 filesize ^ uint8(50) != 86 and
 filesize ^ uint8(51) != 0 and
 filesize ^ uint8(51) != 204 and
 filesize ^ uint8(52) != 22 and
 filesize ^ uint8(52) != 238 and
 filesize ^ uint8(5) != 243 and
 filesize ^ uint8(53) != 19 and
 filesize ^ uint8(53) != 243 and
 filesize ^ uint8(54) != 141 and
 filesize ^ uint8(54) != 39 and
 filesize ^ uint8(5) != 43 and
 filesize ^ uint8(55) != 17 and
 filesize ^ uint8(55) != 244 and
 filesize ^ uint8(56) != 22 and
 filesize ^ uint8(56) != 246 and
 filesize ^ uint8(57) != 14 and
 filesize ^ uint8(57) != 186 and
 filesize ^ uint8(58) != 12 and
 filesize ^ uint8(58) != 77 and
 filesize ^ uint8(59) != 13 and
 filesize ^ uint8(59) != 194 and
 filesize ^ uint8(60) != 142 and
 filesize ^ uint8(60) != 43 and
 filesize ^ uint8(61) != 239 and
 filesize ^ uint8(6) != 129 and
 filesize ^ uint8(61) != 94 and
 filesize ^ uint8(62) != 15 and
 filesize ^ uint8(62) != 246 and
 filesize ^ uint8(63) != 135 and
 filesize ^ uint8(63) != 34 and
 filesize ^ uint8(6) != 39 and
 filesize ^ uint8(64) != 158 and
 filesize ^ uint8(64) != 50 and
 filesize ^ uint8(65) != 215 and
 filesize ^ uint8(65) != 28 and
 filesize ^ uint8(66) != 146 and
 filesize ^ uint8(66) != 51 and
 filesize ^ uint8(67) != 55 and
 filesize ^ uint8(67) != 63 and
 filesize ^ uint8(68) != 135 and
 filesize ^ uint8(68) != 8 and
 filesize ^ uint8(69) != 241 and
 filesize ^ uint8(69) != 30 and
 filesize ^ uint8(70) != 209 and
 filesize ^ uint8(70) != 41 and
 filesize ^ uint8(71) != 128 and
 filesize ^ uint8(71) != 3 and
 filesize ^ uint8(7) != 15 and
 filesize ^ uint8(72) != 219 and
 filesize ^ uint8(7) != 221 and
 filesize ^ uint8(72) != 37 and
 filesize ^ uint8(73) != 17 and
 filesize ^ uint8(73) != 61 and
 filesize ^ uint8(74) != 193 and
 filesize ^ uint8(74) != 45 and
 filesize ^ uint8(75) != 25 and
 filesize ^ uint8(75) != 35 and
 filesize ^ uint8(76) != 30 and
 filesize ^ uint8(76) != 88 and
 filesize ^ uint8(77) != 223 and
 filesize ^ uint8(77) != 22 and
 filesize ^ uint8(78) != 163 and
 filesize ^ uint8(78) != 6 and
 filesize ^ uint8(79) != 104 and
 filesize ^ uint8(79) != 186 and
 filesize ^ uint8(80) != 236 and
 filesize ^ uint8(80) != 56 and
 filesize ^ uint8(8) != 107 and
 filesize ^ uint8(81) != 242 and
 filesize ^ uint8(81) != 7 and
 filesize ^ uint8(82) != 228 and
 filesize ^ uint8(82) != 32 and
 filesize ^ uint8(8) != 2 and
 filesize ^ uint8(83) != 197 and
 filesize ^ uint8(83) != 31 and
 filesize ^ uint8(84) != 231 and
 filesize ^ uint8(84) != 3 and
 filesize ^ uint8(9) != 164 and
 filesize ^ uint8(9) != 5 and
 hash.crc32(34, 2) == 0x5888fc1b and
 hash.crc32(63, 2) == 0x66715919 and
 hash.crc32(78, 2) == 0x7cab8d64 and
 hash.crc32(8, 2) == 0x61089c5c and
 hash.md5(0, 2) == "89484b14b36a8d5329426a3d944d2983" and
 hash.md5(0, filesize) == "b7dc94ca98aa58dabb5404541c812db2" and
 hash.md5(32, 2) == "738a656e8e8ec272ca17cd51e12f558b" and
 hash.md5(50, 2) == "657dae0913ee12be6fb2a6f687aae1c7" and
 hash.md5(76, 2) == "f98ed07a4d5f50f7de1410d905f1477f" and
 hash.sha256(14, 2) == "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f" and
 hash.sha256(56, 2) == "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6" and
 uint32(10) + 383041523 == 2448764514 and
 uint32(17) - 323157430 == 1412131772 and
 uint32(22) ^ 372102464 == 1879700858 and
 uint32(28) - 419186860 == 959764852 and
 uint32(3) ^ 298697263 == 2108416586 and
 uint32(37) + 367943707 == 1228527996 and
 uint32(41) + 404880684 == 1699114335 and
 uint32(46) - 412326611 == 1503714457 and
 uint32(52) ^ 425706662 == 1495724241 and
 uint32(59) ^ 512952669 == 1908304943 and
 uint32(66) ^ 310886682 == 849718389 and
 uint32(70) + 349203301 == 2034162376 and
 uint32(80) - 473886976 == 69677856 and
 uint8(0) & 128 == 0 and
 uint8(0) < 129 and
 uint8(0) % 25 < 25 and
 uint8(0) > 30 and
 uint8(10) % 10 < 10 and
 uint8(10) & 128 == 0 and
 uint8(10) < 146 and
 uint8(10) > 9 and
 uint8(11) & 128 == 0 and
 uint8(11) < 154 and
 uint8(11) > 18 and
 uint8(11) % 27 < 27 and
 uint8(1) & 128 == 0 and
 uint8(1) < 158 and
 uint8(1) % 17 < 17 and
 uint8(1) > 19 and
 uint8(12) & 128 == 0 and
 uint8(12) < 147 and
 uint8(12) > 19 and
 uint8(12) % 23 < 23 and
 uint8(13) & 128 == 0 and
 uint8(13) < 147 and
 uint8(13) > 21 and
 uint8(13) % 27 < 27 and
 uint8(14) & 128 == 0 and
 uint8(14) < 153 and
 uint8(14) % 19 < 19 and
 uint8(14) > 20 and
 uint8(15) & 128 == 0 and
 uint8(15) < 156 and
 uint8(15) % 16 < 16 and
 uint8(15) > 26 and
 uint8(16) & 128 == 0 and
 uint8(16) < 134 and
 uint8(16) > 25 and
 uint8(16) % 31 < 31 and
 uint8(16) ^ 7 == 115 and
 uint8(17) % 11 < 11 and
 uint8(17) & 128 == 0 and
 uint8(17) < 150 and
 uint8(17) > 31 and
 uint8(18) & 128 == 0 and
 uint8(18) < 137 and
 uint8(18) > 13 and
 uint8(18) % 30 < 30 and
 uint8(19) & 128 == 0 and
 uint8(19) < 151 and
 uint8(19) % 30 < 30 and
 uint8(19) > 4 and
 uint8(20) & 128 == 0 and
 uint8(20) < 135 and
 uint8(20) > 1 and
 uint8(20) % 28 < 28 and
 uint8(21) % 11 < 11 and
 uint8(2) + 11 == 119 and
 uint8(21) & 128 == 0 and
 uint8(21) < 138 and
 uint8(21) - 21 == 94 and
 uint8(2) & 128 == 0 and
 uint8(2) < 147 and
 uint8(21) > 7 and
 uint8(2) > 20 and
 uint8(22) & 128 == 0 and
 uint8(22) < 152 and
 uint8(22) > 20 and
 uint8(22) % 22 < 22 and
 uint8(2) % 28 < 28 and
 uint8(23) & 128 == 0 and
 uint8(23) < 141 and
 uint8(23) % 16 < 16 and
 uint8(23) > 2 and
 uint8(24) & 128 == 0 and
 uint8(24) < 148 and
 uint8(24) > 22 and
 uint8(24) % 26 < 26 and
 uint8(25) & 128 == 0 and
 uint8(25) < 154 and
 uint8(25) % 23 < 23 and
 uint8(25) > 27 and
 uint8(26) & 128 == 0 and
 uint8(26) < 132 and
 uint8(26) % 25 < 25 and
 uint8(26) > 31 and
 uint8(26) - 7 == 25 and
 uint8(27) & 128 == 0 and
 uint8(27) < 147 and
 uint8(27) ^ 21 == 40 and
 uint8(27) > 23 and
 uint8(27) % 26 < 26 and
 uint8(28) & 128 == 0 and
 uint8(28) < 160 and
 uint8(28) % 27 < 27 and
 uint8(28) > 27 and
 uint8(29) % 12 < 12 and
 uint8(29) & 128 == 0 and
 uint8(29) < 157 and
 uint8(29) > 22 and
 uint8(30) & 128 == 0 and
 uint8(30) < 131 and
 uint8(30) % 15 < 15 and
 uint8(30) > 6 and
 uint8(31) & 128 == 0 and
 uint8(31) < 145 and
 uint8(31) % 17 < 17 and
 uint8(3) & 128 == 0 and
 uint8(3) % 13 < 13 and
 uint8(3) < 141 and
 uint8(31) > 7 and
 uint8(32) & 128 == 0 and
 uint8(32) < 140 and
 uint8(32) % 17 < 17 and
 uint8(3) > 21 and
 uint8(32) > 28 and
 uint8(33) & 128 == 0 and
 uint8(33) < 160 and
 uint8(33) > 18 and
 uint8(33) % 25 < 25 and
 uint8(34) & 128 == 0 and
 uint8(34) < 138 and
 uint8(34) > 18 and
 uint8(34) % 19 < 19 and
 uint8(35) & 128 == 0 and
 uint8(35) % 15 < 15 and
 uint8(35) < 160 and
 uint8(35) > 1 and
 uint8(36) > 11 and
 uint8(36) & 128 == 0 and
 uint8(36) < 146 and
 uint8(36) % 22 < 22 and
 uint8(36) + 4 == 72 and
 uint8(37) & 128 == 0 and
 uint8(37) < 139 and
 uint8(37) > 16 and
 uint8(37) % 19 < 19 and
 uint8(38) & 128 == 0 and
 uint8(38) < 135 and
 uint8(38) > 18 and
 uint8(38) % 24 < 24 and
 uint8(39) % 11 < 11 and
 uint8(39) & 128 == 0 and
 uint8(39) < 134 and
 uint8(39) > 7 and
 uint8(40) & 128 == 0 and
 uint8(40) < 131 and
 uint8(40) > 15 and
 uint8(40) % 19 < 19 and
 uint8(41) & 128 == 0 and
 uint8(41) < 140 and
 uint8(41) % 27 < 27 and
 uint8(4) & 128 == 0 and
 uint8(4) < 139 and
 uint8(41) > 5 and
 uint8(4) % 17 < 17 and
 uint8(42) & 128 == 0 and
 uint8(42) < 157 and
 uint8(42) % 17 < 17 and
 uint8(42) > 3 and
 uint8(4) > 30 and
 uint8(43) & 128 == 0 and
 uint8(43) < 160 and
 uint8(43) > 24 and
 uint8(43) % 26 < 26 and
 uint8(44) & 128 == 0 and
 uint8(44) < 147 and
 uint8(44) % 27 < 27 and
 uint8(44) > 5 and
 uint8(45) & 128 == 0 and
 uint8(45) < 136 and
 uint8(45) % 17 < 17 and
 uint8(45) > 17 and
 uint8(45) ^ 9 == 104 and
 uint8(46) & 128 == 0 and
 uint8(46) < 154 and
 uint8(46) > 22 and
 uint8(46) % 28 < 28 and
 uint8(47) & 128 == 0 and
 uint8(47) > 13 and
 uint8(47) < 142 and
 uint8(47) % 18 < 18 and
 uint8(48) % 12 < 12 and
 uint8(48) & 128 == 0 and
 uint8(48) < 136 and
 uint8(48) > 15 and
 uint8(49) & 128 == 0 and
 uint8(49) < 129 and
 uint8(49) % 13 < 13 and
 uint8(49) > 27 and
 uint8(50) % 11 < 11 and
 uint8(50) & 128 == 0 and
 uint8(50) < 138 and
 uint8(50) > 19 and
 uint8(51) & 128 == 0 and
 uint8(51) < 139 and
 uint8(51) % 15 < 15 and
 uint8(5) & 128 == 0 and
 uint8(5) > 14 and
 uint8(5) < 158 and
 uint8(51) > 7 and
 uint8(52) & 128 == 0 and
 uint8(52) < 136 and
 uint8(52) % 23 < 23 and
 uint8(52) > 25 and
 uint8(5) % 27 < 27 and
 uint8(53) & 128 == 0 and
 uint8(53) < 144 and
 uint8(53) % 23 < 23 and
 uint8(53) > 24 and
 uint8(54) & 128 == 0 and
 uint8(54) < 152 and
 uint8(54) > 15 and
 uint8(54) % 25 < 25 and
 uint8(55) % 11 < 11 and
 uint8(55) & 128 == 0 and
 uint8(55) < 153 and
 uint8(55) > 5 and
 uint8(56) & 128 == 0 and
 uint8(56) < 155 and
 uint8(56) % 26 < 26 and
 uint8(56) > 8 and
 uint8(57) > 11 and
 uint8(57) & 128 == 0 and
 uint8(57) < 138 and
 uint8(57) % 27 < 27 and
 uint8(58) & 128 == 0 and
 uint8(58) % 14 < 14 and
 uint8(58) < 146 and
 uint8(58) + 25 == 122 and
 uint8(58) > 30 and
 uint8(59) & 128 == 0 and
 uint8(59) < 141 and
 uint8(59) % 23 < 23 and
 uint8(59) > 4 and
 uint8(60) & 128 == 0 and
 uint8(60) < 130 and
 uint8(60) > 14 and
 uint8(60) % 23 < 23 and
 uint8(61) & 128 == 0 and
 uint8(61) > 12 and
 uint8(61) < 160 and
 uint8(6) % 12 < 12 and
 uint8(61) % 26 < 26 and
 uint8(6) & 128 == 0 and
 uint8(6) < 155 and
 uint8(62) & 128 == 0 and
 uint8(62) % 13 < 13 and
 uint8(62) < 146 and
 uint8(62) > 1 and
 uint8(63) & 128 == 0 and
 uint8(63) < 129 and
 uint8(63) % 30 < 30 and
 uint8(63) > 31 and
 uint8(64) & 128 == 0 and
 uint8(64) < 154 and
 uint8(64) % 24 < 24 and
 uint8(64) > 27 and
 uint8(65) & 128 == 0 and
 uint8(65) < 149 and
 uint8(65) > 1 and
 uint8(65) % 22 < 22 and
 uint8(65) - 29 == 70 and
 uint8(66) & 128 == 0 and
 uint8(66) < 133 and
 uint8(66) % 16 < 16 and
 uint8(66) > 30 and
 uint8(6) > 6 and
 uint8(67) & 128 == 0 and
 uint8(67) < 144 and
 uint8(67) % 16 < 16 and
 uint8(67) > 27 and
 uint8(68) > 10 and
 uint8(68) & 128 == 0 and
 uint8(68) < 138 and
 uint8(68) % 19 < 19 and
 uint8(69) & 128 == 0 and
 uint8(69) < 148 and
 uint8(69) > 25 and
 uint8(69) % 30 < 30 and
 uint8(70) & 128 == 0 and
 uint8(70) < 139 and
 uint8(70) % 21 < 21 and
 uint8(70) > 6 and
 uint8(71) & 128 == 0 and
 uint8(71) < 130 and
 uint8(71) > 19 and
 uint8(7) % 12 < 12 and
 uint8(7) & 128 == 0 and
 uint8(71) % 28 < 28 and
 uint8(7) < 131 and
 uint8(7) - 15 == 82 and
 uint8(7) > 18 and
 uint8(72) > 10 and
 uint8(72) & 128 == 0 and
 uint8(72) < 134 and
 uint8(72) % 14 < 14 and
 uint8(73) & 128 == 0 and
 uint8(73) < 136 and
 uint8(73) % 23 < 23 and
 uint8(73) > 26 and
 uint8(74) % 10 < 10 and
 uint8(74) + 11 == 116 and
 uint8(74) & 128 == 0 and
 uint8(74) < 152 and
 uint8(74) > 1 and
 uint8(75) & 128 == 0 and
 uint8(75) < 142 and
 uint8(75) % 24 < 24 and
 uint8(75) - 30 == 86 and
 uint8(75) > 30 and
 uint8(76) & 128 == 0 and
 uint8(76) < 156 and
 uint8(76) % 24 < 24 and
 uint8(76) > 2 and
 uint8(77) & 128 == 0 and
 uint8(77) < 154 and
 uint8(77) % 24 < 24 and
 uint8(77) > 5 and
 uint8(78) & 128 == 0 and
 uint8(78) % 13 < 13 and
 uint8(78) < 141 and
 uint8(78) > 24 and
 uint8(79) & 128 == 0 and
 uint8(79) < 146 and
 uint8(79) % 24 < 24 and
 uint8(79) > 31 and
 uint8(80) & 128 == 0 and
 uint8(80) < 143 and
 uint8(80) > 2 and
 uint8(80) % 31 < 31 and
 uint8(81) > 11 and
 uint8(81) & 128 == 0 and
 uint8(81) < 131 and
 uint8(81) % 14 < 14 and
 uint8(8) & 128 == 0 and
 uint8(8) < 133 and
 uint8(8) % 21 < 21 and
 uint8(82) & 128 == 0 and
 uint8(82) < 152 and
 uint8(82) % 28 < 28 and
 uint8(82) > 3 and
 uint8(8) > 3
 uint8(83) & 128 == 0 and
 uint8(83) < 134 and
 uint8(83) > 16 and
 uint8(83) % 21 < 21 and
 uint8(84) & 128 == 0 and
 uint8(84) < 129 and
 uint8(84) % 18 < 18 and
 uint8(84) > 26 and
 uint8(84) + 3 == 128 and
 uint8(9) & 128 == 0 and
 uint8(9) < 151 and
 uint8(9) % 22 < 22 and
 uint8(9) > 23 and
 ```

Now it is much easier to understand what these conditions check. We convert each condition into
a constraint and we add it to z3. The file that satisfies all the constraints has the following
contents:
```
rule flareon { strings: $f = "1RuleADayK33p$Malw4r3Aw4y@flare-on.com" condition: $f }
```

For more details, please take a look at the [aray_crack.py](./aray_crack.py) script.

So the flag is: `1RuleADayK33p$Malw4r3Aw4y@flare-on.com`
___
