## Flare-On 2024 - #6 bloke2
___

### Description: 

*You've been so helpful lately, and that was very good work you did.*
*Yes, I'm going to put it right here, on the refrigerator, very good job indeed.*
*You're the perfect person to help me with another issue that come up.*
*One of our lab researchers has mysteriously disappeared.*
*He was working on the prototype for a hashing IP block that worked very much like, but not identically to, the common Blake2 hash family.*
*Last we heard from him, he was working on the testbenches for the unit.*
*One of his labmates swears she knew of a secret message that could be extracted with the testbenches, but she couldn't quite recall how to trigger it.*
*Maybe you could help?*

`7-zip password: flare`
___

### Solution:

This was an easy challenge. But we have to read carefully the description. **Very** carefully.

Let's first understand how verilog works:
[Verilog 2: Language Basics](https://www.ece.ucdavis.edu/~bbaas/281/notes/Handout12.verilog2.pdf).
In verilog all instructions are executed in parallel, so it requires some effort to understand
the code.

Program implements a hash function which is *"very much like, but not identically to, the common
Blake2 hash family"*. [This](https://gist.github.com/sooryan/8d1b2c19bf0b971c11366b0680908d4b)
article provides a good explanation of how Blake2 works. Given that we start reading the source
code:
```
-rw-r----- 1 ispo primarygroup 2611 Sep 11 18:23 bloke2b_tb.v
-rw-r----- 1 ispo primarygroup  725 Sep 10 16:23 bloke2b.v
-rw-r----- 1 ispo primarygroup 2611 Sep 11 18:23 bloke2s_tb.v
-rw-r----- 1 ispo primarygroup  658 Sep 10 15:42 bloke2s.v
-rw-r----- 1 ispo primarygroup 1734 Sep 10 16:21 bloke2.v
-rw-r----- 1 ispo primarygroup 2098 Sep 10 16:45 data_mgr.v
-rw-r----- 1 ispo primarygroup 1497 Sep 11 17:25 f_sched_tb.v
-rw-r----- 1 ispo primarygroup 1129 Sep 11 17:21 f_sched.v
-rw-r----- 1 ispo primarygroup 2001 Sep 10 16:42 f_unit.v
-rw-r----- 1 ispo primarygroup  632 Oct  1 21:02 g_over_2.v
-rw-r----- 1 ispo primarygroup 1172 Sep 10 05:24 g_unit.v
-rw-r----- 1 ispo primarygroup  691 Sep 10 05:24 g.v
```

**There must be an (obviously encrypted) flag somewhere.** The only interesting file in the code
is `data_mgr.v`:
```verilog
module data_mgr #(
    parameter W=32
) (
    input clk,
    input rst,

    input [7:0] data_in,
    input       dv_in,
    output      drdy_out,
    input       start,
    input       finish,

    output              msg_strobe,
    output [(W*16)-1:0] m_out,
    output [(W*2)-1:0]  t_out,
    output              f_out,

    input [(W*8)-1:0] h_in,
    input             h_rdy,

    output [7:0] data_out,
    output       dv_out,
    output       data_end
);
    //
    // .....
    //

    localparam TEST_VAL = 512'h3c9cf0addf2e45ef548b011f736cc99144bdfee0d69df4090c8a39c520e18ec3bdc1277aad1706f756affca41178dac066e4beb8ab7dd2d1402c4d624aaabe40;

    reg [(W*8)-1:0] h;
    reg [$clog2(W):0] out_cnt;
    assign data_out = h[7:0];
    assign dv_out = (out_cnt != 0);
    assign data_end = (out_cnt == 1);

    always @(posedge clk) begin
        if (rst) begin 
            out_cnt <= 0;
        end else begin
            //$display("%t dmgr dout oc %h", $time, out_cnt);
            if (h_rdy) begin
                //$display("%t dmgr dout h %h t %b", $time, h_in, tst);
                out_cnt <= W;
                h <= h_in ^ (TEST_VAL & {(W*16){tst}});
            end else if(out_cnt != 0) begin
                //$display("%t dmgr dout d %h dv %b de %b oc %h", $time, data_out, dv_out, data_end, out_cnt);
                out_cnt <= out_cnt - 1;
                h <= {8'b0, h[W*8-1:8]};
            end
        end
    end
endmodule
```

The following hash should be the encrypted flag:
```
h3c9cf0addf2e45ef548b011f736cc99144bdfee0d69df4090c8a39c520e18ec3bdc1277aad1706f756affca41178dac066e4beb8ab7dd2d1402c4d624aaabe40
```

Now let's check the description again: *"...she knew of a secret message that could be extracted
with the testbenches, but she couldn't quite recall how to trigger it."*. That means there is
something in the tests (i.e., the `_tb.v` files) that we should modify.

Let's go back to `data_mgr.v` to see where `TEST_VAL` is used:
```verilog
h <= h_in ^ (TEST_VAL & {(W*16){tst}});
```

There is a special `tst` flag: If it is 0, The `TEST_VAL` **AND'd** with zeros, so it becomes zero
and `h = h_in` (i.e., it has no effect). But if `tst` is **1**, then `TEST_VAL` is being used
(but we do not know how; we can uncomment `$display` and run the tests to understand more about
the program).

We run the tests:
```
┌─[23:38:18]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/06_bloke2/test]
└──> make tests
vvp  f_sched.test.out
vvp  bloke2b.test.out
Received message: 7ց    �A�&�377��S��3��
                                        ���2���&E�}'<���Y|N��:'�ԟ��,ً�� �6�A��C6
Received message: �q]y8��B��y��#>[��qi܊wRg��:���0�����$E���w�5CU��M-���
Received message: 0��+(s3����ۈ��'pɣ�$�vg�x�Ӝ�C�_�je������0��3ym�&�hA����Q
vvp  bloke2s.test.out
Received message:                                 ��F3��p���٨�p�{3xM�%���=W��� 
Received message:                                 n��(� � �F�r�c��@lu�s�fFvr
Received message:                                 
                                                  ��a$�a�b��}���\�H��O?w�`?εb
```

Now let's comment out the effects of `tst` in `data_mgr.v`:
```verilog
h <= h_in ^ (TEST_VAL);// & {(W*16){tst}});
```

We run the tests again:
```
┌─[23:38:25]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/flare-on-challenges/flare-on-2024/06_bloke2/test]
└──> make tests
vvp  f_sched.test.out
iverilog -g2012 -o bloke2b.test.out bloke2.v f_sched.v f_unit.v g_over_2.v g.v g_unit.v data_mgr.v bloke2s.v bloke2b.v bloke2b_tb.v
vvp  bloke2b.test.out
Received message: wh+C�
                       �fD�J�Th��1���Pv�ŝ�~\b'��6�'`�B�0��{*"�[�������o�K�

Received message: X�mB:V��i�c![/�wK'�ڝ�(@<�Q�\�
                                                =�.��W��JZ���h���Β�?\�
Received message: please_send_help_i_am_trapped_in_a_ctf_flag_factory@flare-on.com
iverilog -g2012 -o bloke2s.test.out bloke2.v f_sched.v f_unit.v g_over_2.v g.v g_unit.v data_mgr.v bloke2s.v bloke2b.v bloke2s_tb.v
vvp  bloke2s.test.out
Received message:                                 �J�
                                                     Q��0]_�rD��� \F٬�?�*���-�
Received message:                                 .Tba�2I(�xq�
�̣;���ڦ`u��<)��
Received message:                                 L#��m,.d������lb$��P�q��E�t�
```

And we get the flag!

Another way to solve is to follow the challenge description and modify the `finish` line 
(i.e., change it to `finish <= 1'b1;`) in `bloke2b_tb`:
```verilog
    // Run a string through the hash machine.
    task hash_message (
        input [1023:0] msg
    );
        integer i, len;
    begin
        // Ugh, working around a bug in old Icarus Verilog 10.x which
        // prevents the use of proper strings here.  Get the string
        // length because the string literal comes in backwards.
        for (i = 0; msg[8*i +: 8] != 0; i++); len = i;

        // Set our start and finish lines correctly.
        start <= 1'b1;
        finish <= 1'b0; // Change it from: finish <= 1'b0; 
        @(posedge clk);
        start <= 1'b0;
        finish <= 1'b0;
```

So the flag is: `please_send_help_i_am_trapped_in_a_ctf_flag_factory@flare-on.com`
___
