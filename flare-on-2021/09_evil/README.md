## Flare-On 2021 - #9: Evil
___

### Description: 

*Mandiant's unofficial motto is "find evil and solve crime". Well here is evil but forget crime, solve challenge. Listen kid, RFCs are for fools, but for you we'll make an exception :)*

*The challenge has 3 false flags:*

`!t_$uRe_W0u1d_B3_n1ce_huh!@flare-on.com`

`1s_tHi$_mY_f1aG@flare-on.com`

`N3ver_G0nNa_g1ve_y0u_Up@flare-on.com`


`7-zip password: flare`

___

### Solution:

In this challenge, we are given `evil.exe`, a binary that is heavily protected against Reverse
Engineering. IDA has a hard time recognizing functions, and disassembly listings many times fail
or contain non-sense instructions. The most important thing however is that the the code causes
segmentation faults itself:
```assembly
.text:004064E2 C7 45 E0 32 61 24 00         mov     dword ptr [ebp-20h], 246132h
.text:004064E9 C7 45 DC 5E 2C 5D 1C         mov     dword ptr [ebp-24h], 1C5D2C5Eh
.text:004064F0 C7 40 04 00 00 00 00         mov     dword ptr [eax+4], 0
.text:004064F7 89 03                        mov     [ebx], eax
.text:004064F9 89 18                        mov     [eax], ebx
.text:004064FB FF 35 98 16 6D 00            push    dword_6D1698
.text:00406501 6A 00                        push    0
.text:00406503 6A 00                        push    0
.text:00406505 8B 55 E0                     mov     edx, [ebp-20h]
.text:00406508 8B 4D DC                     mov     ecx, [ebp-24h]
.text:0040650B 33 C0                        xor     eax, eax
.text:0040650D 8B 00                        mov     eax, [eax]
.text:0040650F 74 03                        jz      short l
```

And divisions by zero:
```assembly
.text:00406616 C7 45 D8 32 61 24 00         mov     dword ptr [ebp-28h], 246132h
.text:0040661D C7 45 DC 46 27 D2 05         mov     dword ptr [ebp-24h], 5D22746h
.text:00406624 6A 00                        push    0
.text:00406626 6A 00                        push    0
.text:00406628 FF 75 E4                     push    dword ptr [ebp-1Ch]
.text:0040662B FF 75 08                     push    dword ptr [ebp+8]
.text:0040662E 6A 00                        push    0
.text:00406630 6A 00                        push    0
.text:00406632 8B 55 D8                     mov     edx, [ebp-28h]
.text:00406635 8B 4D DC                     mov     ecx, [ebp-24h]
.text:00406638 33 C0                        xor     eax, eax
.text:0040663A F7 F0                        div     eax
.text:0040663C E8 FF D2 8B 4D               call    near ptr 4DCC3940h
```

This obviously some form of exception handling. To find where the exception handler is defined,
we need to start from the very beginning at `start` at `426BD8h`, which is a wrapper for
`__scrt_common_main_seh`:
```c
char *__usercall __scrt_common_main_seh@<eax>(char *a1@<esi>, int a2@<ebx>, int a3@<edi>) { 
  /* Decls & more */

  dword_1690B90 = 1;
  if ( u_invoke_default_ctors(&glo_ctr_table_default, dword_14051CC) )
    return 255;
  u_invoke_custom_ctors(&glo_ctor_table, &dword_14051A4);
  dword_1690B90 = 2;
  /* ... */

  a1 = main(*v11, v10, v9);
  /* ... */
}
```


Before `main`, function `u_invoke_custom_ctors` at `431ED6h` invokes all constructors one by one:
```assembly
.rdata:00445150 00 00 00 00 glo_ctor_table dd 0
.rdata:00445154 44 6A 42 00         dd offset u_ctor_SetUnhandledExceptionFilter
.rdata:00445158 6C 21 40 00         dd offset u_ctor_init_locks
.rdata:0044515C FD 21 40 00         dd offset u_ctor_init_locks_2
.rdata:00445160 B9 21 40 00         dd offset ??__Efout@std@@YAXXZ  ; std::`dynamic initializer for 'fout''(void)
.rdata:00445164 9A 21 40 00         dd offset u_init_ios_base
.rdata:00445168 F3 21 40 00         dd offset u_ctor_unknown_set
.rdata:0044516C 13 22 40 00         dd offset u_ctor_init_locks_3
.rdata:00445170 29 22 40 00         dd offset u_ctor_at_exit
.rdata:00445174 8E 21 40 00         dd offset u_ctor_at_exit_2
.rdata:00445178 82 21 40 00         dd offset u_ctor_at_exit_3
.rdata:0044517C 60 21 40 00         dd offset u_ctor_at_exit_4
.rdata:00445180 00 10 40 00         dd offset u_ctor_decoy_flag
.rdata:00445184 00 11 40 00         dd offset u_ctor_decrypt_dll_names
.rdata:00445188 70 1F 40 00         dd offset u_ctor_alloc_some_obj_0x18
.rdata:0044518C A0 1F 40 00         dd offset u_ctor_alloc_another_obj_0x18
.rdata:00445190 D0 1F 40 00         dd offset u_ctor_set_LoadLibraryA_addr
.rdata:00445194 D0 20 40 00         dd offset u_ctor_unknown
.rdata:00445198 F0 20 40 00         dd offset u_ctor_set_CryptImportKey
.rdata:0044519C 30 21 40 00         dd offset u_ctor_set_AddVectoredExceptionHandler_addr
.rdata:004451A0 50 21 40 00         dd offset u_ctor_set_vectored_exception_handler
```

There are several interesting functions here. `u_ctor_decoy_flag` at `401000h` decrypts a (false)
flag into `glo_decoy_flag_no2`:
```c
void __cdecl u_ctor_decoy_flag() {
  ThreadLocalStoragePointer = NtCurrentTeb()->ThreadLocalStoragePointer;
  v3[0] = 0x8AFD9FE9;
  v3[1] = 0xE88AADC1;
  tls = *ThreadLocalStoragePointer;
  v3[2] = 0xCFA6C498;
  v3[3] = 0x96D59FFB;
  v3[4] = 0x81F490FF;
  v3[5] = 0xDAABD9E9;
  v3[6] = 0x8FFF8DEB;
  v4 = 0x8C;

  if ( dword_6D177C > *(tls + 4) ) {
    _Init_thread_header(&dword_6D177C);
    if ( dword_6D177C == -1 ) {
      qmemcpy(glo_decoy_flag_no2, v3, 0x1Cu);
      glo_decoy_flag_no2[28] = v4;
      atexit(sub_444950);
      _Init_thread_footer(&dword_6D177C);
    }
  }
  if ( glo_decoy_flag_no2[28] ) {
    i = 30;
    do {
      glo_decoy_flag_no2[i] = -((*(&dword_6D1754 + i + 3) | ~glo_decoy_flag_no2[i]) & (glo_decoy_flag_no2[i] | ~*(&dword_6D1754 + i + 3)))
                            - 4;
      --i;
    } while ( i );
  }

  glo_decoy_flag_no2_addr = glo_decoy_flag_no2;
  glo_decoy_flag_no2[0] = ((~glo_decoy_flag_no2[0] | 0xF3) & ~((glo_decoy_flag_no2[0] | 0x22) & (~glo_decoy_flag_no2[0] | 0xDD))) - 3;
}
```

`u_ctor_decrypt_dll_names` at `401100h` uses the same decryption scheme to decrypt all DLL names
(e.g., `kernel32.dll`, `advapi32.dll` and so on) and store them into global variables.
`u_ctor_set_LoadLibraryA_addr` at `401FD0h` decrypts the `"LoadLibraryA"` string and iterates
over `kernel32.dll` EAT in order to find the address of `LoadLibraryA`:
```c
void (__stdcall *__cdecl u_ctor_set_LoadLibraryA_addr())(_DWORD) {
  if ( dword_6D1814 > *(*NtCurrentTeb()->ThreadLocalStoragePointer + 4) ) {
    _Init_thread_header(&dword_6D1814);
    if ( dword_6D1814 == -1 ) {
      *glo_LoadLibraryA_str = 0xD1B6D2A0;
      *&glo_LoadLibraryA_str[4] = 0xE297F29E;
      *&glo_LoadLibraryA_str[8] = 0xCB8FF386;
      glo_LoadLibraryA_str[12] = -56;
      atexit(sub_444BD0);
      _Init_thread_footer(&dword_6D1814);
    }
  }
  if ( glo_LoadLibraryA_str[12] ) {
    v0 = 14;
    do {
      glo_LoadLibraryA_str[v0] = -((byte_6D182F[v0] | ~glo_LoadLibraryA_str[v0]) & (glo_LoadLibraryA_str[v0] | ~byte_6D182F[v0])) - 4;
      --v0;
    } while ( v0 );
  }

  glo_LoadLibraryA_str[0] = ((~glo_LoadLibraryA_str[0] | 0xF3) & ~((glo_LoadLibraryA_str[0] | 0x10) & (~glo_LoadLibraryA_str[0] | 0xEF))) - 3;
  
  kernel32_base = u_get_kernel32_base();
  result = u_get_proc_addr_from_str(kernel32_base, glo_LoadLibraryA_str);
  glo_LoadLibraryA = result;
  return result;
}
```

Finally, the most important ctor is `u_ctor_set_vectored_exception_handler`:
```assembl
.text:00402150             ; int u_ctor_set_vectored_exception_handler()
.text:00402150             u_ctor_set_vectored_exception_handler proc near
.text:00402150                                                     ; DATA XREF: .rdata:004451A0↓o
.text:00402150 68 D0 6A 40 00        push    offset u_exception_handler
.text:00402155 6A 01                 push    1
.text:00402157 FF 15 E4 16 6D 00     call    glo_AddVectoredExceptionHandler
.text:0040215D C3                    retn
.text:0040215D             u_ctor_set_vectored_exception_handler endp
```

This ctor sets `u_exception_handler`  at `406AD0h` as a new
[Vectored Exception Handler](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling):
```c
int __stdcall u_exception_handler(void *a1_ExceptionInfo) {
  _EXCEPTION_POINTERS *tls; // esi
  _CONTEXT *context; // eax
  int edx_; // edi
  int ecx_; // ebx
  char *proc_addr; // edi

  tls = a1_ExceptionInfo;
  context = *(a1_ExceptionInfo + 1);
  edx_ = context->Edx;
  ecx_ = context->Ecx;
  if ( dword_6D1C78 > *(*NtCurrentTeb()->ThreadLocalStoragePointer + 4) ) {
    _Init_thread_header(&dword_6D1C78);

    if ( dword_6D1C78 == -1 ) {
      glo_VirtualProtect = u_get_proc_addr_using_hash(0x246132, 0xA31BEAA4);// VirtualProtect
      _Init_thread_footer(&dword_6D1C78);
    }
  }

  proc_addr = u_get_proc_addr_using_hash(edx_, ecx_);

  if ( !proc_addr )
    return 0;

  glo_VirtualProtect(tls->ContextRecord->Eip, 0x1000, 0x40, &a1_ExceptionInfo);// PAGE_EXECUTE_READWRITE
  tls->ContextRecord->Eax = proc_addr;
  *(tls->ContextRecord->Eip + 3) = 0xD0FF;      // \xff\xd0 is the opcode for "call eax"
  tls->ContextRecord->Eip += 3;
  glo_VirtualProtect(tls->ContextRecord->Eip, 0x1000, a1_ExceptionInfo, &a1_ExceptionInfo);

  return -1;
}
```

This function is very important: When an exception occurs, the exception handler reads the values
from `EDX` and `RCX` registers and uses them as ordinals to find the appropriate function address
from one of the imported DLLs. If the address is found, it is returned in `EAX` register.
Furthermore, function "patches" the next instruction with `\xFF\xD0` which is the `call eax`
instruction and hands off execution control back to the program. Hence, this exception handling
mechanism provides a stealthy way to invoke DLL functions.

Knowing that, our first task is to fix the disassembly listings. The idea is to locate all
`xor eax, eax; mov eax, [eax]` and `xor eax, eax; div eax` instruction sequences and replace
the next 3 bytes with `nop; call eax` (which is `90 FF D0`) in order to make decompiler happy.
Once we do that, we can go back to `_main` at `406450h`:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  /* Decls & initializations */
  this_obj_new = u_anti_debug_n_calc_hash(this_obj);
  /* ... */
  mutex_handle = MEMORY[0](v29, v30, 0);        // kernel32_CreateMutexA
  this_obj_->mutex_handle_2 = mutex_handle;
  if ( mutex_handle || (v29 = 0x246132, v30 = 0xB3D0027C, ((0x24613200000000i64 / 0ui64))(0xB3D0027C, 0 % 0u) != 183) )// GetLastError
  {
    v29 = u_thread_routine_A_ANTIDEBUG;
    v30 = 0x246132;
    v28 = 0x5D22746;
    v8 = ((0x24613200000000i64 / 0ui64))(0x5D22746, 0 % 0u, 0, 0, u_thread_routine_A_ANTIDEBUG, thread_param, 0, 0);// CreateThread
    v28 = u_thread_routine_D_ANTIDEBUG;
    v29 = 0x246132;
    v30 = 0x5D22746;
    this_obj_->thread_handle = v8;
    LODWORD(v9) = 0;
    HIDWORD(v9) = v29;
    ((v9 / v9))(v30, 0 % 0u, 0, 0, v28, thread_param, 0, 0);// CreateThread
  }
  buf__ = buf_;
  buf_1 = buf_;
  buf_->field_198 = 0;
  buf__->socket_serv = 0xFFFFFFFF;
  buf__->socket_2 = 0xFFFFFFFF;
  buf__->guard_flag = 0;
  memset(buf_1, 0, 0x190u);
  v11 = this_obj_;
  v35 = 2;
  buf__->semaphore_handle = 0;
  buf__->this_obj = v11;
  thread_param = buf__;

  if ( argc == 2 )                              //  We need a command line arg!
  {
    u_bind_server(buf__, argv[1]);
    v28 = 2384178;
    v29 = 0x5D22746;
    thread_B_handle = ((0x24613200000000i64 / 0ui64))(0x5D22746, 0 % 0u, 0, 0, u_thread_routine_B, thread_param, 0, 0);
    v28 = 0x246132;
    v29 = 0x5D22746;
    buf_->thread_B_handle = thread_B_handle;
    LODWORD(v13) = 0;
    HIDWORD(v13) = v28;
    thread_C_handle = ((v13 / v13))(v29, 0 % 0u, 0, 0, u_thread_routine_C, thread_param, 0, 0);// CreateThread
    v15 = buf_;
    v28 = 2384178;
    v29 = 0xF5D407D0;
    buf_->thread_C_handle = thread_C_handle;
    ((__PAIR64__(v28, &v15->thread_B_handle) / 0))(v29, &v15->thread_B_handle % 0, 2, &v15->thread_B_handle, 1, -1);// WaitForMultipleObjects

    /* teardown / closesocket() / free() */
  }

  return 0;
}
```


First of all, `evil.exe` requires a command line argument. It also spawns **4** threads. **2** of
them are used as anti-debugging protections. while the other **2** performs the actual computations.
Let's start with `u_anti_debug_n_calc_hash` at `4023D0h`:
```c
int __thiscall u_anti_debug_n_calc_hash(this_obj *this_obj) {
  p_system_time = &system_time;
  MEMORY[0](0x66FFF672, 0x246132, &system_time);// GetSystemTime

  glo_prng = 1000001 * v18;
  DbgBreakPoint = u_get_proc_addr_using_hash(0x176684, 0xFE76FB3A);
  if ( DbgBreakPoint ) {
    /* Invoke DbgBreakPoint */
  }

  DbgUiRemoteBreakin = u_get_proc_addr_using_hash(1533572, 0xC06E38C1);
  DbgBreakPoint = DbgUiRemoteBreakin;
  TerminateProcess = u_get_proc_addr_using_hash(2384178, 0x24E0B26E);
  some_fptr = TerminateProcess;

  if ( DbgUiRemoteBreakin ) {
    if ( TerminateProcess ) {
      /* Invoke DbgUiRemoteBreakin */
    }
  }

  u_unknown_func_ANTIDEBUG_maybe();
  u_calc_hash_outer();

  retval = this_obj_;
  some_fptr = 0;
  *u_map_insert_maybe(&this_obj_->hash_map, &some_fptr) = u_check_for_debugger_1;
  some_fptr = 1;
  *u_map_insert_maybe(&retval->hash_map, &some_fptr) = u_check_for_debugger;
  some_fptr = 2;
  *u_map_insert_maybe(&retval->hash_map, &some_fptr) = u_check_for_debugger_from_fs;
  some_fptr = 3;
  *u_map_insert_maybe(&retval->hash_map, &some_fptr) = u_anti_debug_check_privilege;
  some_fptr = 4;
  *u_map_insert_maybe(&retval->hash_map, &some_fptr) = u_anti_debug_thread_context;
  some_fptr = 5;
  *u_map_insert_maybe(&retval->hash_map, &some_fptr) = u_anti_debug_tick_count;
  hash_map = retval->hash_map;
  v12 = hash_map->field_0;
  if ( hash_map->field_0 != hash_map ){
    do {
      (*(v12 + 20))(*(v12 + 16));               // invoke all functions one by one
      /* ... */
    }
    while ( v12 != retval->hash_map );
  }
  return retval;
}
```

This function creates a hashmap, and inserts the following anti-reversing functions to it:
```
  (0, u_check_for_debugger_1)
  (1, u_check_for_debugger)
  (2, u_check_for_debugger_from_fs)
  (3, u_anti_debug_check_privilege)
  (4, u_anti_debug_thread_context)
  (5, u_anti_debug_tick_count)
```

Each function implements a different anti-reversing protection. We will not get into details here,
since we only want to avoid those functions. `u_bind_server` at `403A70h` creates a UDP server
using `argv[1]` as the server address. The port is set to **0** (i.e., system selects an
ephemeral port).

Let's look now at the anti-reversing threads:
```c
void __cdecl __noreturn u_thread_routine_A_ANTIDEBUG(this_obj *a1_this_obj) {
  while ( 1 ) {
    u_spawn_anti_debug_thread(a1_this_obj);
    glo_prng = 0x41C64E6D * glo_prng + 12345;
    MEMORY[0](0x4F2E84B7, 0x246132, 1000 * ((HIWORD(glo_prng) & 0x7FFF) % 10));// Sleep
  }
}

void __thiscall u_spawn_anti_debug_thread(this_obj *arg_this_obj) {
  glo_prng = 0x41C64E6D * glo_prng + 12345;
  param = (HIWORD(glo_prng) & 0x7FFFui64) % arg_this_obj->modulo;

  thread_handle_ = param;
  anti_debug_func = *u_map_select(&arg_this_obj->hash_map, &thread_handle_);

  thread_handle = ((0x24613200000000i64 / 0ui64))(0x5D22746, 0 % 0u, 0, 0, anti_debug_func, param, 0, 0);// CreateThread
  thread_handle_ = thread_handle;

  if ( thread_handle != -1 )
    (((thread_handle | 0x24613200000000ui64) / 0))(0x277D84BB, thread_handle % 0, thread_handle_, 5000);// WaitForSingleObject

  MEMORY[0](0xED79E920, 0x246132, thread_handle_);// CloseHandle
}
```

```c
void __cdecl __noreturn u_thread_routine_D_ANTIDEBUG(ispo_struct *a1)
{
  ispo_struct *i; // eax
  bool v2; // zf
  int mutex; // eax

  for ( i = a1; ; i = a1 ) {
    do {
      v2 = (((i->thread_handle | 0x24613200000000ui64) / 0))(0x277D84BB, i->thread_handle % 0u, i->thread_handle, -1) == 0;// WaitForSingleObject
      i = a1;
    } while ( !v2 );
    CloseHandle(a1->mutex_handle_2);
    
    a1->mutex_handle_2 = 0;
    mutex = MEMORY[0](0x1C5D2C5E, 0x246132, 0); // CreateMutexA
    a1->mutex_handle_2 = mutex;
    if ( mutex || ((0x24613200000000i64 / 0ui64))(0xB3D0027C, 0 % 0u) != 183 )// GetLastError
    {
      a1->thread_handle = ((0x24613200000000i64 / 0ui64))(
                            0x5D22746,
                            0 % 0u,
                            0,
                            0,
                            u_thread_routine_A_ANTIDEBUG,
                            a1,
                            0,
                            0);                 // CreateThread
      ((0x24613200000000i64 / 0ui64))(0x5D22746, 0 % 0u, 0, 0, u_thread_routine_D_ANTIDEBUG, a1, 0, 0);// CreateThread
    }
  }
}
```

Thread **D** here spawns thread **A** and thread **A** (pseudo) randomly chooses one of the 6
anti-reversing functions from the hashmap and spawns a new thread to execute it.

Now let's move to thread **B**. Thread **B** iterates over a loop. It first invokes
`u_spawn_anti_debug_thread` and then allocates **1500** bytes for a new object and invokes 
`recvfrom` to receive a special packet from the UDP server, parse it and insert the data into a
struct:
```c
int __stdcall u_thread_routine_B(ispo_struct *a1) {  
  /* Decls & initializations */

  while ( 1 ) {
    u_spawn_anti_debug_thread(v1->this_obj);

    recv_buf_ = u_new(1500u);
    socket_serv = v1->socket_serv;
    recv_buf = recv_buf_;
    memset(v32, 0, sizeof(v32));
    v42 = 16;
    v43 = socket_serv;
    LODWORD(v4) = 0;
    HIDWORD(v4) = v39;
    nrecv = ((v4 / v4))(v38, 0 % 0u, socket_serv, recv_buf_, 1500, 0, from, from_len);// ws2_32_recvfrom

    if ( nrecv == -1 ) {
      /* WSAGetLastError and return */
    }

    if ( !nrecv )
      break;

    /* use htons to parse numbers for the packet and copy buffers */

    new_buf->num = v14;
    v35 = 0x246132;
    num = a1->mutex_handle;
    v36 = 0x277D84BB;

    if ( !(((num | 0x24613200000000ui64) / 0))(0x277D84BB, num % 0, num, 10000) )// WaitForSingleObject
    {
      u_spawn_anti_debug_thread(a1->this_obj);
      v20 = a1->block.field_10;
      v21 = a1->block.field_C;
      v22 = v20;
      if ( ((v21 + v20) & 3) == 0 && a1->block.field_8 <= (v20 + 4) >> 2 )
      {
        u_some_kind_of_insert(&a1->block.tiny_buf_8, a1->block.field_10);
        v21 = a1->block.field_C;
        v22 = a1->block.field_10;
      }
      v23 = a1->block.field_8;
      v24 = v21 & (4 * v23 - 1);
      a1->block.field_C = v24;
      v25 = v24 + v22;
      v26 = 4 * ((v25 >> 2) & (v23 - 1));
      v27 = a1->block.field_4;
      v43 = v26;
      if ( !*(v27 + v26) )
      {
        v28 = operator new(0x10u);
        v29 = v43;
        *(v43 + a1->block.field_4) = v28;
        v26 = v29;
        v27 = a1->block.field_4;
      }
      v30 = *(v26 + v27);
      v35 = 0x246132;
      v36 = 0x5BB9CE5D;
      *(v30 + 4 * (v25 & 3)) = new_buf_;
      ++a1->block.field_10;
      num = a1->semaphore_handle;
      MEMORY[0](v36, v35, num);                 // kernel32_ReleaseSemaphore
      v35 = 0x246132;
      v36 = 0x53805498;
      num = a1->mutex_handle;
      MEMORY[0](0x53805498, 0x246132, num);     // kernel32_ReleaseMutex
    }

  /* teardown */

  return 0;
}
```

The packet struct looks like this:
```
00000000 packet_struct struc ; (sizeof=0x5DC, mappedto_126)
00000000                                         ; XREF: u_pack_and_sendto/r
00000000 magic   dw ?                            ; XREF: u_pack_and_sendto+34/w
00000000                                         ; u_pack_and_sendto:loc_403E75/r ...
00000002 packet_size dw ?                        ; XREF: u_pack_and_sendto+1A9/w
00000004 prng_hiword dw ?                        ; XREF: u_pack_and_sendto+89/w
00000006 const_8000 dw ?                         ; XREF: u_pack_and_sendto+CB/w
00000008 const_1180 dw ?                         ; XREF: u_pack_and_sendto+9C/w
0000000A chksum_maybe dw ?                       ; XREF: u_pack_and_sendto+20C/w
0000000C arg_a4  dd ?                            ; XREF: u_pack_and_sendto+93/w
00000010 arg_a5  dd ?                            ; XREF: u_pack_and_sendto+A5/w
00000010                                         ; u_pack_and_sendto+21C/r
00000014 ispo_struct_field_19C_loword dw ?       ; XREF: u_pack_and_sendto+111/w
00000016 arg_a6  dw ?                            ; XREF: u_pack_and_sendto+D6/w
00000016                                         ; u_pack_and_sendto+225/r
00000018 datalen dw ?                            ; XREF: u_pack_and_sendto+16E/w
0000001A const_0 dw ?                            ; XREF: u_pack_and_sendto+11A/w
0000001C data    db 1472 dup(?)                  ; XREF: u_pack_and_sendto+10B/o ; base 10
000005DC packet_struct ends
```

On the other side of the server, thread **C** is used to send packets to thread **B**:
```c
int __stdcall u_thread_routine_C(ispo_struct *a1) {
  /* Decls */
  
  if ( !a1->guard_flag ) {
    while ( 1 ) {

      ipc_handle = v1->semaphore_handle;
      if ( (((ipc_handle | 0x24613200000000ui64) / 0))(0x277D84BB, ipc_handle % 0, ipc_handle, 10000) )// WaitForSingleObject
        goto LOOP_END;
      Block = 0x246132;
      ipc_handle = a1->mutex_handle;
      if ( (((ipc_handle | 0x24613200000000ui64) / 0))(0x277D84BB, ipc_handle % 0, ipc_handle, 10000) )// WaitForSingleObject
        goto LOOP_END;
      u_spawn_anti_debug_thread(a1->this_obj);

      v2 = a1->block.field_C;
      v3 = *(*(a1->block.field_4 + 4 * ((v2 >> 2) & (a1->block.field_8 - 1))) + 4 * (v2 & 3));
      v4 = a1->block.field_10-- == 1;
      Block = v3;
      a1->block.field_C = v4 ? 0 : v2 + 1;
      mutex_handle = a1->mutex_handle;
      ipc_handle = 0x246132;
      MEMORY[0](0x53805498, 0x246132, mutex_handle);// kernel32_ReleaseMutex
      
      v5 = Block;
      if ( !Block )
        goto LOOP_END;
      ipc_handle = Block->field_C;
      if ( *ipc_handle == 1 )
        goto LABEL_111;
      if ( *ipc_handle == 2 )
        break;
      if ( *ipc_handle != 3 ) {
        /* prepare packet */
        u_pack_and_sendto(a1, sendbuf, sendbuflen + 8, Block->field_4, Block->tiny_buf_8, Block->field_8);
        u__free_base_0(sendbuf);
        goto SKIP;
      }

      v15 = Block->field_C;
      if ( *(v15 + 4) >= 2u ) {
        if ( *(v15 + 8) == 'ZM' ) {
          v16 = u_new(47u);
          iter = 39;
          *v16 = 0xFFFF;
          *(v16 + 1) = 39;
          v18 = v16 + 8;
          do
          {
            v19 = (v18++)[glo_ciphertext_C - (v16 + 8)];
            *(v18 - 1) = v19;
            --iter;
          }
          while ( iter );
          u_decrypt_data(glo_key_C, (v16 + 8), (v16 + 4));
          v5 = Block;
          u_pack_and_sendto(a1, v16, v16[4] + 8, Block->field_4, Block->tiny_buf_8, Block->field_8);
          *glo_key_C = 0;
          *&glo_key_C[4] = 0;
          *&glo_key_C[8] = 0;
          *&glo_key_C[12] = 0;
          u__free_base(v16);
          goto LOOP_END_AND_FREE;
        }

        sub_403FC0(a1, Block);
      }

      /* teardown */

      if ( a1->guard_flag )
        return 0;
    }

    a1_buf = Block->field_C;
    ThreadLocalStoragePointer = NtCurrentTeb()->ThreadLocalStoragePointer;
    chksum = 0;
    tls = *ThreadLocalStoragePointer;
    if ( dword_6D179C > *(*ThreadLocalStoragePointer + 4) )
    {
      _Init_thread_header(&dword_6D179C);
      if ( dword_6D179C == -1 ) {
        if ( dword_6D17A0 > *(tls + 4) ) {
          _Init_thread_header(&dword_6D17A0);
          if ( dword_6D17A0 == -1 ) {
            *glo_str_L0ve = 0xEB83FAC9;
            glo_str_L0ve[4] = 0xE8;
            atexit(u_nothing);
            _Init_thread_footer(&dword_6D17A0);
          }
        }

        if ( glo_str_L0ve[4] ) {
          i = 6;
          do {
            glo_str_L0ve[i] = -((*(&dword_6D17A4 + i + 3) | ~glo_str_L0ve[i]) & (glo_str_L0ve[i] | ~*(&dword_6D17A4 + i + 3))) - 4;
            --i;
          } while ( i );
        }

        glo_str_L0ve_ptr = glo_str_L0ve;
        glo_str_L0ve[0] = (~((glo_str_L0ve[0] | 0x79) & (~glo_str_L0ve[0] | 0x86)) & (~((glo_str_L0ve[0] | 0xFB) & (~glo_str_L0ve[0] | 4)) | 0xF3)) - 3;
        _Init_thread_footer(&dword_6D179C);
      }
    }

    if ( dword_6D17C4 > *(tls + 4) )    {
      /* Use the same algorithm to decrypt "s3cret" and store it on glo_str_s3cret */
    }

    if ( dword_6D17A4 > *(tls + 4) ) {
      /* Use the same algorithm to decrypt "5Ex" and store it on glo_str_5Ex_ptr */
    }

    if ( dword_6D1788 > *(tls + 4) ) {
      /* Use the same algorithm to decrypt "g0d" and store it on glo_str_g0d */
    }

    /* 
     * Initialize glo_key_C at 6D1680h
     */
    v26 = a1_buf;
    v27 = *(a1_buf + 1);
    if ( v27 > 0 ) {
      L0ve_str = glo_str_L0ve_ptr;
      i_1 = 0;
      if ( *glo_str_L0ve_ptr ) {
        do
          ++i_1;
        while ( glo_str_L0ve_ptr[i_1] );        // strlen
      }

      if ( v27 >= i_1 ) {
        i_2 = 0;
        if ( *glo_str_L0ve_ptr ) {
          do
            ++i_2;
          while ( glo_str_L0ve_ptr[i_2] );      // more strlen
        }
      }

      else {
        i_2 = *(a1_buf + 1);
      }

      v31 = a1_buf + 8;
      a1_bufa = a1_buf + 8;
      v32 = v26 + 8;
      if ( !i_2 ) goto MATCH_FOUND_1;
      
      while ( 1 ) {
        key = *L0ve_str;
        if ( !*L0ve_str || key != *v32 )
          break;
        ++L0ve_str;
        ++v32;
        if ( !--i_2 )
          goto MATCH_FOUND_1;
      }

      if ( key == *v32 ) {
MATCH_FOUND_1:
        v34 = ipc_handle;
        v35 = glo_key_C;
        v36 = &glo_key_C[1];
        ipc_handle = &glo_key_C[3];
        v37 = &glo_key_C[2];
      }
      else {
        /* Same as before: Check if string is glo_str_s3cret_ptr */

        if ( v43 == *v42 ) {
MATCH_FOUND_2:
          v34 = ipc_handle;
          v35 = &glo_key_C[4];
          v36 = &glo_key_C[5];
          ipc_handle = &glo_key_C[7];
          v37 = &glo_key_C[6];
        }
        else {
          /* Same as before: Check if string is glo_str_5Ex_ptr */
          if ( v48 == *v47 ) {
MATCH_FOUND_3:
            v34 = ipc_handle;
            v35 = &glo_key_C[8];
            v36 = &glo_key_C[9];
            ipc_handle = &glo_key_C[11];
            v37 = &glo_key_C[10];
          }
          else {
            /* Same as before: Check if string is glo_str_g0d_ptr */             
MATCH_FOUND_4:
            v34 = ipc_handle;
            v35 = &glo_key_C[12];
            v36 = &glo_key_C[13];
            ipc_handle = &glo_key_C[15];
            v37 = &glo_key_C[14];
          }
        }
      }

      u_crc32_maybe(a1_bufa, *(v34 + 4), &chksum);
      *v35 = HIBYTE(chksum);
      *v36 = BYTE2(chksum);
      *v37 = BYTE1(chksum);
      *ipc_handle = chksum;
    }
SKIP:
    v5 = Block;
    goto LOOP_END_AND_FREE;
  }

  return 0;
}
```

As its name suggests, `u_pack_and_sendto` at `403D40h` packs all information into a packet
and uses `sendto` to send it to thread **B**. Then thread, checks if value of the received
sub-buffer matches any of the following **4** keywords: `L0ve`, `s3cret`, `5Ex` and `g0d`.
If so, it calculates CRC32 checksum of the keyword and uses it to contribute **4** bytes to
the decryption key `glo_key_C` at `6D1680h`. Knowing that, we can easily recover the key:
```
E3 FC 31 F4 D8 E9 B0 78 77 06 6B 5A A2 4F 5B 95
```

Besides that key, there are **2** more keys `glo_key_B` at `6CFB90h` and `glo_key_A` at `6CFBC8h`
(which are identical):
```
55 8B EC 64 A1 00 00 00 6A FF 68 D4 21 41 00 50
```

The decryption takes place inside `u_decrypt_data` at `4067A0h`:
```c
void __thiscall u_decrypt_data(int a1_key, int a2_outbuf, int a3_size) {  
  hprov = 0;
  pKey = 0;
  v16 = 0;
  v4 = calloc(1u, 0x1Cu);
  pbData_2 = v4;
  pbData = v4;
  if ( v4 )
  {
    v6 = *a1_key;
    *&pbData_2->header.bType = 0x208;           // PLAINTEXTKEYBLOB = 0x08
    pbData_2->header.aiKeyAlg = 0x6802;         // CALG_SEAL
    pbData_2->key_size = 0x10;
    *pbData_2->key_bytes = v6;
    *&pbData_2->key_bytes[4] = *(a1_key + 4);
    *&pbData_2->key_bytes[8] = *(a1_key + 8);
    *&pbData_2->key_bytes[12] = *(a1_key + 12);

    LODWORD(v7) = 0;
    HIDWORD(v7) = &unk_523422;
    if ( ((v7 / v7))(0xCAC815FA, 0 % 0u, &hprov, 0, 0, 1, 0)// CryptAcquireContextA
      || (LODWORD(v8) = 0,
          HIDWORD(v8) = &unk_523422,
          v9 = ((v8 / v8))(
                 0xCAC815FA,
                 0 % 0u,
                 &hprov,
                 0,
                 0,
                 1,
                 8),                            // CryptAcquireContextA
          v9(),
          !v10)
      || (LODWORD(v11) = 0, HIDWORD(v11) = &unk_523422, ((v11 / v11))(0xCAC815FA, 0 % 0u, &hprov, 0, 0, 1, 0xF0000000)) )// CryptImportKey
    {
      if ( ((0x52342200000000i64 / 0ui64))(0x94F7A04C, 0 % 0u, hprov, pbData, 0x1C, 0, 0, &pKey) )
      {
        LODWORD(v12) = 0;
        HIDWORD(v12) = &unk_523422;
        if ( ((v12 / v12))(0x151B52DF, 0 % 0u, pKey, 0, 1, 0, a2_outbuf, a3_size) )// CryptDecrypt
          v16 = 1;
      }
    }
    u__free_base_1(pbData);
  }
  if ( pKey )
    v4 = MEMORY[0](0x4FBDC973, &unk_523422, pKey);
  if ( hprov )
    ((__PAIR64__(&unk_523422, v4) / 0))(0x539DDA96, v4 % 0, hprov, 0);// CryptReleaseContext
}
```

This function takes a key and a ciphertext as input and uses SEAL algorithm to perform the
decryption. After some search we see that `SEAL` cipher is essentially `RC4`. There are
**3** XREFs to `u_decrypt_data` that decrypt different ciphertexts:
```c
memmove(v3, glo_ciphertext_A, Size);    // glo_ciphertext_A at 5B7330h
u_decrypt_data(glo_key_A, v32, &Size);  

v15 = v14;
do {
  v16 = (v15++)[glo_ciphertext_B - v14]; // glo_ciphertext_B at 6CFBA0h
  *(v15 - 1) = v16;
  --v13;
} while ( v13 );
u_decrypt_data(glo_key_B, v14, (v12 + 1));

do {
  v19 = (v18++)[glo_ciphertext_C - (v16 + 8)]; // glo_ciphertext_C at 6CFB68h
  *(v18 - 1) = v19;
  --iter;
} while ( iter );
u_decrypt_data(glo_key_C, (v16 + 8), (v16 + 4));
```

We use the [evil_crack.py](./evil_crack.py) file to decrypt the ciphertexts. The first ciphertext
gives us a BMP image:

![alt text](pic_dec.bmp "")

The second ciphertext gives us a false flag: `N3ver_G0nNa_g1ve_y0u_Up@flare-on.com`, 

Finally, the last ciphertext gives us the correct flag: `n0_mOr3_eXcEpti0n$_p1ea$e@flare-on.com`
___
