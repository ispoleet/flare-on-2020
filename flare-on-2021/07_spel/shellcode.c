// Compile as: x86_64-w64-mingw32-gcc-10 shellcode.c -o shellcode.exe
#include <windows.h>

typedef unsigned __int64 QWORD;



int main() {
    HANDLE hproc = GetCurrentProcess();
    DWORD oldprot = 0;

    if (!VirtualProtectEx(hproc,
                          (LPVOID)((QWORD)&shellcode & 0xFFFFF000),
                          sizeof(shellcode) + 0x1000,
                          PAGE_EXECUTE_READWRITE,
                          &oldprot)) {
        return -1;
    }


	(*(int(*)()) shellcode)();

	return 0;
}
