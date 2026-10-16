# Fortnite 5.41 original loader/entrypoint probe

All results are static, from the original SHA-256-verified retail executable. No game execution or runtime injection.

Entrypoint: **0x351ca98**, section **.text**.
Unwind entries: 291,757; broad stratified samples: 407; samples decoding >=90%: 36.

## Executable section entropy in 64 KiB blocks

| Section (RVA) | Raw bytes | Overall entropy | Window median | Windows >7.95 | Windows <7.5 |
|---|---:|---:|---:|---:|---:|
| .text (0x1000) | 56,361,472 | 7.99514 | 7.995805 | 830/860 | 10 |
| .text (0x5ae4000) | 5,177,856 | 7.5342 | 7.59725 | 22/79 | 39 |

## Original entrypoint direct CALL targets
Entry target 0x5ae6509: 35 entrypoint-reachable static x64 instructions within section 0x5ae4000; unique direct call destinations 0.
~~~asm
0x5ae6509 56                       push rsi
0x5ae650a 50                       push rax
0x5ae650b 4155                     push r13
0x5ae650d 53                       push rbx
0x5ae650e 57                       push rdi
0x5ae650f 4150                     push r8
0x5ae6511 52                       push rdx
0x5ae6512 4157                     push r15
0x5ae6514 4152                     push r10
0x5ae6516 4154                     push r12
0x5ae6518 4156                     push r14
0x5ae651a 4153                     push r11
0x5ae651c 4151                     push r9
0x5ae651e 51                       push rcx
0x5ae651f 488da42400ffffff         lea rsp, [rsp - 0x100]
0x5ae6527 660f110424               movupd xmmword ptr [rsp], xmm0
0x5ae652c 66440f11642410           movupd xmmword ptr [rsp + 0x10], xmm12
0x5ae6533 66440f11442420           movupd xmmword ptr [rsp + 0x20], xmm8
0x5ae653a 66440f11542430           movupd xmmword ptr [rsp + 0x30], xmm10
0x5ae6541 660f11742440             movupd xmmword ptr [rsp + 0x40], xmm6
0x5ae6547 66440f115c2450           movupd xmmword ptr [rsp + 0x50], xmm11
0x5ae654e 66440f114c2460           movupd xmmword ptr [rsp + 0x60], xmm9
~~~

## Authenticated entrypoint first 30 decoded x64 instructions

~~~asm
0x351ca98 4883ec28                 sub rsp, 0x28
0x351ca9c e8689a5c02               call 0x145ae6509
0x351caa1 69a4b34b8baf917840cc48   imul esp, dword ptr [rbx + rsi*4 - 0x6e5074b5], 0x48cc4078
0x351caac ad                       lodsd eax, dword ptr [rsi]
0x351caad 02a685d27fbf             add ah, byte ptr [rsi - 0x40802d7b]
0x351cab3 198f09500825             sbb dword ptr [rdi + 0x25085009], ecx
0x351cab9 2a900d110da8             sub dl, byte ptr [rax - 0x57f2eef3]
~~~

## Relevant imported Windows APIs
KERNEL32.dll!VirtualQueryEx, KERNEL32.dll!VirtualAlloc, KERNEL32.dll!VirtualProtect, KERNEL32.dll!LoadLibraryA, KERNEL32.dll!VirtualQuery, KERNEL32.dll!LoadLibraryExW, KERNEL32.dll!GetProcAddress, KERNEL32.dll!LoadLibraryW

## Limits
This is structural evidence, not a proven offline decryptor. The correct next move depends on whether the entrypoint and second executable section form coherent loader code. The full JSON retains spatial samples and instruction previews.
