# Fortnite 5.41 original loader/entrypoint probe

All results are static, from the original SHA-256-verified retail executable. No game execution or runtime injection.

Entrypoint: **0x351ca98**, section **.text**.
Unwind entries: 291,757; broad stratified samples: 407; samples decoding >=90%: 36.

## Executable section entropy in 64 KiB blocks

| Section (RVA) | Raw bytes | Overall entropy | Window median | Windows >7.95 | Windows <7.5 |
|---|---:|---:|---:|---:|---:|
| .text (0x1000) | 56,361,472 | 7.99514 | 7.995805 | 830/860 | 10 |
| .text (0x5ae4000) | 5,177,856 | 7.5342 | 7.59725 | 22/79 | 39 |

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
