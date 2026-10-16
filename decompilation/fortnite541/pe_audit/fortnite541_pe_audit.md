# Fortnite 5.41 original PE audit

Downloaded and SHA-256-verified the original 97 MB executable on an ephemeral GitHub-hosted runner. Static inspection only; no execution and no upload of the binary.

## Source
SHA-256: 7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108
Size: 97284496

## PE
Entrypoint: 0x351ca98 (.text)
Raw SizeOfCode: 100483584
Overlay bytes: 6032

| Section | Size | Entropy | Executable |
|---|---:|---:|---|
| .text | 56361472 | 7.9951 | True |
| .rdata | 24502272 | 5.3146 | False |
| .data | 5702144 | 2.6691 | False |
| .pdata | 3501568 | 7.0325 | False |
| _RDATA | 40960 | 7.2683 | False |
| .rsrc | 43520 | 7.5049 | False |
| .reloc | 1916416 | 5.4764 | False |
| .idata | 30720 | 4.942 | False |
| .text | 5177856 | 7.5342 | True |

## Unwind index
Valid ranges: 291757
Unique start RVAs: 291757
In executable sections: 291757
Median range: 66 bytes
At most 16 bytes: 32438
At most 64 bytes: 142205

## Machine-code sample
Sampled ranges: 265
Source bytes sampled: 45125
Linearly decoded bytes: 6839
Direct calls: 29
Calls to exact .pdata starts: 0
Other executable call targets: 14
Targets outside executable sections: 15

## Imported DLLs
WS2_32.dll, dbghelp.dll, WINMM.dll, KERNEL32.dll, USER32.dll, GDI32.dll, ADVAPI32.dll, SHELL32.dll, ole32.dll, OLEAUT32.dll, IPHLPAPI.DLL, SETUPAPI.dll, dwmapi.dll, IMM32.dll, CRYPT32.dll, XINPUT1_3.dll, dxgi.dll, d3d9.dll, d3d11.dll, X3DAudio1_7.dll, XAPOFX1_5.dll, WINHTTP.dll, WLDAP32.dll, Normaliz.dll, OPENGL32.dll, DSOUND.dll, MSVCP140.dll, ntdll.dll, VERSION.dll, POWRPROF.dll, bcrypt.dll, VCRUNTIME140.dll, api-ms-win-crt-runtime-l1-1-0.dll, api-ms-win-crt-utility-l1-1-0.dll, api-ms-win-crt-string-l1-1-0.dll, api-ms-win-crt-stdio-l1-1-0.dll, api-ms-win-crt-math-l1-1-0.dll, api-ms-win-crt-convert-l1-1-0.dll, api-ms-win-crt-heap-l1-1-0.dll, api-ms-win-crt-time-l1-1-0.dll, api-ms-win-crt-environment-l1-1-0.dll, api-ms-win-crt-conio-l1-1-0.dll, api-ms-win-crt-filesystem-l1-1-0.dll, api-ms-win-crt-locale-l1-1-0.dll, HID.DLL

## Raw ASCII markers
Unreal: 5, UE4: 37, Fortnite: 3653, FortniteGame: 828, /Game/: 2, /Engine/: 4, FMaterial: 0, .pdb: 1

## Caution
This audit cannot prove absence of runtime decryption. Match original machine instructions against Unreal Engine source before trusting Ghidra pseudocode.

Full machine-code excerpts, section data and imports are in the JSON report.
