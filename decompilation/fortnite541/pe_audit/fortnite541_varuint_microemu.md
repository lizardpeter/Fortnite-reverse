# Authenticated native ULEB128 micro-emulation

Original EXE SHA256 verified: 7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108

Only the original loop at RVA 0x5c61e26 executed in a no-syscall Unicorn sandbox. It stops BEFORE successor block 0x5bf2a18.

| Synthetic input | Original x64 result | Bytes consumed | Actual executed instructions |
|---|---:|---:|---:|
| zero | 0 | 1 | 24 |
| one | 1 | 1 | 24 |
| single_max | 127 | 1 | 24 |
| two_bytes | 128 | 2 | 47 |
| three_bytes | 624485 | 3 | 70 |
| u32_max | 4294967295 | 5 | 116 |
| read_until_stop | 0 | 2 | 47 |
| original_x86_shift_wrap | 8 | 6 | 139 |

Every case agrees with the Rust source-equivalent 32-bit wrapping arithmetic. This is not a claim that any Fortnite game logic has been decrypted.
