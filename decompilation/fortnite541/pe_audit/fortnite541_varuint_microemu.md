# Authenticated native ULEB128 micro-emulation

Original EXE SHA256 verified: 7a1805869283ffa74df400d9e32dda4a1b6c07ebb0e0a1ce027ee846a18bd108

Only the original loop at RVA 0x5c61e26 and accumulator update at 0x5bf2a18 execute in a no-syscall Unicorn sandbox. Execution stops before further dispatch at 0x5bf2a34.

| Synthetic input | Original decoded u32 | Accumulated u32 | Bytes consumed | Actual x64 instructions |
|---|---:|---:|---:|---:|
| zero | 0 | 14 | 1 | 33 |
| one | 1 | 15 | 1 | 33 |
| single_max | 127 | 141 | 1 | 33 |
| two_bytes | 128 | 142 | 2 | 56 |
| three_bytes | 624485 | 624499 | 3 | 79 |
| u32_max | 4294967295 | 13 | 5 | 125 |
| read_until_stop | 0 | 14 | 2 | 56 |
| original_x86_shift_wrap | 8 | 22 | 6 | 148 |

Every case agrees with the Rust source-equivalent 32-bit wrapping arithmetic. This is not a claim that any Fortnite game logic has been decrypted.
