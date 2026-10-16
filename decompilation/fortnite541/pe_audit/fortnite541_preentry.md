# Fortnite 5.41 pre-entrypoint / trampoline census

SHA-256 verified retail executable; static inspection only. No game execution.

## Pre-entrypoint candidates
TLS directory: **present**.
Raw TLS callback pointers: **0**.

## Exact original entrypoint
Original RVA: 0x351ca98
Original E8 target: 0x5ae6509

## Original unwind starts and trampoline patterns
Unique unwind starts: 291757
Starts examined: 291757
Raw E8 byte-pattern hits into second .text within first 24 bytes: 35
Raw E8 hits at offset 0: 0
Raw E8 byte patterns into original trampoline by offset: {4: 1}
Deterministic non-entrypoint controls: {'samples': 10000, 'first_byte_0xE8': 46, 'raw_E8_into_secondary': 2}

## Most frequent E8 byte-pattern destinations
| Destination RVA | Raw hits | First decoded mnemonic |
|---|---:|---|
| 0x5bc8859 | 3 | push |
| 0x5ec4aeb | 1 | cmpsd |
| 0x5c45e53 | 1 | <invalid> |
| 0x5c7b560 | 1 | clc |
| 0x5fb99ee | 1 | and |
| 0x5ef728f | 1 | movabs |
| 0x5ca4f6c | 1 | xchg |
| 0x5c3e046 | 1 | out |
| 0x5d8835e | 1 | <invalid> |
| 0x5d34915 | 1 | or |
| 0x5ee8754 | 1 | add |
| 0x5e555cd | 1 | movabs |

## Direct original x64 near-JMP gate chain
### entry_aligned_path
0x88664 -> 0x2e3fd6
0x2e3fd6 -> nonlinear_or_suspicious_instruction
### entry_unaligned_path
0x2db999 -> 0x88664
0x88664 -> 0x2e3fd6
0x2e3fd6 -> nonlinear_or_suspicious_instruction
### common_secondary_call_target
0x5bc8859 -> no_bounded_direct_jump

## Interpretive limits
A byte-pattern hit is not a verified instruction or executable call. The report compares original function starts against deterministic non-entrypoint controls and records the original source hashes. No plaintext reconstruction has been claimed.

See the JSON report for TLS callback snippets, protected branch targets, and frequency data.
