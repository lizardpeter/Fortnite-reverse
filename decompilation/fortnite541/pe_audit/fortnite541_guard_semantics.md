# Fortnite 5.41 original guard callee / bitstream analysis

Source SHA-256 verified. Static analysis of original on-disk instructions; neither plaintext game code nor runtime execution is claimed.

| Native root | Instructions decoded | Calls | Register-addressed writes | Direct executable-section writes | Bitwise operations |
|---|---:|---:|---:|---:|---:|
| guard_argument_setup (0x5c4ce84) | 15 | 1 | 0 | 0 | 0 |
| guard_call_target (0x5b0cf49) | 20 | 0 | 0 | 0 | 0 |
| guard_call_continuation (0x5cda17b) | 7 | 0 | 0 | 1 | 0 |
| seven_bit_reader (0x5c61e26) | 24 | 0 | 1 | 0 | 2 |
| seven_bit_reader_caller (0x5d986de) | 10 | 0 | 0 | 0 | 0 |
| known_text_store (0x5bd4b1b) | 7 | 0 | 0 | 1 | 0 |

## guard_argument_setup
Original source RVA: 0x5c4ce84
Call targets: 0x5b0cf49
Writes through register-indirect pointers: 0
Bit operations: 

## guard_call_target
Original source RVA: 0x5b0cf49
Call targets: 
Writes through register-indirect pointers: 0
Bit operations: 

## guard_call_continuation
Original source RVA: 0x5cda17b
Call targets: 
Writes through register-indirect pointers: 0
Bit operations: 

## seven_bit_reader
Original source RVA: 0x5c61e26
Call targets: 
Writes through register-indirect pointers: 1
Bit operations: and 0x7f, add 0x7

## seven_bit_reader_caller
Original source RVA: 0x5d986de
Call targets: 
Writes through register-indirect pointers: 0
Bit operations: 

## known_text_store
Original source RVA: 0x5bd4b1b
Call targets: 
Writes through register-indirect pointers: 0
Bit operations: 

## Explicit limits
Disassembly, branches, and memory operations are observed on disk, not proven runtime code execution.
A memory write through RCX/RDX or another register may modify a code page or ordinary data; without runtime pointer values the destination cannot be determined.
The 7-bit / 0x7F pattern suggests variable-length integer decoding but its exact algorithm is not established until more loop and caller context is recovered.
No decrypted executable bytes have been produced.
