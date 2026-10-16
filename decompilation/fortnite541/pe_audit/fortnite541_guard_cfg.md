# Fortnite 5.41 authenticated guarded-execution CFG audit

Read-only static study of original SHA256-verified shipping EXE. Not an unpacker or a decryption claim.

| Root | Decoded instruction starts | CALL references | Memory-write operations | RIP writes into executable section | Outbound targets |
|---|---:|---:|---:|---:|---:|
| entry_call_handoff (0x4419) | 8 | 0 | 1 | 0 | 2 |
| secondary_register_guard (0x5c83d4e) | 35 | 0 | 0 | 0 | 2 |
| secondary_shared_code (0x5bc8859) | 21 | 0 | 6 | 0 | 2 |
| original_entrypoint (0x351ca98) | 3 | 1 | 0 | 0 | 1 |
| handoff_branch_body (0xbcf126) | 14 | 1 | 3 | 0 | 1 |
| shared_code_branch_body (0x5c32a2a) | 9 | 1 | 3 | 0 | 2 |
| secondary_guard_alignment_branch (0xeb6b64) | 2 | 0 | 0 | 0 | 1 |
| secondary_guard_nonalign_branch (0x597bc9) | 2 | 0 | 0 | 0 | 1 |

## entry_call_handoff
Root RVA: 0x4419
Static interpretation region: 0x4419–0x5419
Calls: 
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x12b7, 0xbcf126

## secondary_register_guard
Root RVA: 0x5c83d4e
Static interpretation region: 0x5c83d4e–0x5c84d4e
Calls: 
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x597bc9, 0xeb6b64

## secondary_shared_code
Root RVA: 0x5bc8859
Static interpretation region: 0x5bc8859–0x5bc9859
Calls: 
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x8a9cd7, 0x5c32a2a

## original_entrypoint
Root RVA: 0x351ca98
Static interpretation region: 0x351ca98–0x351caaa
Calls: 0x5ae6509
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x5ae6509

## handoff_branch_body
Root RVA: 0xbcf126
Static interpretation region: 0xbcf126–0xbcf82c
Calls: unresolved
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x3d0c9

## shared_code_branch_body
Root RVA: 0x5c32a2a
Static interpretation region: 0x5c32a2a–0x5c33a2a
Calls: 0x5d986de
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x5bd4b1b, 0x5d986de

## secondary_guard_alignment_branch
Root RVA: 0xeb6b64
Static interpretation region: 0xeb6b64–0xeb7b64
Calls: 
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0x1568966

## secondary_guard_nonalign_branch
Root RVA: 0x597bc9
Static interpretation region: 0x597bc9–0x598bc9
Calls: 
Resolved RIP-relative writes into executable section: 0
Outbound preview targets: 0xeb6b64

## Limits
An unknown-pointer memory store does not establish that program code is being decrypted. No runtime memory was inspected.
See the JSON file for independently sourced original instruction previews and followable control-flow edges.
