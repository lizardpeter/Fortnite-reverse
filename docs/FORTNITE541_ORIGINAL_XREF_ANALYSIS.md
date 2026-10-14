# Fortnite 5.41 native shader/material xref index

## Purpose

The fully indexed original .pdata dump has 291,701 real Ghidra C bodies and
56 unresolved entries. Searching generated function names and C pseudocode
has not identified the original Unreal material/shader engine functions.
This pass works **from retail executable bytes**, not the pseudocode keyword
index. It does not rerun the 291,757-function Ghidra export.

Run \`.github/workflows/fortnite541-original-xrefs.yml\` against the
SHA256-authenticated FortniteClient-Win64-Shipping.exe. After the workflow
succeeds it saves these **new** evidence products to the existing
\`re/fortnite541-ghidra-full\` branch in
\`decompilation/fortnite541/index/original_xrefs/\`:

- \`summary.json\` — validated original PE identity, .pdata extent counts,
  and source evidence counts. The run can legitimately find zero candidates.
- \`string_reference_evidence.jsonl.gz\` — original .rdata/.data anchor
  addresses, literal material/shader/RHI/texture terms and RIP-relative
  original machine-instruction witnesses.
- \`candidate_function_evidence.jsonl.gz\` — original .pdata function start,
  referenced anchor addresses, bounded direct-call edges into/out of the
  candidate, and weak ranking for human verification.

No original executable or raw retail section bytes are committed. The
output links to the independent address-to-C lookup in
\`decompilation/fortnite541/index/original_function_lookup.jsonl.gz\`;
addresses remain RVAs, not inferred class names. The scan includes ASCII
and UTF-16LE strings in readable non-executable PE sections and resolves
x64 RIP-relative operands by their effective virtual address.

### Limits and next use

The scanner linearly decodes instruction bytes **within original .pdata
function boundaries**. Its putative references and calls are not
control-flow reachable proofs; an instruction may be unreachable, misdecoded
after a branch, or a non-symbolic address could share a string range. It does
not infer functions from missing unwind entries, read a PDB, reconstruct
C++ type layouts, or recover compiled shader semantics.

After the source report is committed, prioritize candidates with direct
references to material/shader-map serializer or cache terms. Confirm each
candidate with the original Ghidra CFG, nearby callers, field offsets,
string uses and independent asset/material dependencies. Only confirmed
functions should be annotated as Unreal symbols. Specifically, an AMD
\`agsDriverExtensionsDX11_SetDiskShaderCacheEnabled\` name must **not**
be mislabeled \`FMaterialShaderMap\`.

## Local development check

\`\`\`sh
python -m pip install 'capstone>=5,<6'
python -m unittest discover -s crates/fortnite_541/tools/tests -p 'test_original_win64_xrefs.py' -v
\`\`\`

Run the analyzer only with the exact authenticated original executable,
never against a substituted build:

\`\`\`sh
python crates/fortnite_541/tools/index_original_win64_xrefs.py \
  --exe /local/original/FortniteClient-Win64-Shipping.exe \
  --out /tmp/fortnite541-xrefs
\`\`\`
