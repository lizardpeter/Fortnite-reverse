#!/usr/bin/env python3
"""Temporary source-exact Naga 30.0.1 Vulkan BindingArray comparison fix.

No fallback equations; leave input SPIR-V untouched. Tested only with
original Valve CS2 shader binaries until safe for engine integration.
"""
from pathlib import Path
import sys
path=Path(sys.argv[1])
s=path.read_text()
old="""    let original_ty = &arena[var.ty];
    let original_ty_span = arena.get_span(var.ty);
    let ty_inner = match original_ty.inner {"""
new="""    // Source-backed SPIR-V descriptor arrays can be sampler/image binding
    // arrays, not only standalone Image or Sampler types. Work from a clone
    // so the canonicalized child type may be inserted into the same arena.
    let original_ty = arena[var.ty].clone();
    let original_ty_span = arena.get_span(var.ty);
    let name = original_ty.name.clone();
    let ty_inner = match original_ty.inner {"""
assert s.count(old)==1,"upstream Naga frontend layout diverged"
s=s.replace(old,new)
old2="""        crate::TypeInner::Sampler { .. } => crate::TypeInner::Sampler { comparison: true },
        ref other => unreachable!("Unexpected type for comparison mutation: {:?}", other),"""
new2="""        crate::TypeInner::Sampler { .. } => crate::TypeInner::Sampler { comparison: true },
        crate::TypeInner::BindingArray { base, size } => {
            // The source shader indexes an original descriptor array.
            // Do NOT flatten a dynamic source index or substitute one
            // texture: re-type only the array's inner resource.
            let base_ty = arena[base].clone();
            let patch = match base_ty.inner {
                crate::TypeInner::Image {
                    class: crate::ImageClass::Sampled { multi, .. },
                    dim,
                    arrayed,
                } => crate::TypeInner::Image {
                    class: crate::ImageClass::Depth { multi },
                    dim,
                    arrayed,
                },
                crate::TypeInner::Sampler { .. } =>
                    crate::TypeInner::Sampler { comparison: true },
                _ => return false,
            };
            let new_base = arena.insert(
                crate::Type {
                    name: base_ty.name.clone(),
                    inner: patch,
                },
                arena.get_span(base),
            );
            crate::TypeInner::BindingArray {
                base: new_base,
                size,
            }
        },
        ref other => {
            log::warn!("Unsupported original SPIR-V comparison type {other:?}");
            return false;
        },"""
assert s.count(old2)==1,"upstream Naga comparison patch site diverged"
s=s.replace(old2,new2)
old3="""    let name = original_ty.name.clone();
    var.ty = arena.insert("""
new3="""    var.ty = arena.insert("""
assert s.count(old3)==1,"Naga original shadow replacement not found"
s=s.replace(old3,new3)
path.write_text(s)
print(f"Patched original Naga BindingArray comparison typing: {path}")
