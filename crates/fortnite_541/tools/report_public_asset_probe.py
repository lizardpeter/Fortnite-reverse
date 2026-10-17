#!/usr/bin/env python3
"""Metadata-only report for original Fortnite 5.41 public-runner asset probes.

Source packages are never copied into Git or the public Actions artifact.
Only path names, lengths, source-verified digest claims and independent hashes
are retained. The remote fetching scripts do the actual UE4 PAK SHA-1
validation before this report is created.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

SOURCE_SUFFIXES = frozenset((".uasset", ".uexp", ".umap", ".ubulk"))
MANIFEST_NAMES = ("fortnite541-source-manifest.json", "verified-541-source-manifest.json")


def summarize(root: pathlib.Path, scope: str) -> dict:
    if not root.is_dir():
        raise ValueError("original source directory missing")
    manifest_paths = [root / name for name in MANIFEST_NAMES if (root / name).is_file()]
    if len(manifest_paths) != 1:
        raise ValueError(f"expected exactly one verified source manifest, got {len(manifest_paths)}")
    raw = json.loads(manifest_paths[0].read_text(encoding="utf-8"))
    claimed = raw if isinstance(raw, list) else raw.get("files")
    if not isinstance(claimed, list) or not claimed:
        raise ValueError("verified original source manifest has no files")
    root_abs = root.resolve()
    observed = []
    names = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in MANIFEST_NAMES:
            continue
        if path.is_symlink():
            raise ValueError("source probe refuses symlink files")
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            raise ValueError(f"unrecognized original source file extension: {path.suffix}")
        rel = path.resolve().relative_to(root_abs).as_posix()
        if rel in names:
            raise ValueError("duplicate original source package path")
        names.add(rel)
        digest = hashlib.sha256()
        with path.open("rb") as fh:
            while chunk := fh.read(1024 * 1024):
                digest.update(chunk)
        observed.append({
            "path": rel, "bytes": path.stat().st_size, "sha256": digest.hexdigest(),
        })
    if len(observed) != len(claimed):
        raise ValueError(
            f"manifest/source count mismatch: {len(claimed)} verified, "
            f"{len(observed)} source files"
        )
    claimed_sizes = {}
    for entry in claimed:
        if not isinstance(entry, dict):
            raise ValueError("malformed verified source manifest entry")
        name = entry.get("path")
        if not isinstance(name, str) or not name:
            raise ValueError("verified source manifest entry lacks a path")
        # The fetchers differ in path style. Main PAK uses relative internal
        # archive paths; split-PAK manifest uses absolute destination paths.
        normalized = pathlib.PurePosixPath(name.replace("\\", "/"))
        if normalized.is_absolute():
            path = pathlib.Path(name).resolve()
            rel = path.relative_to(root_abs).as_posix()
        else:
            rel = normalized.as_posix()
        if rel in claimed_sizes:
            raise ValueError("duplicate source manifest entry")
        claimed_sizes[rel] = int(entry["bytes"] if "bytes" in entry else entry["size"])
    for entry in observed:
        if claimed_sizes.get(entry["path"]) != entry["bytes"]:
            raise ValueError(f"original source manifest size mismatch: {entry['path']}")
    return {
        "probe": "Fortnite 5.41 source-authenticated public-runner metadata",
        "scope": scope,
        "verified_files": len(observed),
        "verified_bytes": sum(entry["bytes"] for entry in observed),
        "files": observed,
        "verified_pak_manifest": manifest_paths[0].name,
        "does_not_include_source_asset_bytes": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=pathlib.Path, required=True)
    parser.add_argument("--scope", choices=("terrain", "sky", "foliage"), required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    report = summarize(args.source_root, args.scope)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("FORTNITE541_PUBLIC_SOURCE_PROBE_METADATA_VERIFIED",
          report["scope"], report["verified_files"], report["verified_bytes"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        print(f"FORTNITE541_PUBLIC_SOURCE_PROBE_FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
