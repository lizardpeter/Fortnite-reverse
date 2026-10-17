"""Tests for source-metadata-only Fortnite 5.41 public probe reports."""
import json
import pathlib
import tempfile
import unittest

from report_public_asset_probe import summarize
from probe_remote_541_paks import TARGETS, FOLIAGE_TARGETS


class SourceProbeMetadataTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = pathlib.Path(self.work.name) / "source"
        (self.root / "FortniteGame" / "Content").mkdir(parents=True)
        self.asset = self.root / "FortniteGame" / "Content" / "fixture.uasset"
        self.asset.write_bytes(b"test copyrighted content is NEVER in metadata\n")

    def save_manifest(self, entries):
        (self.root / "fortnite541-source-manifest.json").write_text(
            json.dumps({"files": entries}), encoding="utf-8"
        )

    def test_verified_relative_manifest_emits_hash_metadata_only(self):
        self.save_manifest([{
            "path": "FortniteGame/Content/fixture.uasset",
            "bytes": self.asset.stat().st_size,
        }])
        summary = summarize(self.root, "terrain")
        self.assertEqual(summary["verified_files"], 1)
        self.assertEqual(summary["verified_bytes"], self.asset.stat().st_size)
        self.assertEqual(summary["files"][0]["path"], "FortniteGame/Content/fixture.uasset")
        self.assertEqual(len(summary["files"][0]["sha256"]), 64)
        self.assertNotIn("test copyrighted content", json.dumps(summary))
        self.assertTrue(summary["does_not_include_source_asset_bytes"])

    def test_verified_absolute_split_pak_manifest(self):
        (self.root / "verified-541-source-manifest.json").write_text(
            json.dumps([{
                "path": str(self.asset),
                "size": self.asset.stat().st_size,
                "sha1": "0123456789abcdef" * 2 + "01234567",
            }]), encoding="utf-8"
        )
        self.assertEqual(summarize(self.root, "sky")["verified_files"], 1)

    def test_original_skydome_source_input_targets_are_explicit(self):
        """Probe actual source packages, not an inferred sky texture set."""
        paths = [path.lstrip("/") for path in TARGETS]
        self.assertEqual(len(paths), len(set(paths)))
        required = [
            "Packages/Fortress_Sky/SkyDome/Master/M_SkyDome",
            "Packages/Fortress_Sky/Materials/FinalCloudNormalAndHeightMap",
            "Packages/Fortress_Sky/SkyDome/Master/T_SkyDome_Stars_Sharp",
            "Packages/Fortress_Sky/Textures/Galaxy_Background",
            "Packages/Fortress_Sky/Textures/Galaxy_Background_Tiling",
            "VisualThreatManager/StormVisuals/LargeClouds/T_StormCloudDetail01_M",
        ]
        for base in required:
            for suffix in (".uasset", ".uexp"):
                self.assertIn(base + suffix, paths)

    def test_foliage_research_targets_match_hidden_runtime_sources(self):
        names = [x.lstrip("/") for x in FOLIAGE_TARGETS]
        self.assertEqual(len(names), len(set(names)))
        for base in (
            "Athena/Environments/Landscape/Foliage/MI_Athena_Grass_TopoColor",
            "Environments/Foliage/Materials/M_FieldGrassMatching",
            "Athena/Environments/Landscape/Foliage/Athena_SM_WavyGrass_TopologyColor",
            "Environments/Foliage/Meshes/S_WavyGrass_01",
        ):
            self.assertIn(base + ".uasset", names)
            self.assertIn(base + ".uexp", names)

    def test_disallow_manifest_size_mismatch(self):
        self.save_manifest([{
            "path": "FortniteGame/Content/fixture.uasset",
            "bytes": 1,
        }])
        with self.assertRaisesRegex(ValueError, "manifest size mismatch"):
            summarize(self.root, "terrain")

    def test_disallow_missing_manifest_entries_and_extra_files(self):
        self.save_manifest([{
            "path": "FortniteGame/Content/fixture.uasset",
            "bytes": self.asset.stat().st_size,
        }])
        (self.root / "FortniteGame" / "Content" / "rogue.uexp").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "count mismatch"):
            summarize(self.root, "terrain")

    def test_disallow_absolute_source_paths_outside_runner_directory(self):
        self.save_manifest([{
            "path": "/tmp/another-user-private-asset.uasset",
            "bytes": self.asset.stat().st_size,
        }])
        with self.assertRaises(ValueError):
            summarize(self.root, "terrain")


if __name__ == "__main__":
    unittest.main()
