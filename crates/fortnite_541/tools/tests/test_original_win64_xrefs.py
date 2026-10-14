"""Synthetic-only contracts for source-index extraction (never invent retail coverage)."""
import importlib.util
import struct
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "index_original_win64_xrefs.py"
spec = importlib.util.spec_from_file_location("retail_xrefs", FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class XrefTests(unittest.TestCase):
    def test_pe64_sections_and_unwind_extents(self):
        b = bytearray(0x900)
        b[:2] = b"MZ"
        struct.pack_into("<I", b, 0x3c, 0x80)
        b[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<HH", b, 0x84, 0x8664, 2)
        struct.pack_into("<H", b, 0x84 + 16, 0xf0)
        opt = 0x84 + 20
        struct.pack_into("<H", b, opt, 0x20b)
        struct.pack_into("<Q", b, opt + 24, 0x140000000)
        sh = opt + 0xf0
        for off, name, va, raw, flags in (
            (sh, b".text", 0x1000, 0x400, 0x60000020),
            (sh + 40, b".pdata", 0x3000, 0x600, 0x40000040),
        ):
            b[off:off + 8] = name.ljust(8, b"\x00")
            struct.pack_into("<IIII", b, off + 8, 0x100, va, 0x100, raw)
            struct.pack_into("<I", b, off + 36, flags)
        struct.pack_into("<III", b, 0x600, 0x1000, 0x1010, 0x5000)
        image, sections = module.parse_pe(b)
        self.assertEqual(image, 0x140000000)
        self.assertEqual(module.original_pdata(b, sections), [(0x1000, 0x1010)])
        self.assertEqual(len(module.function_code(b, sections, 0x1000, 0x1010)), 16)

    def test_string_anchors_are_addressed_not_named_functions(self):
        ascii_data = b"FMaterialShaderMap\x00other strings\x00"
        utf16 = "MaterialUniformExpression".encode("utf-16le")
        blob = ascii_data + b"\x00\x00\x00" + utf16
        sec = {"name": ".rdata", "va": 0x2000, "rawptr": 0,
               "rawsize": len(blob), "flags": 0x40000040}
        anchors = module.scan_anchors(blob, [sec])
        self.assertIn(0x2000, anchors)
        self.assertTrue(any(a["encoding"] == "utf16le" for a in anchors.values()))
        self.assertEqual(anchors[0x2000]["score"], 20)
        self.assertFalse(any("function_name" in a for a in anchors.values()))

    def test_rip_reference_is_original_function_address_evidence(self):
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        image = 0x140000000
        code = b"\x48\x8d\x05\xf9\x0f\x00\x00\xc3"
        text_section = {"name": ".text", "va": 0x1000, "rawptr": 0,
                        "rawsize": len(code), "flags": 0x60000020}
        anchors = {0x2000: {"byte_length": 20, "score": 10}}
        refs, hits, incoming, outgoing, visited, skipped, calls = module.discover(
            code, image, [text_section], [(0x1000, 0x1008)], anchors
        )
        self.assertEqual((visited, skipped), (1, 0))
        self.assertEqual(refs[0x2000][0]["target_rva"], "0x00002000")
        self.assertIn(0x1000, hits)
        self.assertEqual(dict(incoming), {})
        self.assertEqual(dict(outgoing), {})


    def test_source_pointer_slot_reaches_original_function(self):
        image = 0x140000000
        data = struct.pack("<Q", image + 0x2000)
        sec = {"name": ".rdata", "va": 0x3000, "rawptr": 0,
               "rawsize": len(data), "flags": 0x40000040}
        anchors = {0x2000: {"byte_length": 20, "score": 10}}
        pointers = module.original_string_pointer_slots(data, image, [sec], anchors)
        self.assertEqual(pointers, {0x3000: 0x2000})
        code = b"\x48\x8d\x05\xf9\x1f\x00\x00\xc3"
        text = {"name": ".text", "va": 0x1000, "rawptr": 0,
                "rawsize": len(code), "flags": 0x60000020}
        refs, hits, _in, _out, visited, skipped, calls = module.discover(
            code, image, [text], [(0x1000, 0x1008)], anchors, pointers
        )
        self.assertEqual((visited, skipped), (1, 0))
        self.assertEqual(refs[0x2000][0]["reference_kind"],
                         "indirect_original_va_pointer_slot")
        self.assertIn(0x1000, hits)


    def test_original_linear_direct_call_is_preserved(self):
        import io
        image = 0x140000000
        # CALL 0x1008, RET, padding, RET. The second retail extent
        # starts exactly at 0x1008.
        code = b"\xe8\x03\x00\x00\x00\xc3\x90\x90\xc3"
        text = {"name": ".text", "va": 0x1000, "rawptr": 0,
                "rawsize": len(code), "flags": 0x60000020}
        out = io.StringIO()
        *_, counters = module.discover(
            code, image, [text], [(0x1000, 0x1008), (0x1008, 0x1009)],
            {}, edges_sink=out
        )
        rows = [__import__("json").loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["callsite_rva"], "0x00001000")
        self.assertEqual(rows[0]["target_original_pdata_start"], "0x00001008")
        self.assertTrue(rows[0]["target_is_exact_original_entry"])
        self.assertEqual(counters["linear_direct_calls_to_exact_entries"], 1)


if __name__ == "__main__":
    unittest.main()
