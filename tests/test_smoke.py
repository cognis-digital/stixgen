"""Smoke tests for STIXGEN. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from stixgen import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    classify_ioc,
    parse_iocs,
    build_bundle,
    summarize,
    render_html,
)
from stixgen.cli import main  # noqa: E402


class TestClassify(unittest.TestCase):
    def test_ipv4(self):
        ioc = classify_ioc("203.0.113.66")
        self.assertEqual(ioc.kind, "ipv4-addr")
        self.assertIn("ipv4-addr:value = '203.0.113.66'", ioc.pattern)
        self.assertTrue(ioc.valid)

    def test_ipv6(self):
        ioc = classify_ioc("2001:db8:dead:beef::1337")
        self.assertEqual(ioc.kind, "ipv6-addr")

    def test_domain(self):
        ioc = classify_ioc("bad.example.net")
        self.assertEqual(ioc.kind, "domain-name")

    def test_url(self):
        ioc = classify_ioc("https://evil.example.com/x")
        self.assertEqual(ioc.kind, "url")
        self.assertEqual(ioc.severity, "high")

    def test_email(self):
        ioc = classify_ioc("billing@bad-example.net")
        self.assertEqual(ioc.kind, "email-addr")

    def test_md5(self):
        ioc = classify_ioc("d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(ioc.kind, "file")
        self.assertIn("MD5", ioc.pattern)

    def test_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ioc = classify_ioc(h)
        self.assertEqual(ioc.kind, "file")
        self.assertIn("SHA-256", ioc.pattern)

    def test_cve(self):
        ioc = classify_ioc("cve-2026-31337")
        self.assertEqual(ioc.kind, "vulnerability")
        self.assertEqual(ioc.value, "CVE-2026-31337")

    def test_junk_unknown(self):
        ioc = classify_ioc("this is not an indicator")
        self.assertEqual(ioc.kind, "unknown")
        self.assertFalse(ioc.valid)

    def test_refang_url_and_domain(self):
        self.assertEqual(
            classify_ioc("hxxp[:]//evil[.]example[.]com/x").kind, "url")
        self.assertEqual(classify_ioc("bad[.]example[.]net").kind, "domain-name")

    def test_deterministic_id(self):
        b1 = build_bundle([classify_ioc("203.0.113.66")])
        b2 = build_bundle([classify_ioc("203.0.113.66")])
        ind1 = [o for o in b1["objects"] if o["type"] == "indicator"][0]
        ind2 = [o for o in b2["objects"] if o["type"] == "indicator"][0]
        self.assertEqual(ind1["id"], ind2["id"])


class TestParseAndBundle(unittest.TestCase):
    SAMPLE = (
        "# comment\n"
        "203.0.113.66\n"
        "203.0.113.66\n"  # dup, should collapse
        "bad.example.net\n"
        "CVE-2026-31337\n"
        "garbage line here\n"
    )

    def test_parse_dedupes_and_comments(self):
        iocs = parse_iocs(self.SAMPLE)
        # 3 unique valid + 1 unknown = 4 (dup ip collapsed, comment skipped)
        kinds = sorted(i.kind for i in iocs)
        self.assertEqual(
            kinds, ["domain-name", "ipv4-addr", "unknown", "vulnerability"])

    def test_bundle_structure(self):
        iocs = parse_iocs(self.SAMPLE)
        bundle = build_bundle(iocs, producer="TestOrg")
        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("identity", types)
        self.assertIn("indicator", types)
        self.assertIn("vulnerability", types)
        for o in bundle["objects"]:
            self.assertEqual(o["spec_version"], "2.1")
            self.assertTrue("id" in o and "created" in o)
        # unknown line never becomes an object
        self.assertEqual(types.count("indicator"), 2)

    def test_summary(self):
        s = summarize(parse_iocs(self.SAMPLE))
        self.assertEqual(s["valid"], 3)
        self.assertEqual(s["invalid"], 1)
        self.assertEqual(s["top_severity"], "medium")


class TestRenderHTML(unittest.TestCase):
    def test_html_self_contained(self):
        iocs = parse_iocs("203.0.113.66\nhttps://evil.example.com/x\n")
        s = summarize(iocs)
        out = render_html(iocs, s, "Greenway SOC", "bundle--x")
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)  # inline CSS, self-contained
        self.assertIn("Greenway SOC", out)
        self.assertIn("203.0.113.66", out)

    def test_html_escapes(self):
        iocs = parse_iocs("https://evil.example.com/<script>\n")
        out = render_html(iocs, summarize(iocs), "P", "b--1")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)


class TestCLI(unittest.TestCase):
    def _capture(self, argv):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        self.demo = os.path.join(
            os.path.dirname(__file__), "..", "demos", "01-basic", "iocs.txt")

    def test_version(self):
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(TOOL_VERSION, out.getvalue())
        self.assertEqual(TOOL_NAME, "stixgen")

    def test_no_subcommand_returns_1(self):
        code, _, _ = self._capture([])
        self.assertEqual(code, 1)

    def test_build_table_findings_exit_2(self):
        code, out, _ = self._capture(["build", self.demo, "--format", "table"])
        self.assertEqual(code, 2)  # findings present
        self.assertIn("STIXGEN", out)
        self.assertIn("ipv4-addr", out)

    def test_build_json_is_valid_bundle(self):
        code, out, _ = self._capture(["build", self.demo, "--format", "json"])
        self.assertEqual(code, 2)
        bundle = json.loads(out)
        self.assertEqual(bundle["type"], "bundle")
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("vulnerability", types)
        self.assertEqual(types.count("indicator"), 7)

    def test_build_empty_exit_0(self):
        # an all-comment file yields no valid IOCs
        import tempfile
        with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False, encoding="utf-8") as fh:
            fh.write("# nothing here\n\n")
            path = fh.name
        try:
            code, _, _ = self._capture(["build", path, "--format", "json"])
            self.assertEqual(code, 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
