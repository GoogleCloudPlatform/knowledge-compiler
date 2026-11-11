# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
test_extract_hardening.py
Unit tests for Wave 2 extract_source.py hardening:
- Source parity across scripts/ and skills/
- PDF fallback page anchors and accurate page_count
- Tabular row caps (--max-rows) and pipe escaping
- URL fetch SSRF prevention, redirect safety, timeout, and 20 MiB cap
- OOXML zip bomb, traversal, symlink, and XML entity bomb prevention
"""
from __future__ import annotations

import csv
import io
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

# Ensure scripts directory is on sys.path for hermetic execution in 1P and 3P
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import extract_source


class TestExtractSourceParity(unittest.TestCase):
    """Verifies all copies of extract_source.py remain byte-for-byte identical."""

    def test_extract_source_byte_parity(self):
        repo_root = Path(__file__).resolve().parent.parent
        src1 = repo_root / "scripts" / "extract_source.py"
        src2 = repo_root / "skills" / "ingest" / "scripts" / "extract_source.py"
        src3 = repo_root / ".agents" / "skills" / "ingest" / "scripts" / "extract_source.py"

        self.assertTrue(src1.exists(), f"Missing {src1}")
        self.assertTrue(src2.exists(), f"Missing {src2}")

        bytes1 = src1.read_bytes()
        bytes2 = src2.read_bytes()

        self.assertEqual(bytes1, bytes2, "scripts/ and skills/ingest/ copies differ!")

        # In 1P environment, verify .agents/ copy is also byte-for-byte identical
        if (repo_root / ".agents").is_dir():
            self.assertTrue(src3.exists(), f"Missing {src3}")
            bytes3 = src3.read_bytes()
            self.assertEqual(bytes1, bytes3, "scripts/ and .agents/skills/ingest/ copies differ!")


class TestPdfExtractionHardening(unittest.TestCase):
    """Verifies PDF extraction page anchors and accurate page_count fallback."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.vault_root = Path(self.tmp_dir.name)
        (self.vault_root / "raw").mkdir(parents=True, exist_ok=True)
        self.dummy_pdf = self.vault_root / "raw" / "sample.pdf"
        self.dummy_pdf.write_bytes(b"%PDF-1.4 dummy binary content")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_pdftotext_fallback_multipage(self):
        stdout_content = "First page text\fSecond page text\fThird page text\f"
        mock_res = mock.MagicMock(returncode=0, stdout=stdout_content)

        with mock.patch.dict("sys.modules", {"pypdf": None}), \
             mock.patch("subprocess.run", return_value=mock_res) as mock_run:
            ok = extract_source.extract_pdf(self.dummy_pdf, self.vault_root, force=True)
            self.assertTrue(ok)
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            self.assertEqual(kwargs.get("timeout"), 30)

        out_md = self.vault_root / "raw" / "sample.md"
        self.assertTrue(out_md.exists())
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("pages_count: 3", content)
        self.assertIn("## Page 1\n\nFirst page text\n\n---", content)
        self.assertIn("## Page 2\n\nSecond page text\n\n---", content)
        self.assertIn("## Page 3\n\nThird page text\n\n---", content)
        self.assertNotIn("## Page 4", content)

    def test_pdftotext_fallback_empty_output(self):
        mock_res = mock.MagicMock(returncode=0, stdout="")
        with mock.patch.dict("sys.modules", {"pypdf": None}), \
             mock.patch("subprocess.run", return_value=mock_res):
            ok = extract_source.extract_pdf(self.dummy_pdf, self.vault_root, force=True)
            self.assertTrue(ok)

        out_md = self.vault_root / "raw" / "sample.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("pages_count: 0", content)
        self.assertNotIn("## Page 1", content)

    def test_pdftotext_fallback_single_page_no_trailing_ff(self):
        mock_res = mock.MagicMock(returncode=0, stdout="Single page without trailing form feed")
        with mock.patch.dict("sys.modules", {"pypdf": None}), \
             mock.patch("subprocess.run", return_value=mock_res):
            ok = extract_source.extract_pdf(self.dummy_pdf, self.vault_root, force=True)
            self.assertTrue(ok)

        out_md = self.vault_root / "raw" / "sample.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("pages_count: 1", content)
        self.assertIn("## Page 1\n\nSingle page without trailing form feed\n\n---", content)
        self.assertNotIn("## Page 2", content)

    def test_pdftotext_timeout_fails_closed(self):
        with mock.patch.dict("sys.modules", {"pypdf": None}), \
             mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["pdftotext"], timeout=30)):
            ok = extract_source.extract_pdf(self.dummy_pdf, self.vault_root, force=True)
            self.assertFalse(ok)


class TestTabularRowCaps(unittest.TestCase):
    """Verifies row capping (--max-rows) and pipe escaping in CSV/XLSX extractors."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.vault_root = Path(self.tmp_dir.name)
        (self.vault_root / "raw").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_extract_csv_default_cap(self):
        csv_file = self.vault_root / "raw" / "inventory.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ID", "Item", "Quantity"])
            for i in range(1, 201):
                writer.writerow([f"ID_{i}", f"Product {i}", i * 10])

        ok = extract_source.extract_csv(csv_file, self.vault_root, force=True)
        self.assertTrue(ok)
        out_md = self.vault_root / "raw" / "inventory.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("| ID_1 | Product 1 | 10 |", content)
        self.assertIn("| ID_150 | Product 150 | 1500 |", content)
        self.assertNotIn("| ID_151 |", content)
        self.assertIn("[TRUNCATED: showing 150 of 200 data rows]", content)

    def test_extract_csv_custom_cap(self):
        csv_file = self.vault_root / "raw" / "metrics.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Metric", "Score"])
            for i in range(1, 26):
                writer.writerow([f"Metric_{i}", i])

        ok = extract_source.extract_csv(csv_file, self.vault_root, force=True, max_rows=5)
        self.assertTrue(ok)
        out_md = self.vault_root / "raw" / "metrics.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("| Metric_1 | 1 |", content)
        self.assertIn("| Metric_5 | 5 |", content)
        self.assertNotIn("| Metric_6 |", content)
        self.assertIn("[TRUNCATED: showing 5 of 25 data rows]", content)

    def test_extract_csv_pipe_escaping(self):
        csv_file = self.vault_root / "raw" / "pipes.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Col1", "Col2"])
            writer.writerow(["Alpha|Beta", "Value 1"])

        ok = extract_source.extract_csv(csv_file, self.vault_root, force=True)
        self.assertTrue(ok)
        out_md = self.vault_root / "raw" / "pipes.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("Alpha\\|Beta", content)

    def test_extract_xlsx_default_cap_and_pipe_escaping(self):
        xlsx_file = self.vault_root / "raw" / "services.xlsx"
        # Build minimal synthetic XLSX
        rows_xml = ['<row r="1"><c t="inlineStr"><is><t>Service</t></is></c><c t="inlineStr"><is><t>Region|Zone</t></is></c></row>']
        for i in range(1, 81):
            r_idx = i + 1
            rows_xml.append(
                f'<row r="{r_idx}"><c t="inlineStr"><is><t>App_{i}</t></is></c>'
                f'<c t="inlineStr"><is><t>US|West_{i}</t></is></c></row>'
            )

        with zipfile.ZipFile(xlsx_file, "w") as zf:
            zf.writestr(
                "xl/workbook.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheets><sheet name="Clusters" sheetId="1" r:id="rId1" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></sheets>'
                "</workbook>",
            )
            zf.writestr(
                "xl/worksheets/sheet1.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                f'<sheetData>{"".join(rows_xml)}</sheetData>'
                "</worksheet>",
            )

        # Default cap (50 data rows)
        ok = extract_source.extract_xlsx(xlsx_file, self.vault_root, force=True)
        self.assertTrue(ok)
        out_md = self.vault_root / "raw" / "services.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("Region\\|Zone", content)
        self.assertIn("| App_1 | US\\|West_1 |", content)
        self.assertIn("| App_50 | US\\|West_50 |", content)
        self.assertNotIn("| App_51 |", content)
        self.assertIn("[TRUNCATED: showing 50 of 80 data rows]", content)

        # Explicit cap (10 data rows)
        ok2 = extract_source.extract_xlsx(xlsx_file, self.vault_root, force=True, max_rows=10)
        self.assertTrue(ok2)
        content2 = out_md.read_text(encoding="utf-8")
        self.assertIn("| App_10 | US\\|West_10 |", content2)
        self.assertNotIn("| App_11 |", content2)
        self.assertIn("[TRUNCATED: showing 10 of 80 data rows]", content2)

    def test_process_target_propagates_max_rows(self):
        csv_file = self.vault_root / "raw" / "target_test.csv"
        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Header1", "Header2"])
            for i in range(1, 30):
                writer.writerow([f"A{i}", f"B{i}"])

        results = extract_source.process_target(
            str(csv_file), vault_root=self.vault_root, force=True, max_rows=3
        )
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["success"])
        out_md = self.vault_root / "raw" / "target_test.md"
        content = out_md.read_text(encoding="utf-8")
        self.assertIn("[TRUNCATED: showing 3 of 29 data rows]", content)


class TestUrlFetchSecurity(unittest.TestCase):
    """Verifies URL fetch SSRF, redirect safety, timeout, and 20 MiB limit."""

    def test_rejects_non_https(self):
        for bad_url in [
            "http://example.com/data",
            "file:///etc/passwd",
            "ftp://files.example.com/",
            "gopher://example.com/",
        ]:
            with self.assertRaises(ValueError):
                extract_source.validate_public_https_url(bad_url)

    def test_rejects_userinfo(self):
        bad_url = "https://user:password@example.com/resource"
        with self.assertRaises(ValueError):
            extract_source.validate_public_https_url(bad_url)

    def test_rejects_missing_hostname(self):
        for bad_url in ["https:///path", "https://@"]:
            with self.assertRaises(ValueError):
                extract_source.validate_public_https_url(bad_url)

    def test_rejects_private_and_loopback_ips(self):
        bad_ips = [
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "fc00::1",
            "fe80::1",
            "0.0.0.0",
        ]
        for ip in bad_ips:
            url = f"https://{ip}/status" if ":" not in ip or ip.startswith(":") else f"https://[{ip}]/status"
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    extract_source.validate_public_https_url(url)

    def test_rejects_mixed_dns_records(self):
        # Even if one record is public, any non-global / private record causes rejection
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo):
            with self.assertRaises(ValueError):
                extract_source.validate_public_https_url("https://dual.example.com")

    def test_accepts_valid_public_https(self):
        fake_addrinfo = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ]
        with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo):
            ips = extract_source.validate_public_https_url("https://public.example.com")
            self.assertEqual(ips, ["93.184.216.34"])

    def test_redirect_handler_blocks_private_ip(self):
        handler = extract_source.SafeHTTPRedirectHandler()
        fake_req = mock.MagicMock()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(
                fake_req, None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/"
            )

    def test_extract_url_blocks_content_length_over_20mb(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_root = Path(tmp_dir)
            (vault_root / "raw").mkdir(parents=True, exist_ok=True)

            mock_resp = mock.MagicMock()
            mock_resp.headers.get.return_value = str(25 * 1024 * 1024)
            mock_resp.__enter__.return_value = mock_resp

            fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo), \
                 mock.patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
                ok = extract_source.extract_url("https://big.example.com/file", vault_root)
                self.assertFalse(ok)
                mock_resp.read.assert_not_called()

    def test_extract_url_blocks_streaming_body_over_20mb(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_root = Path(tmp_dir)
            (vault_root / "raw").mkdir(parents=True, exist_ok=True)

            mock_resp = mock.MagicMock()
            mock_resp.headers.get.return_value = None
            # Return chunks that exceed 20 MiB
            chunk = b"x" * 65536
            mock_resp.read.side_effect = [chunk] * 400  # 400 * 64 KiB = 25 MiB
            mock_resp.__enter__.return_value = mock_resp

            fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo), \
                 mock.patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
                ok = extract_source.extract_url("https://stream.example.com/file", vault_root)
                self.assertFalse(ok)

    def test_extract_url_valid_https_success(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_root = Path(tmp_dir)
            (vault_root / "raw").mkdir(parents=True, exist_ok=True)

            html_content = b"<html><head><title>Safe Example</title></head><body><p>Hello World</p></body></html>"
            mock_resp = mock.MagicMock()
            mock_resp.headers.get.return_value = str(len(html_content))
            mock_resp.read.side_effect = [html_content, b""]
            mock_resp.__enter__.return_value = mock_resp

            fake_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
            with mock.patch("socket.getaddrinfo", return_value=fake_addrinfo), \
                 mock.patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
                ok = extract_source.extract_url("https://public.example.com/page", vault_root)
                self.assertTrue(ok)

            out_md = vault_root / "raw" / "Safe Example.md"
            self.assertTrue(out_md.exists())
            self.assertIn("Hello World", out_md.read_text(encoding="utf-8"))


class TestOoxmlZipSecurity(unittest.TestCase):
    """Verifies OOXML zip bomb, traversal, symlink, and XML entity bomb guards."""

    def test_safe_parse_xml_blocks_doctype_and_entity(self):
        bombs = [
            b"<!DOCTYPE foo SYSTEM 'evil.dtd'><foo/>",
            b'<?xml version="1.0"?><!ENTITY xxe "billion"><foo>&xxe;</foo>',
            b'<!doctype doc [<!element doc (#pcdata)*>]><doc/>',
            '<?xml version="1.0"?><!ENTITY attack "bomb"><foo/>'.encode("utf-16"),
        ]
        for bomb in bombs:
            with self.subTest(bomb=bomb[:20]):
                with self.assertRaises(ValueError):
                    extract_source._safe_parse_xml(bomb)

    def test_safe_parse_xml_accepts_clean_xml(self):
        valid = b'<?xml version="1.0"?><root><item>Hello</item></root>'
        el = extract_source._safe_parse_xml(valid)
        self.assertEqual(el.tag, "root")

    def test_ooxml_zip_rejects_path_traversal(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.png", b"malicious binary")
        with tempfile.NamedTemporaryFile(suffix=".pptx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_absolute_path(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/etc/passwd", b"malicious binary")
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_symlink(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("ppt/media/symlink.png")
            info.external_attr = 0o120777 << 16  # S_IFLNK
            zf.writestr(info, b"/etc/shadow")
        with tempfile.NamedTemporaryFile(suffix=".pptx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_deflate_bomb_ratio(self):
        # >100:1 ratio and > 1 MiB decompressed
        data = b"0" * 2_000_000
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml", data)
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_max_entries(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(10):
                zf.writestr(f"entry_{i}.xml", b"<xml/>")
        with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            with mock.patch.object(extract_source, "MAX_ZIP_ENTRIES", 5):
                self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_xml_entity_bomb(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "word/document.xml",
                '<?xml version="1.0"?>'
                '<!DOCTYPE test [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;">]>'
                '<w:document><w:body><w:p><w:r><w:t>&lol2;</w:t></w:r></w:p></w:body></w:document>',
            )
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_stdlib_extractors_raise_on_unsafe_archive(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../traversal.xml", b"traversal")
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            with self.assertRaises(ValueError):
                extract_source._extract_docx_stdlib(temp_path)
            with self.assertRaises(ValueError):
                extract_source._extract_pptx_stdlib(temp_path, "title", "sha", 0)
            with self.assertRaises(ValueError):
                extract_source._extract_xlsx_stdlib(temp_path)
        finally:
            temp_path.unlink()

    def test_ooxml_extractors_block_unsafe_archives(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../traversal.xml", b"traversal")
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(buf.getvalue())
            f.flush()
            temp_path = Path(f.name)
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                vault_root = Path(tmp_dir)
                self.assertFalse(extract_source.extract_docx(temp_path, vault_root, force=True))
                self.assertFalse(extract_source.extract_pptx(temp_path, vault_root, force=True))
                self.assertFalse(extract_source.extract_xlsx(temp_path, vault_root, force=True))
        finally:
            temp_path.unlink()

    def test_pptx_media_unpacking_sanitization(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_root = Path(tmp_dir)
            (vault_root / "raw").mkdir(parents=True, exist_ok=True)
            pptx_path = vault_root / "raw" / "deck.pptx"

            with zipfile.ZipFile(pptx_path, "w") as zf:
                zf.writestr(
                    "ppt/slides/slide1.xml",
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                    "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Slide Title</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>"
                    "</p:sld>",
                )
                zf.writestr("ppt/media/valid_image.png", b"PNG_DATA")

            ok = extract_source.extract_pptx(pptx_path, vault_root, force=True)
            self.assertTrue(ok)
            asset_file = vault_root / "raw" / "assets" / "deck" / "valid_image.png"
            self.assertTrue(asset_file.exists())
            self.assertEqual(asset_file.read_bytes(), b"PNG_DATA")

    def test_ooxml_zip_rejects_spoofed_file_size(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("test.xml", b"<root>" + b"A" * 5000 + b"</root>")
        raw = bytearray(buf.getvalue())
        # Local header: PK\x03\x04
        loc = raw.find(b"PK\x03\x04")
        struct.pack_into("<I", raw, loc + 22, 10)
        # Central directory: PK\x01\x02
        cd = raw.find(b"PK\x01\x02")
        struct.pack_into("<I", raw, cd + 24, 10)

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(raw)
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_unsupported_compress_method(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("test.xml", b"<root>data</root>")
        raw = bytearray(buf.getvalue())
        # Set compression method to 12 (bzip2)
        loc = raw.find(b"PK\x03\x04")
        struct.pack_into("<H", raw, loc + 8, 12)
        cd = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, cd + 10, 12)

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(raw)
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_ooxml_zip_rejects_encrypted_flag(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr("test.xml", b"<root>data</root>")
        raw = bytearray(buf.getvalue())
        # Set encryption flag bit 0
        loc = raw.find(b"PK\x03\x04")
        struct.pack_into("<H", raw, loc + 6, 1)
        cd = raw.find(b"PK\x01\x02")
        struct.pack_into("<H", raw, cd + 8, 1)

        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(raw)
            f.flush()
            temp_path = Path(f.name)
        try:
            self.assertFalse(extract_source.validate_safe_ooxml_zip(temp_path))
        finally:
            temp_path.unlink()

    def test_pptx_media_filtering_disallowed_extension_and_long_name(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            vault_root = Path(tmp_dir)
            (vault_root / "raw").mkdir(parents=True, exist_ok=True)
            pptx_path = vault_root / "raw" / "deck_filter.pptx"

            with zipfile.ZipFile(pptx_path, "w") as zf:
                zf.writestr(
                    "ppt/slides/slide1.xml",
                    '<?xml version="1.0" encoding="UTF-8"?>'
                    '<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                    'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                    "<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Filtered Deck</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld>"
                    "</p:sld>",
                )
                zf.writestr("ppt/media/ok.png", b"PNG")
                zf.writestr("ppt/media/evil.md", b"# Injected Markdown")
                zf.writestr("ppt/media/.dotfile.png", b"HIDDEN")
                zf.writestr(f"ppt/media/{'a' * 210}.png", b"LONG")

            ok = extract_source.extract_pptx(pptx_path, vault_root, force=True)
            self.assertTrue(ok)
            assets_dir = vault_root / "raw" / "assets" / "deck_filter"
            self.assertTrue((assets_dir / "ok.png").exists())
            self.assertFalse((assets_dir / "evil.md").exists())
            self.assertFalse((assets_dir / ".dotfile.png").exists())
            self.assertFalse((assets_dir / f"{'a' * 210}.png").exists())

    def test_cli_exit_code_on_refused_target(self):
        repo_root = Path(__file__).resolve().parent.parent
        script = repo_root / "scripts" / "extract_source.py"
        with tempfile.TemporaryDirectory() as tmp_dir:
            res = subprocess.run(
                [sys.executable, str(script), "file:///etc/passwd", "--vault", tmp_dir],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 1)


if __name__ == "__main__":
    unittest.main()
