#!/usr/bin/env python3
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
extract_source.py
Universal Multi-Format Source Extraction Utility with SHA-256 Caching for Antigravity Knowledge Compilers.

Extracts text, tables, speaker notes, and embedded visual assets from:
- PowerPoint Decks (.pptx)
- PDFs (.pdf)
- Word Documents (.docx)
- Excel Spreadsheets (.xlsx, .xls, .csv)
- Web URLs / HTML pages
- Markdown & Plain Text (.md, .txt)

Places extracted text into <vault>/raw/<Title>.md and unpacks embedded assets into <vault>/raw/assets/<Title>/.
Maintains an immutable SHA-256 cache (.ingest_cache.json) to guarantee idempotency and avoid duplicate LLM processing.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import socket
import struct
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib

# Security thresholds for OOXML ZIP archive inspection (unit tests can monkeypatch)
MAX_ZIP_ENTRIES = 2000
MAX_ZIP_MEMBER_BYTES = 100 * 1024 * 1024  # 100 MiB
MAX_ZIP_TOTAL_BYTES = 500 * 1024 * 1024   # 500 MiB
MAX_ZIP_COMPRESSION_RATIO = 100.0

# Security thresholds for URL fetching
MAX_URL_BYTES = 20 * 1024 * 1024  # 20 MiB

# Allowed media asset extensions for extraction from presentations
SAFE_MEDIA_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".bmp",
    ".tiff",
    ".webp",
    ".emf",
    ".wmf",
    ".mp4",
    ".mov",
    ".avi",
    ".mp3",
    ".wav",
    ".bin",
}


def _xml_local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def _read_member_bytes(
    zf: zipfile.ZipFile, name: str, max_bytes: int = MAX_ZIP_MEMBER_BYTES
) -> bytes:
    """Read a zip member safely in chunks up to max_bytes without allocating unbounded memory."""
    buf = bytearray()
    with zf.open(name, "r") as mf:
        while True:
            chunk = mf.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise ValueError(
                    f"Zip member {name!r} exceeds {max_bytes} bytes limit"
                )
    return bytes(buf)


def _safe_parse_xml(xml_bytes: bytes) -> ET.Element:
    """Safe XML parser blocking <!DOCTYPE and <!ENTITY declarations to prevent XML entity expansion bombs."""
    if not xml_bytes:
        raise ValueError("Empty XML content")

    for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin1"):
        try:
            decoded = xml_bytes.decode(enc, errors="ignore").upper()
            if re.search(r"<!\s*(DOCTYPE|ENTITY)", decoded):
                raise ValueError(
                    "Security violation: XML contains DOCTYPE or ENTITY declaration"
                )
        except Exception as e:
            if isinstance(e, ValueError) and "Security violation" in str(e):
                raise

    return ET.fromstring(xml_bytes)


def validate_safe_ooxml_zip(file_path: Path | str) -> bool:
    """Validates that an OOXML archive is safe from zip bombs, path traversal, symlinks, and XML entity bombs."""
    path = Path(file_path)
    if not path.is_file():
        return False

    try:
        with zipfile.ZipFile(path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ZIP_ENTRIES:
                return False

            total_decompressed = 0
            with open(path, "rb") as raw_f:
                for info in infolist:
                    name = info.filename
                    if not name or "\0" in name:
                        return False
                    if name.startswith("/") or name.startswith("\\"):
                        return False
                    if re.match(r"^[a-zA-Z]:", name):
                        return False

                    posix_parts = PurePosixPath(name).parts
                    win_parts = PureWindowsPath(name).parts
                    if ".." in posix_parts or ".." in win_parts:
                        return False

                    # Reject encrypted archives / password-protected members
                    if info.flag_bits & 0x1:
                        return False

                    # Reject ZIP symlinks (Unix mode in high 16 bits)
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        return False

                    # OPC standard (ISO/IEC 29500-2) strictly allows only Deflate (8) or Stored (0)
                    if info.compress_type not in (
                        zipfile.ZIP_STORED,
                        zipfile.ZIP_DEFLATED,
                    ):
                        return False

                    if info.file_size < 0 or info.compress_size < 0:
                        return False

                    if info.file_size > MAX_ZIP_MEMBER_BYTES:
                        return False

                    if info.is_dir():
                        continue

                    # Validate local file header signature and locate raw data offset
                    raw_f.seek(info.header_offset)
                    sig = raw_f.read(4)
                    if sig != b"PK\x03\x04":
                        return False
                    raw_f.seek(info.header_offset + 26)
                    hdr_lens = raw_f.read(4)
                    if len(hdr_lens) != 4:
                        return False
                    nlen, elen = struct.unpack("<HH", hdr_lens)
                    data_offset = info.header_offset + 30 + nlen + elen

                    is_xml = name.lower().endswith((".xml", ".rels"))
                    xml_chunks: list[bytes] = []

                    if info.compress_type == zipfile.ZIP_STORED:
                        if info.compress_size != info.file_size:
                            return False
                        total_decompressed += info.file_size
                        if total_decompressed > MAX_ZIP_TOTAL_BYTES:
                            return False

                        if is_xml:
                            raw_f.seek(data_offset)
                            read_len = min(info.file_size, 10 * 1024 * 1024)
                            xml_bytes = raw_f.read(read_len)
                            xml_chunks.append(xml_bytes)

                    elif info.compress_type == zipfile.ZIP_DEFLATED:
                        raw_f.seek(data_offset)
                        decompressor = zlib.decompressobj(-15)
                        member_decompressed = 0
                        bytes_left = info.compress_size

                        while bytes_left > 0:
                            to_read = min(bytes_left, 65536)
                            c_chunk = raw_f.read(to_read)
                            if len(c_chunk) != to_read:
                                return False
                            bytes_left -= len(c_chunk)

                            data_to_feed = c_chunk
                            while data_to_feed:
                                d_chunk = decompressor.decompress(
                                    data_to_feed, 65536
                                )
                                member_decompressed += len(d_chunk)
                                total_decompressed += len(d_chunk)
                                if member_decompressed > info.file_size:
                                    return False
                                if member_decompressed > MAX_ZIP_MEMBER_BYTES:
                                    return False
                                if total_decompressed > MAX_ZIP_TOTAL_BYTES:
                                    return False
                                if member_decompressed > 1024 * 1024:
                                    if info.compress_size == 0:
                                        return False
                                    if (
                                        member_decompressed
                                        / info.compress_size
                                    ) > MAX_ZIP_COMPRESSION_RATIO:
                                        return False
                                if is_xml and len(xml_chunks) < 500:
                                    xml_chunks.append(d_chunk)
                                data_to_feed = decompressor.unconsumed_tail

                        try:
                            tail = decompressor.flush()
                            if tail:
                                member_decompressed += len(tail)
                                total_decompressed += len(tail)
                                if member_decompressed > info.file_size:
                                    return False
                                if member_decompressed > MAX_ZIP_MEMBER_BYTES:
                                    return False
                                if total_decompressed > MAX_ZIP_TOTAL_BYTES:
                                    return False
                                if member_decompressed > 1024 * 1024:
                                    if info.compress_size == 0:
                                        return False
                                    if (
                                        member_decompressed
                                        / info.compress_size
                                    ) > MAX_ZIP_COMPRESSION_RATIO:
                                        return False
                                if is_xml and len(xml_chunks) < 500:
                                    xml_chunks.append(tail)
                        except zlib.error:
                            return False

                        if member_decompressed != info.file_size:
                            return False

                    if is_xml and xml_chunks:
                        full_xml = b"".join(xml_chunks)
                        for enc in (
                            "utf-8",
                            "utf-16",
                            "utf-16-le",
                            "utf-16-be",
                            "latin1",
                        ):
                            try:
                                decoded = full_xml.decode(
                                    enc, errors="ignore"
                                ).upper()
                                if re.search(r"<!\s*(DOCTYPE|ENTITY)", decoded):
                                    return False
                            except Exception:
                                pass

    except (zipfile.BadZipFile, Exception):
        return False

    return True


def validate_public_https_url(url: str) -> list[str]:
    """Validates URL scheme is HTTPS and resolves exclusively to public, non-loopback/private IPs."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError(f"Scheme must be https, got {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("Missing hostname in URL")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise ValueError("Userinfo / credentials not allowed in URL")

    port = parsed.port or 443
    try:
        addr_info = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {parsed.hostname}: {e}")

    if not addr_info:
        raise ValueError(f"DNS resolution returned no records for {parsed.hostname}")

    resolved_ips: list[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as e:
            raise ValueError(f"Invalid IP address {ip_str}: {e}")

        mapped = getattr(ip, "ipv4_mapped", None)
        check_ip = mapped if mapped else ip

        if (
            check_ip.is_loopback
            or check_ip.is_private
            or check_ip.is_link_local
            or check_ip.is_multicast
            or check_ip.is_reserved
            or check_ip.is_unspecified
            or not check_ip.is_global
        ):
            raise ValueError(f"Disallowed IP address {ip_str} for {parsed.hostname}")

        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        raise ValueError(f"No valid public IP addresses resolved for {parsed.hostname}")

    return resolved_ips


class SafeHTTPRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            validate_public_https_url(newurl)
        except Exception as e:
            raise urllib.error.HTTPError(
                newurl, code, f"Unsafe redirect blocked: {e}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _extract_pptx_stdlib(
    file_path: Path, clean_title: str, sha256_hash: str, media_count: int
) -> list[str]:
    """Zero-dependency stdlib zipfile + ElementTree PPTX extractor for stock Linux Python."""
    if not validate_safe_ooxml_zip(file_path):
        raise ValueError(f"Unsafe or invalid OOXML ZIP archive: {file_path}")

    slide_entries: list[tuple[int, str]] = []
    notes_map: dict[int, str] = {}
    with zipfile.ZipFile(file_path, "r") as z:
        for name in z.namelist():
            m_slide = re.fullmatch(r"ppt/slides/slide(\d+)\.xml", name)
            if m_slide:
                slide_entries.append((int(m_slide.group(1)), name))
            m_note = re.fullmatch(r"ppt/notesSlides/notesSlide(\d+)\.xml", name)
            if m_note:
                notes_map[int(m_note.group(1))] = name
        slide_entries.sort(key=lambda item: item[0])

        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_file: "{file_path.name}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            f"slides_count: {len(slide_entries)}",
            f"assets_count: {media_count}",
            "---",
            "",
            f"# {clean_title}",
            f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)",
            f"**Total Slides**: {len(slide_entries)}",
            f"**Extracted Media Assets**: {media_count} (saved to `raw/assets/{clean_title}/`)\n",
            "---\n",
        ]

        for idx, (slide_num, slide_xml_name) in enumerate(slide_entries, 1):
            lines.append(f"## Slide {idx}\n")
            root = _safe_parse_xml(_read_member_bytes(z, slide_xml_name))
            paragraphs: list[str] = []
            for elem in root.iter():
                if _xml_local_name(elem.tag) == "p":
                    runs = [
                        t.text
                        for t in elem.iter()
                        if _xml_local_name(t.tag) == "t" and t.text
                    ]
                    para = "".join(runs).strip()
                    if para:
                        paragraphs.append(para)
            if paragraphs:
                lines.append(f"### Title: {paragraphs[0]}\n")
                if len(paragraphs) > 1:
                    lines.append("### Content:")
                    for b in paragraphs[1:]:
                        lines.append(f"- {b}")
                    lines.append("")
            if slide_num in notes_map:
                try:
                    n_root = _safe_parse_xml(_read_member_bytes(z, notes_map[slide_num]))
                    n_runs = [
                        t.text.strip()
                        for t in n_root.iter()
                        if _xml_local_name(t.tag) == "t" and t.text and t.text.strip()
                    ]
                    if n_runs:
                        lines.append("### Speaker Notes:")
                        lines.append(f"> {' '.join(n_runs)}\n")
                except Exception:
                    pass
            lines.append("---\n")
    return lines


def _extract_docx_stdlib(file_path: Path) -> tuple[list[str], list[str]]:
    """Zero-dependency stdlib zipfile + ElementTree DOCX extractor for stock Linux Python."""
    if not validate_safe_ooxml_zip(file_path):
        raise ValueError(f"Unsafe or invalid OOXML ZIP archive: {file_path}")

    paragraphs: list[str] = []
    tables: list[str] = []
    with zipfile.ZipFile(file_path, "r") as z:
        if "word/document.xml" not in z.namelist():
            return paragraphs, tables
        root = _safe_parse_xml(_read_member_bytes(z, "word/document.xml"))
        body = next((el for el in root if _xml_local_name(el.tag) == "body"), root)
        for child in body:
            lname = _xml_local_name(child.tag)
            if lname == "p":
                runs = [
                    t.text
                    for t in child.iter()
                    if _xml_local_name(t.tag) == "t" and t.text
                ]
                txt = "".join(runs).strip()
                if txt:
                    paragraphs.append(txt)
            elif lname == "tbl":
                t_lines: list[str] = []
                for r_idx, tr in enumerate(
                    el for el in child if _xml_local_name(el.tag) == "tr"
                ):
                    cells: list[str] = []
                    for tc in (el for el in tr if _xml_local_name(el.tag) == "tc"):
                        c_runs = [
                            t.text
                            for t in tc.iter()
                            if _xml_local_name(t.tag) == "t" and t.text
                        ]
                        cells.append(" ".join("".join(c_runs).split()))
                    if cells:
                        t_lines.append("| " + " | ".join(cells) + " |")
                        if r_idx == 0:
                            t_lines.append("| " + " | ".join(["---"] * len(cells)) + " |")
                if t_lines:
                    tables.append("\n".join(t_lines))
    return paragraphs, tables


def _extract_xlsx_stdlib(file_path: Path) -> list[tuple[str, list[list[str]]]]:
    """Zero-dependency stdlib zipfile + ElementTree XLSX extractor for stock Linux Python."""
    if not validate_safe_ooxml_zip(file_path):
        raise ValueError(f"Unsafe or invalid OOXML ZIP archive: {file_path}")

    sheets_data: list[tuple[str, list[list[str]]]] = []
    with zipfile.ZipFile(file_path, "r") as z:
        names = set(z.namelist())
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in names:
            ss_root = _safe_parse_xml(_read_member_bytes(z, "xl/sharedStrings.xml"))
            for si in ss_root:
                if _xml_local_name(si.tag) == "si":
                    parts = [
                        t.text
                        for t in si.iter()
                        if _xml_local_name(t.tag) == "t" and t.text
                    ]
                    shared_strings.append("".join(parts))

        sheet_names: list[str] = []
        if "xl/workbook.xml" in names:
            wb_root = _safe_parse_xml(_read_member_bytes(z, "xl/workbook.xml"))
            for el in wb_root.iter():
                if _xml_local_name(el.tag) == "sheet" and el.attrib.get("name"):
                    sheet_names.append(el.attrib["name"])

        ws_files = sorted(
            (
                (int(m.group(1)), n)
                for n in names
                if (m := re.fullmatch(r"xl/worksheets/sheet(\d+)\.xml", n))
            ),
            key=lambda x: x[0],
        )
        for idx, (_snum, ws_path) in enumerate(ws_files):
            s_title = (
                sheet_names[idx] if idx < len(sheet_names) else f"Sheet{idx + 1}"
            )
            ws_root = _safe_parse_xml(_read_member_bytes(z, ws_path))
            rows: list[list[str]] = []
            for el in ws_root.iter():
                if _xml_local_name(el.tag) == "row":
                    row_vals: list[str] = []
                    for c in el:
                        if _xml_local_name(c.tag) != "c":
                            continue
                        c_type = c.attrib.get("t", "")
                        v_el = next(
                            (ch for ch in c if _xml_local_name(ch.tag) == "v"), None
                        )
                        if c_type == "s" and v_el is not None and v_el.text:
                            try:
                                s_idx = int(v_el.text.strip())
                                row_vals.append(
                                    shared_strings[s_idx]
                                    if 0 <= s_idx < len(shared_strings)
                                    else v_el.text
                                )
                            except Exception:
                                row_vals.append(v_el.text or "")
                        elif c_type == "inlineStr":
                            t_runs = [
                                t.text
                                for t in c.iter()
                                if _xml_local_name(t.tag) == "t" and t.text
                            ]
                            row_vals.append("".join(t_runs))
                        elif v_el is not None and v_el.text:
                            row_vals.append(v_el.text.strip())
                        else:
                            row_vals.append("")
                    if any(row_vals):
                        rows.append(row_vals)
            sheets_data.append((s_title, rows))
    return sheets_data


def compute_sha256(file_path: Path) -> str:
    """Computes SHA-256 hex digest of a file in chunks."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_string_sha256(content: str) -> str:
    """Computes SHA-256 hex digest of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def find_vault_root(start_path=None):
    """Locates the active Knowledge Compiler vault root."""
    if start_path:
        p = Path(start_path).resolve()
        if (p / "GEMINI.md").exists() or (p / "raw").exists() or (p / "wiki").exists():
            return p
        if p.is_dir():
            return p

    cwd = Path.cwd().resolve()
    for parent in [cwd] + list(cwd.parents):
        if (
            (parent / "GEMINI.md").exists()
            or (parent / "raw").exists()
            or (parent / "wiki").exists()
        ):
            return parent

    vault_env = os.environ.get("OBSIDIAN_VAULT_PATH")
    default_vault = (
        Path(vault_env).expanduser().resolve()
        if vault_env
        else (Path.home() / "ObsidianVault")
    )
    if default_vault.exists():
        return default_vault

    return cwd


def get_cache_path(vault_root: Path) -> Path:
    """Returns path to .ingest_cache.json in vault root."""
    return vault_root / ".ingest_cache.json"


def load_cache(vault_root: Path) -> dict:
    """Loads ingest cache from disk."""
    cache_file = get_cache_path(vault_root)
    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(vault_root: Path, cache: dict):
    """Atomically saves ingest cache to disk."""
    cache_file = get_cache_path(vault_root)
    tmp_file = cache_file.with_suffix(".tmp")
    try:
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
        tmp_file.replace(cache_file)
    except Exception as e:
        print(f"[!] Warning: Failed to write ingest cache: {e}", file=sys.stderr)


def sanitize_filename(name):
    """Sanitizes strings for safe filesystem naming."""
    name = re.sub(r'[\\/*?:"<>|]', "", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name


def record_cache_entry(
    vault_root: Path,
    file_path: Path,
    sha256_hash: str,
    output_md: Path,
    asset_count: int = 0,
):
    """Records or updates a cache entry."""
    cache = load_cache(vault_root)
    rel_source = (
        str(file_path.relative_to(vault_root))
        if file_path.is_relative_to(vault_root)
        else file_path.name
    )
    rel_output = (
        str(output_md.relative_to(vault_root))
        if output_md.is_relative_to(vault_root)
        else output_md.name
    )

    cache[rel_source] = {
        "sha256": sha256_hash,
        "mtime": file_path.stat().st_mtime if file_path.exists() else 0,
        "size_bytes": file_path.stat().st_size if file_path.exists() else 0,
        "output_md": rel_output,
        "asset_count": asset_count,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
    }
    save_cache(vault_root, cache)


def is_source_cached(
    vault_root: Path,
    file_path: Path,
    sha256_hash: str,
    target_md: Path,
    force: bool = False,
) -> bool:
    """Checks if source file is unchanged and output Markdown exists."""
    if force:
        return False
    if not target_md.exists():
        return False

    cache = load_cache(vault_root)
    rel_source = (
        str(file_path.relative_to(vault_root))
        if file_path.is_relative_to(vault_root)
        else file_path.name
    )

    entry = cache.get(rel_source)
    if entry and entry.get("sha256") == sha256_hash:
        return True

    # Fallback: check if target_md has source_sha256 in frontmatter
    try:
        with open(target_md, "r", encoding="utf-8") as f:
            content = f.read(1024)
            if (
                f"source_sha256: {sha256_hash}" in content
                or f'source_sha256: "{sha256_hash}"' in content
            ):
                record_cache_entry(vault_root, file_path, sha256_hash, target_md)
                return True
    except Exception:
        pass

    return False


def extract_pptx(file_path: Path, vault_root: Path, force: bool = False):
    """Extracts text, tables, speaker notes, and media from PPTX."""
    if not validate_safe_ooxml_zip(file_path):
        print(f"[!] Unsafe or invalid OOXML ZIP archive: {file_path}", file=sys.stderr)
        return False

    sha256_hash = compute_sha256(file_path)
    stem = file_path.stem
    clean_title = sanitize_filename(
        stem.replace("Copy of ", "").replace("Copy of", "").strip()
    )
    raw_dir = vault_root / "raw"
    raw_assets_dir = raw_dir / "assets" / clean_title
    out_md = raw_dir / f"{clean_title}.md"

    if is_source_cached(vault_root, file_path, sha256_hash, out_md, force):
        print(
            f"[⚡ CACHE HIT] {file_path.name} unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
        )
        return True

    raw_assets_dir.mkdir(parents=True, exist_ok=True)

    # Unpack media assets
    media_count = 0
    with zipfile.ZipFile(file_path, "r") as z:
        for item in z.namelist():
            if item.startswith("ppt/media/"):
                info = z.getinfo(item)
                if info.is_dir():
                    continue
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    continue
                fname = Path(item).name
                if not fname or fname in (".", ".."):
                    continue
                if len(fname) > 200 or fname.startswith("."):
                    continue
                ext = Path(fname).suffix.lower()
                if ext not in SAFE_MEDIA_EXTENSIONS:
                    continue
                out_path = raw_assets_dir / fname
                try:
                    if not out_path.resolve().is_relative_to(raw_assets_dir.resolve()):
                        continue
                except (ValueError, RuntimeError):
                    continue
                try:
                    media_bytes = _read_member_bytes(z, item)
                    with open(out_path, "wb") as f:
                        f.write(media_bytes)
                    media_count += 1
                except Exception:
                    continue

    try:
        from pptx import Presentation
        from pptx.enum.shapes import MSO_SHAPE_TYPE

        prs = Presentation(file_path)
        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_file: "{file_path.name}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            f"slides_count: {len(prs.slides)}",
            f"assets_count: {media_count}",
            "---",
            "",
            f"# {clean_title}",
            f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)",
            f"**Total Slides**: {len(prs.slides)}",
            f"**Extracted Media Assets**: {media_count} (saved to `raw/assets/{clean_title}/`)\n",
            "---\n",
        ]

        for idx, slide in enumerate(prs.slides, 1):
            lines.append(f"## Slide {idx}\n")
            title_text = ""
            body_texts = []
            tables = []

            for shape in slide.shapes:
                if shape.has_text_frame:
                    txt = shape.text_frame.text.strip()
                    if not txt:
                        continue
                    if shape == slide.shapes.title or (
                        not title_text and shape.shape_type == MSO_SHAPE_TYPE.PLACEHOLDER
                    ):
                        title_text = txt
                    else:
                        body_texts.append(txt)

                elif shape.has_table:
                    table_lines = []
                    for row_idx, row in enumerate(shape.table.rows):
                        row_cells = [
                            cell.text.strip().replace("\n", " ") for cell in row.cells
                        ]
                        table_lines.append("| " + " | ".join(row_cells) + " |")
                        if row_idx == 0:
                            table_lines.append(
                                "| " + " | ".join(["---"] * len(row_cells)) + " |"
                            )
                    if table_lines:
                        tables.append("\n".join(table_lines))

            if title_text:
                lines.append(f"### Title: {title_text}\n")
            if body_texts:
                lines.append("### Content:")
                for b in body_texts:
                    lines.append(f"- {b}")
                lines.append("")
            if tables:
                lines.append("### Tables:")
                for t in tables:
                    lines.append(t)
                    lines.append("")

            notes_text = ""
            if slide.has_notes_slide and slide.notes_slide.notes_text_frame:
                notes_text = slide.notes_slide.notes_text_frame.text.strip()
            if notes_text:
                lines.append("### Speaker Notes:")
                lines.append(f"> {notes_text}\n")

            lines.append("---\n")

        with open(out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        record_cache_entry(vault_root, file_path, sha256_hash, out_md, media_count)
        print(
            f"[✓] Successfully extracted PPTX: {file_path.name} -> {out_md.relative_to(vault_root)} ({media_count} assets, SHA-256: {sha256_hash[:10]}...)"
        )
        return True
    except ImportError:
        try:
            lines = _extract_pptx_stdlib(file_path, clean_title, sha256_hash, media_count)
            with open(out_md, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            record_cache_entry(vault_root, file_path, sha256_hash, out_md, media_count)
            print(
                f"[✓] Successfully extracted PPTX (stdlib OOXML): {file_path.name} -> {out_md.relative_to(vault_root)}"
            )
            return True
        except Exception as e:
            print(f"[!] Error extracting PPTX {file_path.name}: {e}", file=sys.stderr)
            return False
    except Exception as e:
        try:
            lines = _extract_pptx_stdlib(
                file_path, clean_title, sha256_hash, media_count
            )
            with open(out_md, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            record_cache_entry(vault_root, file_path, sha256_hash, out_md, media_count)
            print(
                f"[✓] Successfully extracted PPTX (stdlib fallback): {file_path.name} -> {out_md.relative_to(vault_root)}"
            )
            return True
        except Exception as e2:
            print(f"[!] Error extracting PPTX {file_path.name}: {e} (fallback error: {e2})", file=sys.stderr)
            return False


def extract_pdf(file_path: Path, vault_root: Path, force: bool = False):
    """Extracts text from PDF files."""
    sha256_hash = compute_sha256(file_path)
    stem = file_path.stem
    clean_title = sanitize_filename(stem.replace("Copy of ", "").strip())
    raw_dir = vault_root / "raw"
    out_md = raw_dir / f"{clean_title}.md"

    if is_source_cached(vault_root, file_path, sha256_hash, out_md, force):
        print(
            f"[⚡ CACHE HIT] {file_path.name} unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
        )
        return True

    text_content = ""
    page_count = 0
    try:
        import pypdf

        reader = pypdf.PdfReader(file_path)
        page_count = len(reader.pages)
        pages_text = []
        for idx, page in enumerate(reader.pages, 1):
            t = page.extract_text() or ""
            pages_text.append(f"## Page {idx}\n\n{t.strip()}\n\n---")
        text_content = "\n\n".join(pages_text)
    except Exception:
        try:
            res = subprocess.run(
                ["pdftotext", str(file_path), "-"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if res.returncode == 0:
                if not res.stdout:
                    raw_pages = []
                else:
                    raw_pages = res.stdout.split("\f")
                    if len(raw_pages) > 1 and raw_pages[-1] == "":
                        raw_pages.pop()
                page_count = len(raw_pages)
                pages_text = []
                for idx, t in enumerate(raw_pages, 1):
                    pages_text.append(f"## Page {idx}\n\n{t.strip()}\n\n---")
                text_content = "\n\n".join(pages_text)
            else:
                print(
                    f"[!] Failed to extract PDF {file_path.name}: install pypdf or poppler-utils (pdftotext)",
                    file=sys.stderr,
                )
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            print(
                f"[!] Failed to extract PDF {file_path.name} via pdftotext: {e}",
                file=sys.stderr,
            )
            return False

    lines = [
        "---",
        f'title: "{clean_title}"',
        "type: raw-source",
        f'source_file: "{file_path.name}"',
        f'source_sha256: "{sha256_hash}"',
        f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
        f"pages_count: {page_count}",
        "---",
        "",
        f"# {clean_title}",
        f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)\n",
        "---\n",
        text_content,
    ]
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    record_cache_entry(vault_root, file_path, sha256_hash, out_md)
    print(
        f"[✓] Successfully extracted PDF: {file_path.name} -> {out_md.relative_to(vault_root)} (SHA-256: {sha256_hash[:10]}...)"
    )
    return True


def extract_docx(file_path: Path, vault_root: Path, force: bool = False):
    """Extracts text and tables from Word documents (.docx)."""
    if not validate_safe_ooxml_zip(file_path):
        print(f"[!] Unsafe or invalid OOXML ZIP archive: {file_path}", file=sys.stderr)
        return False

    sha256_hash = compute_sha256(file_path)
    stem = file_path.stem
    clean_title = sanitize_filename(stem.replace("Copy of ", "").strip())
    raw_dir = vault_root / "raw"
    out_md = raw_dir / f"{clean_title}.md"

    if is_source_cached(vault_root, file_path, sha256_hash, out_md, force):
        print(
            f"[⚡ CACHE HIT] {file_path.name} unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
        )
        return True

    try:
        try:
            import docx

            doc = docx.Document(file_path)
            paragraphs = []
            for p in doc.paragraphs:
                text = p.text.strip()
                if text:
                    if p.style.name.startswith("Heading 1"):
                        paragraphs.append(f"# {text}")
                    elif p.style.name.startswith("Heading 2"):
                        paragraphs.append(f"## {text}")
                    elif p.style.name.startswith("Heading 3"):
                        paragraphs.append(f"### {text}")
                    else:
                        paragraphs.append(text)

            tables = []
            for table in doc.tables:
                table_lines = []
                for row_idx, row in enumerate(table.rows):
                    row_cells = [cell.text.strip().replace("\n", " ") for cell in row.cells]
                    table_lines.append("| " + " | ".join(row_cells) + " |")
                    if row_idx == 0:
                        table_lines.append(
                            "| " + " | ".join(["---"] * len(row_cells)) + " |"
                        )
                if table_lines:
                    tables.append("\n".join(table_lines))
        except (ImportError, Exception):
            paragraphs, tables = _extract_docx_stdlib(file_path)

        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_file: "{file_path.name}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            "---",
            "",
            f"# {clean_title}",
            f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)\n",
            "---\n",
            "\n\n".join(paragraphs),
            "\n\n## Tables\n\n" + "\n\n".join(tables) if tables else "",
        ]

        with open(out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        record_cache_entry(vault_root, file_path, sha256_hash, out_md)
        print(
            f"[✓] Successfully extracted DOCX: {file_path.name} -> {out_md.relative_to(vault_root)}"
        )
        return True
    except Exception as e:
        print(f"[!] Error extracting DOCX {file_path.name}: {e}", file=sys.stderr)
        return False


def extract_xlsx(
    file_path: Path,
    vault_root: Path,
    force: bool = False,
    max_rows: int | None = None,
):
    """Extracts sheets and schema from XLSX."""
    if not validate_safe_ooxml_zip(file_path):
        print(f"[!] Unsafe or invalid OOXML ZIP archive: {file_path}", file=sys.stderr)
        return False

    sha256_hash = compute_sha256(file_path)
    stem = file_path.stem
    clean_title = sanitize_filename(stem.replace("Copy of ", "").strip())
    raw_dir = vault_root / "raw"
    out_md = raw_dir / f"{clean_title}.md"

    if is_source_cached(vault_root, file_path, sha256_hash, out_md, force):
        print(
            f"[⚡ CACHE HIT] {file_path.name} unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
        )
        return True

    cap = max(1, max_rows) if max_rows is not None else 50
    MAX_COLS_CAP = 100
    try:
        sheets_data = []
        try:
            import openpyxl

            wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
            for name in wb.sheetnames:
                ws = wb[name]
                if hasattr(ws, "reset_dimensions"):
                    ws.reset_dimensions()
                true_width = 0
                for r_cells in ws.iter_rows(max_row=1):
                    for c in r_cells:
                        if c.value is not None and str(c.value).strip() != "":
                            if c.column and c.column > true_width:
                                true_width = c.column
                rows = []
                total_real_rows = 0
                for r in ws.iter_rows(max_col=MAX_COLS_CAP + 1, values_only=True):
                    has_val = (
                        any(c is not None and str(c).strip() != "" for c in r)
                        if r
                        else False
                    )
                    if not has_val:
                        continue
                    total_real_rows += 1
                    if len(rows) < cap + 1:
                        cleaned_row = [
                            (
                                str(c).replace("\n", " ").strip()
                                if c is not None
                                else ""
                            )
                            for c in r
                        ]
                        while cleaned_row and cleaned_row[-1] == "":
                            cleaned_row.pop()
                        if cleaned_row:
                            rows.append(cleaned_row)
                sheets_data.append((name, rows, total_real_rows, true_width))
        except (ImportError, Exception):
            stdlib_res = _extract_xlsx_stdlib(file_path)
            sheets_data = [
                (sname, srows, len(srows), 0) for sname, srows in stdlib_res
            ]

        sheet_names = [name for name, _, _, _ in sheets_data]
        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_file: "{file_path.name}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            f"sheets: {json.dumps(sheet_names)}",
            "---",
            "",
            f"# {clean_title}",
            f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)",
            f"**Sheets**: {', '.join(sheet_names)}\n",
            "---\n",
        ]
        for name, rows, total_rows_count, true_width in sheets_data:
            max_cols = max((len(r) for r in rows), default=0)
            actual_cols = max(max_cols, true_width)
            col_cap = min(actual_cols, MAX_COLS_CAP)
            lines.append(
                f"## Sheet: {name} ({total_rows_count} rows, {actual_cols} cols)\n"
            )
            if not rows:
                continue
            raw_header = [
                (
                    str(c).replace("\n", " ").replace("|", "\\|").strip()
                    if c is not None
                    else ""
                )
                for c in rows[0]
            ]
            header = raw_header[:col_cap]
            if len(header) < col_cap:
                header = header + [""] * (col_cap - len(header))

            lines.append("| " + " | ".join(header) + " |")
            lines.append("| " + " | ".join(["---"] * len(header)) + " |")
            data_rows = rows[1:]
            sample_rows = data_rows[:cap]
            for r in sample_rows:
                row_vals = [
                    (
                        str(c).replace("\n", " ").replace("|", "\\|").strip()
                        if c is not None
                        else ""
                    )
                    for c in r[:col_cap]
                ]
                if len(row_vals) < len(header):
                    row_vals = row_vals + [""] * (len(header) - len(row_vals))
                lines.append("| " + " | ".join(row_vals[: len(header)]) + " |")

            total_data_count = (
                max(0, total_rows_count - 1)
                if total_rows_count > 1
                else len(data_rows)
            )
            if total_data_count > cap:
                lines.append(
                    f"\n[TRUNCATED: showing {cap} of {total_data_count} data rows]\n"
                )
            if actual_cols > col_cap:
                if actual_cols == MAX_COLS_CAP + 1 and true_width <= MAX_COLS_CAP:
                    lines.append(
                        f"\n[TRUNCATED: showing {col_cap} of more than {MAX_COLS_CAP} columns]\n"
                    )
                else:
                    lines.append(
                        f"\n[TRUNCATED: showing {col_cap} of {actual_cols} columns]\n"
                    )
            lines.append("\n---\n")

        with open(out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        record_cache_entry(vault_root, file_path, sha256_hash, out_md)
        print(
            f"[✓] Successfully extracted Excel: {file_path.name} -> {out_md.relative_to(vault_root)}"
        )
        return True
    except Exception as e:
        print(f"[!] Error extracting XLSX {file_path.name}: {e}", file=sys.stderr)
        return False


def extract_csv(
    file_path: Path,
    vault_root: Path,
    force: bool = False,
    max_rows: int | None = None,
):
    """Extracts tables and schema from CSV files."""
    sha256_hash = compute_sha256(file_path)
    stem = file_path.stem
    clean_title = sanitize_filename(stem.replace("Copy of ", "").strip())
    raw_dir = vault_root / "raw"
    out_md = raw_dir / f"{clean_title}.md"

    if is_source_cached(vault_root, file_path, sha256_hash, out_md, force):
        print(
            f"[⚡ CACHE HIT] {file_path.name} unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
        )
        return True

    try:
        rows = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                rows.append(
                    [
                        str(c).strip().replace("\n", " ").replace("|", "\\|")
                        for c in row
                    ]
                )

        if not rows:
            print(f"[!] Empty CSV: {file_path.name}", file=sys.stderr)
            return False

        header = rows[0]
        data_rows = rows[1:]

        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_file: "{file_path.name}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            f"row_count: {len(rows)}",
            f"col_count: {len(header)}",
            "---",
            "",
            f"# {clean_title}",
            f"\n**Source File**: `{file_path.name}` (SHA-256: `{sha256_hash}`)\n",
            f"**Dimensions**: {len(rows)} rows, {len(header)} columns\n",
            "---\n",
            "| " + " | ".join(header) + " |",
            "| " + " | ".join(["---"] * len(header)) + " |",
        ]

        cap = max(1, max_rows) if max_rows is not None else 150
        sample_rows = data_rows[:cap]
        for r in sample_rows:
            if len(r) < len(header):
                r = r + [""] * (len(header) - len(r))
            lines.append("| " + " | ".join(r[: len(header)]) + " |")

        if len(data_rows) > cap:
            lines.append(
                f"\n[TRUNCATED: showing {cap} of {len(data_rows)} data rows]\n"
            )

        with open(out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        record_cache_entry(vault_root, file_path, sha256_hash, out_md)
        print(
            f"[✓] Successfully extracted CSV: {file_path.name} -> {out_md.relative_to(vault_root)}"
        )
        return True
    except Exception as e:
        print(f"[!] Error extracting CSV {file_path.name}: {e}", file=sys.stderr)
        return False


def extract_url(url: str, vault_root: Path, force: bool = False) -> bool:
    """Fetches URL securely with SSRF checks, redirect validation, and a 20 MiB limit."""
    try:
        validate_public_https_url(url)
    except Exception as e:
        print(f"[!] Invalid or unsafe URL {url}: {e}", file=sys.stderr)
        return False

    try:
        opener = urllib.request.build_opener(SafeHTTPRedirectHandler)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with opener.open(req, timeout=20) as resp:
            cl_header = resp.headers.get("Content-Length")
            if cl_header:
                try:
                    content_length = int(cl_header.strip())
                    if content_length > MAX_URL_BYTES:
                        print(
                            f"[!] URL Content-Length {content_length} exceeds limit of {MAX_URL_BYTES} bytes: {url}",
                            file=sys.stderr,
                        )
                        return False
                except ValueError:
                    pass

            chunks = []
            total_bytes = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_URL_BYTES:
                    print(
                        f"[!] URL response exceeded maximum size limit of {MAX_URL_BYTES} bytes: {url}",
                        file=sys.stderr,
                    )
                    return False
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)
            html = raw_bytes.decode("utf-8", errors="ignore")

        sha256_hash = compute_string_sha256(html)
        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "Web Source"
        clean_title = sanitize_filename(title)
        out_md = vault_root / "raw" / f"{clean_title}.md"

        if is_source_cached(vault_root, Path(url), sha256_hash, out_md, force):
            print(
                f"[⚡ CACHE HIT] URL content unchanged (SHA-256: {sha256_hash[:10]}...). Skipping extraction."
            )
            return True

        text = re.sub(r"<script.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<style.*?</style>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()

        lines = [
            "---",
            f'title: "{clean_title}"',
            "type: raw-source",
            f'source_url: "{url}"',
            f'source_sha256: "{sha256_hash}"',
            f'extracted_at: "{datetime.now(timezone.utc).isoformat()}"',
            "---",
            "",
            f"# {title}\n\n**Source URL**: {url} (SHA-256: `{sha256_hash}`)\n\n---\n\n{text}",
        ]

        with open(out_md, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        record_cache_entry(vault_root, Path(url), sha256_hash, out_md)
        print(
            f"[✓] Successfully extracted URL: {url} -> {out_md.relative_to(vault_root)}"
        )
        return True
    except Exception as e:
        print(f"[!] Failed to fetch URL {url}: {e}", file=sys.stderr)
        return False


def scan_raw_directory(
    vault_root: Path, force: bool = False, max_rows: int | None = None
):
    """Scans raw/ for unextracted PPTX, PDF, DOCX, XLSX files."""
    raw_dir = vault_root / "raw"
    if not raw_dir.exists():
        print(f"[!] No raw/ directory found in {vault_root}", file=sys.stderr)
        return

    processed = 0
    for item in sorted(raw_dir.iterdir()):
        if item.is_file() and not item.name.startswith("."):
            suffix = item.suffix.lower()
            if suffix == ".pptx":
                if extract_pptx(item, vault_root, force):
                    processed += 1
            elif suffix == ".pdf":
                if extract_pdf(item, vault_root, force):
                    processed += 1
            elif suffix == ".docx":
                if extract_docx(item, vault_root, force):
                    processed += 1
            elif suffix in [".xlsx", ".xls"]:
                if extract_xlsx(item, vault_root, force, max_rows=max_rows):
                    processed += 1
            elif suffix == ".csv":
                if extract_csv(item, vault_root, force, max_rows=max_rows):
                    processed += 1

    print(f"\n[📊 SCAN COMPLETE] Total processed/verified: {processed} files.")


def rebuild_cache(vault_root: Path):
    """Rebuilds the entire .ingest_cache.json from all raw source files and extracted Markdown."""
    raw_dir = vault_root / "raw"
    if not raw_dir.exists():
        print("[!] No raw directory found.")
        return

    cache = {}
    count = 0
    print(f"[*] Rebuilding SHA-256 cache across all raw files in {raw_dir}...")
    for item in sorted(raw_dir.iterdir()):
        if item.is_file() and not item.name.startswith("."):
            suffix = item.suffix.lower()
            if suffix in [".pptx", ".pdf", ".docx", ".xlsx", ".xls", ".csv"]:
                sha = compute_sha256(item)
                stem = sanitize_filename(
                    item.stem.replace("Copy of ", "").replace("Copy of", "").strip()
                )
                target_md = raw_dir / f"{stem}.md"
                rel_source = str(item.relative_to(vault_root))
                rel_output = (
                    str(target_md.relative_to(vault_root)) if target_md.exists() else ""
                )

                cache[rel_source] = {
                    "sha256": sha,
                    "mtime": item.stat().st_mtime,
                    "size_bytes": item.stat().st_size,
                    "output_md": rel_output,
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                }
                count += 1
                print(
                    f"  [+] Binary source : {item.name} ({item.stat().st_size:,} bytes) -> SHA-256: {sha[:12]}..."
                )
            elif suffix == ".md":
                # Standalone raw markdown source
                sha = compute_sha256(item)
                rel_source = str(item.relative_to(vault_root))
                cache[rel_source] = {
                    "sha256": sha,
                    "mtime": item.stat().st_mtime,
                    "size_bytes": item.stat().st_size,
                    "output_md": rel_source,
                    "extracted_at": datetime.now(timezone.utc).isoformat(),
                }
                count += 1
                print(
                    f"  [+] Markdown source: {item.name} ({item.stat().st_size:,} bytes) -> SHA-256: {sha[:12]}..."
                )

    save_cache(vault_root, cache)
    print(
        f"\n[✓] Successfully rebuilt cache with {count} raw source entries in {get_cache_path(vault_root)}."
    )


def process_target(
    target: str,
    vault_root: Path = None,
    force: bool = False,
    max_rows: int | None = None,
) -> list:
    """Process a target file, directory, or URL with caching and error handling."""
    if vault_root is None:
        vault_root = find_vault_root()
    else:
        vault_root = Path(vault_root).resolve()

    results = []
    if target.startswith("http://") or target.startswith("https://"):
        success = extract_url(target, vault_root, force=force)
        results.append(
            {
                "success": bool(success),
                "type": "url",
                "target": target,
                "output_file": str(
                    vault_root / "raw" / f"{sanitize_filename(target)}.md"
                ),
            }
        )
    else:
        target_path = Path(target).resolve()
        if not target_path.exists():
            raw_target = vault_root / "raw" / target
            if raw_target.exists():
                target_path = raw_target
            else:
                return [{"success": False, "error": f"Target not found: {target}"}]

        if target_path.is_dir():
            for item in sorted(target_path.iterdir()):
                if item.is_file() and not item.name.startswith("."):
                    ext = item.suffix.lower()
                    if ext == ".pptx":
                        ok = extract_pptx(item, vault_root, force=force)
                        results.append(
                            {
                                "success": bool(ok),
                                "type": "pptx",
                                "title": item.stem,
                                "output_file": str(
                                    vault_root
                                    / "raw"
                                    / f"{sanitize_filename(item.stem)}.md"
                                ),
                            }
                        )
                    elif ext == ".pdf":
                        ok = extract_pdf(item, vault_root, force=force)
                        results.append(
                            {
                                "success": bool(ok),
                                "type": "pdf",
                                "title": item.stem,
                                "output_file": str(
                                    vault_root
                                    / "raw"
                                    / f"{sanitize_filename(item.stem)}.md"
                                ),
                            }
                        )
                    elif ext == ".docx":
                        ok = extract_docx(item, vault_root, force=force)
                        results.append(
                            {
                                "success": bool(ok),
                                "type": "docx",
                                "title": item.stem,
                                "output_file": str(
                                    vault_root
                                    / "raw"
                                    / f"{sanitize_filename(item.stem)}.md"
                                ),
                            }
                        )
                    elif ext in [".xlsx", ".xls"]:
                        ok = extract_xlsx(item, vault_root, force=force, max_rows=max_rows)
                        results.append(
                            {
                                "success": bool(ok),
                                "type": "xlsx",
                                "title": item.stem,
                                "output_file": str(
                                    vault_root
                                    / "raw"
                                    / f"{sanitize_filename(item.stem)}.md"
                                ),
                            }
                        )
                    elif ext == ".csv":
                        ok = extract_csv(item, vault_root, force=force, max_rows=max_rows)
                        results.append(
                            {
                                "success": bool(ok),
                                "type": "csv",
                                "title": item.stem,
                                "output_file": str(
                                    vault_root
                                    / "raw"
                                    / f"{sanitize_filename(item.stem)}.md"
                                ),
                            }
                        )
                    elif ext in [".md", ".txt"]:
                        raw_dir = vault_root / "raw"
                        raw_dir.mkdir(parents=True, exist_ok=True)
                        dest = raw_dir / item.name
                        if item.resolve() != dest.resolve():
                            dest.write_text(
                                item.read_text(encoding="utf-8", errors="ignore"),
                                encoding="utf-8",
                            )
                        sha = compute_sha256(dest)
                        record_cache_entry(vault_root, dest, sha, dest)
                        results.append(
                            {
                                "success": True,
                                "type": "text",
                                "title": item.stem,
                                "output_file": str(dest),
                            }
                        )
        elif target_path.is_file():
            ext = target_path.suffix.lower()
            if ext == ".pptx":
                ok = extract_pptx(target_path, vault_root, force=force)
                results.append(
                    {
                        "success": bool(ok),
                        "type": "pptx",
                        "title": target_path.stem,
                        "output_file": str(
                            vault_root
                            / "raw"
                            / f"{sanitize_filename(target_path.stem)}.md"
                        ),
                    }
                )
            elif ext == ".pdf":
                ok = extract_pdf(target_path, vault_root, force=force)
                results.append(
                    {
                        "success": bool(ok),
                        "type": "pdf",
                        "title": target_path.stem,
                        "output_file": str(
                            vault_root
                            / "raw"
                            / f"{sanitize_filename(target_path.stem)}.md"
                        ),
                    }
                )
            elif ext == ".docx":
                ok = extract_docx(target_path, vault_root, force=force)
                results.append(
                    {
                        "success": bool(ok),
                        "type": "docx",
                        "title": target_path.stem,
                        "output_file": str(
                            vault_root
                            / "raw"
                            / f"{sanitize_filename(target_path.stem)}.md"
                        ),
                    }
                )
            elif ext in [".xlsx", ".xls"]:
                ok = extract_xlsx(target_path, vault_root, force=force, max_rows=max_rows)
                results.append(
                    {
                        "success": bool(ok),
                        "type": "xlsx",
                        "title": target_path.stem,
                        "output_file": str(
                            vault_root
                            / "raw"
                            / f"{sanitize_filename(target_path.stem)}.md"
                        ),
                    }
                )
            elif ext == ".csv":
                ok = extract_csv(target_path, vault_root, force=force, max_rows=max_rows)
                results.append(
                    {
                        "success": bool(ok),
                        "type": "csv",
                        "title": target_path.stem,
                        "output_file": str(
                            vault_root
                            / "raw"
                            / f"{sanitize_filename(target_path.stem)}.md"
                        ),
                    }
                )
            else:
                raw_dir = vault_root / "raw"
                raw_dir.mkdir(parents=True, exist_ok=True)
                dest = raw_dir / target_path.name
                if target_path.resolve() != dest.resolve():
                    dest.write_text(
                        target_path.read_text(encoding="utf-8", errors="ignore"),
                        encoding="utf-8",
                    )
                sha = compute_sha256(dest)
                record_cache_entry(vault_root, dest, sha, dest)
                results.append(
                    {
                        "success": True,
                        "type": "text",
                        "title": target_path.stem,
                        "output_file": str(dest),
                    }
                )
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Universal Source Extraction Tool with SHA-256 Caching for Antigravity Knowledge Compilers."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="raw",
        help="Target file path, directory, URL, or 'raw' to scan vault raw/ directory",
    )
    parser.add_argument(
        "--vault",
        default=None,
        help="Path to Knowledge Compiler vault root (defaults to auto-detection)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-extraction even if SHA-256 cache matches",
    )
    parser.add_argument(
        "--rebuild-cache",
        action="store_true",
        help="Rebuild .ingest_cache.json from current raw directory",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=None,
        help="Maximum number of data rows to extract from spreadsheets (CSV/XLSX)",
    )
    args = parser.parse_args()

    vault_root = find_vault_root(args.vault)
    print(f"[*] Target Knowledge Compiler Vault: {vault_root}")

    if args.rebuild_cache:
        rebuild_cache(vault_root)
        return

    target = args.target
    success = True
    if target.startswith("http://") or target.startswith("https://"):
        success = extract_url(target, vault_root, args.force)
    elif target in ["raw", "all"]:
        scan_raw_directory(vault_root, args.force, max_rows=args.max_rows)
    else:
        target_path = Path(target).resolve()
        if not target_path.exists():
            raw_target = vault_root / "raw" / target
            if raw_target.exists():
                target_path = raw_target
            else:
                print(f"[!] Target not found: {target}", file=sys.stderr)
                sys.exit(1)

        if target_path.is_dir():
            scan_raw_directory(vault_root, args.force, max_rows=args.max_rows)
        elif target_path.suffix.lower() == ".pptx":
            success = extract_pptx(target_path, vault_root, args.force)
        elif target_path.suffix.lower() == ".pdf":
            success = extract_pdf(target_path, vault_root, args.force)
        elif target_path.suffix.lower() == ".docx":
            success = extract_docx(target_path, vault_root, args.force)
        elif target_path.suffix.lower() in [".xlsx", ".xls"]:
            success = extract_xlsx(target_path, vault_root, args.force, max_rows=args.max_rows)
        elif target_path.suffix.lower() == ".csv":
            success = extract_csv(target_path, vault_root, args.force, max_rows=args.max_rows)
        elif target_path.suffix.lower() in [".md", ".txt"]:
            print(f"[✓] Target is already plain text: {target_path.name}")
        else:
            print(
                f"[!] Unsupported file extension: {target_path.suffix}", file=sys.stderr
            )
            success = False

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
