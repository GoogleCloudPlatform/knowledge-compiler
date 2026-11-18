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
Open Knowledge Format (OKF v0.3, with full v0.2 backward compatibility) Core Parser,
Conformance Validator, and YAML Engine.

Provides size-capped (16 KiB), anchor/alias-safe YAML frontmatter extraction and parsing
with 100% behavioral parity between PyYAML (`yaml.safe_load` / YAML 1.2 Core Schema) and
a pure-Python stdlib fallback parser. Also implements OKF v0.3 §4–§12 semantic helpers:
- `normalize_verified_list`: normalizes bare `verified: {by, at}` mapping to 1-element list.
- `derive_trust_tier`: computes `"unverified"`, `"machine-confirmed"`, or `"human-reviewed"`
  strictly from current verification events (`verified[].at >= generated.at`, OKF v0.3 §5.3).
- `has_stale_verifications`: detects concepts whose verifications are all older than `generated.at`.
- `is_stale`: evaluates `stale_after` RFC 3339 date/datetime against reference UTC time
  (treating unparseable `stale_after` values as stale per OKF v0.3 §5.5 & §11.2).
- `is_current_status`: treats missing/`stable`/`draft` as current and `deprecated`/unknown as not current (§5.4).
- `resolve_okf_path`: resolves relative vs `/`-rooted bundle paths with `v0.2` fallback (§6.2, §12.1).
- `canonical_content_hash`: computes no-churn SHA-256 over canonical frontmatter + body.
- `validate_okf_concept`: validates OKF v0.3 §4–§11 conformance, citations, and Attested Computations.
- `migrate_legacy_sources_in_frontmatter`: deterministically upgrades string `sources:` to `{id, resource}`.
- `stamp_human_verification`: deterministically records `human:<id>` verification in frontmatter.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any
import urllib.parse

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

SUPPORTED_OKF_VERSION = "0.3"
SUPPORTED_OKF_VERSIONS = ("0.2", "0.3")
OKF_VALID_STATUSES = frozenset({"draft", "stable", "deprecated"})
MAX_FRONTMATTER_BYTES = 16 * 1024  # 16 KiB hard frontmatter cap
MAX_YAML_NESTING_DEPTH = 64  # Hard cap on flow/block nesting depth

_FRONTMATTER_RE = re.compile(
    r"\A---[ \t]*(\r?\n)(?:([\s\S]*?)\r?\n)?---[ \t]*(\r?\n|\Z)([\s\S]*)\Z"
)
_OPENING_FENCE_ONLY_RE = re.compile(r"\A---[ \t]*(?:\r?\n|\Z)")
_BLOCK_SCALAR_HEADER_RE = re.compile(r"^[|>](?:[-+][1-9]?|[1-9][-+]*|[0-9]*)$")
_INT_RE = re.compile(r"^[+-]?(?:0|[1-9][0-9]*)$")
_HEX_INT_RE = re.compile(r"^[+-]?0[xX][0-9a-fA-F]+$")
_FLOAT_RE = re.compile(
    r"^[+-]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][+-][0-9]+)?$"
)
_ISO_DATE_ONLY_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
_ISO_DATETIME_WITH_OFFSET_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
_ACTOR_RE = re.compile(r"^([^\s/:]+/\S+|[A-Za-z][A-Za-z0-9+.-]*:\S+)$")
_PATH_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_ATX_HEADING_RE = re.compile(r"^[ \t]{0,3}(#{1,6})[ \t]+(.*?)[ \t]*#*[ \t]*$")

_FENCE_LINE_RE = re.compile(r"^[ \t]*(?:>[ \t]*)*(`{3,}|~{3,})(.*)$")
_BACKTICK_RUN_RE = re.compile(r"`+")
_FOOTNOTE_DEF_RE = re.compile(r"(?m)^[ \t]*\[\^([^\]\s]+)\]:")
_FOOTNOTE_REF_RE = re.compile(r"\[\^([^\]\s]+)\](?!:)")
_COMPUTATION_HEADING_RE = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]+Computation\b")
_HUMAN_ID_RE = re.compile(r"^[A-Za-z0-9._@-]+$")


class OKFParseError(ValueError):
    """Raised when OKF YAML frontmatter violates size limits, safety rules, or YAML syntax."""


def _get_yaml_module(use_pyyaml: bool = True) -> Any:
    """Return active PyYAML module if enabled and not disabled in sys.modules."""
    if not use_pyyaml:
        return None
    if yaml is None:
        return None
    if "yaml" in sys.modules and sys.modules["yaml"] is None:
        return None
    return yaml


def _coerce_unquoted_scalar(s: str) -> Any:
    """Coerce an unquoted YAML scalar string using OKF v0.2 / YAML 1.2 Core Schema rules."""
    if not s or s in ("null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if _INT_RE.match(s):
        try:
            return int(s)
        except ValueError:
            pass
    if _HEX_INT_RE.match(s):
        try:
            return int(s, 16)
        except ValueError:
            pass
    if _FLOAT_RE.match(s):
        try:
            return float(s)
        except ValueError:
            pass
    low = s.lower()
    if low in (".inf", "+.inf"):
        return float("inf")
    if low == "-.inf":
        return float("-inf")
    if low == ".nan":
        return "NaN"
    return s


def _build_okf_safe_loader(yaml_mod: Any) -> Any:
    """Build a YAML 1.2 Core Schema SafeLoader subclass rejecting anchors, aliases, and merge keys."""
    base_loader = getattr(yaml_mod, "SafeLoader", None)
    if base_loader is None:
        return None

    class _OKFSafeLoader(base_loader):  # type: ignore[valid-type,misc]
        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml_mod.events.AliasEvent):
                ev = self.peek_event()
                alias_name = getattr(ev, "anchor", "")
                raise OKFParseError(
                    f"YAML alias '*{alias_name}' is forbidden in OKF frontmatter"
                )
            ev = self.peek_event()
            anchor = getattr(ev, "anchor", None)
            if anchor is not None:
                raise OKFParseError(
                    f"YAML anchor '&{anchor}' is forbidden in OKF frontmatter"
                )
            return base_loader.compose_node(self, parent, index)

        def flatten_mapping(self, node: Any) -> None:
            for key_node, _val_node in node.value:
                if key_node.tag == "tag:yaml.org,2002:merge" or (
                    isinstance(key_node, yaml_mod.ScalarNode)
                    and key_node.style is None
                    and key_node.value == "<<"
                ):
                    raise OKFParseError(
                        "YAML merge keys ('<<:') are forbidden in OKF frontmatter"
                    )
            base_loader.flatten_mapping(self, node)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
            self.flatten_mapping(node)
            mapping: dict[str, Any] = {}
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml_mod.ScalarNode):
                    key_str = str(self.construct_scalar(key_node))
                else:
                    key_obj = self.construct_object(key_node, deep=deep)
                    key_str = str(key_obj)
                val_obj = self.construct_object(value_node, deep=deep)
                mapping[key_str] = val_obj
            return mapping

    def _construct_okf_scalar(loader: Any, node: Any) -> Any:
        val = loader.construct_scalar(node)
        return _coerce_unquoted_scalar(str(val))

    def _reject_merge(loader: Any, node: Any) -> Any:
        raise OKFParseError("YAML merge keys ('<<:') are forbidden in OKF frontmatter")

    for tag in (
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:timestamp",
        "tag:yaml.org,2002:value",
    ):
        _OKFSafeLoader.add_constructor(tag, _construct_okf_scalar)
    _OKFSafeLoader.add_constructor("tag:yaml.org,2002:merge", _reject_merge)
    return _OKFSafeLoader


def _normalize_parsed_obj(obj: Any) -> Any:
    """Ensure parsed YAML primitives are clean JSON-compatible types across PyYAML and stdlib."""
    if isinstance(obj, datetime):
        if obj.tzinfo is not None:
            try:
                utc_dt = obj.astimezone(timezone.utc)
                return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OverflowError):
                return obj.isoformat()
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, float) and math.isnan(obj):
        return "NaN"
    if isinstance(obj, dict):
        return {str(k): _normalize_parsed_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_parsed_obj(v) for v in obj]
    return obj


def split_frontmatter(content: str) -> tuple[str, str | None, str]:
    """Split Markdown content into `(raw_frontmatter_with_fences, yaml_text, body)`.

    If no valid closed frontmatter block is present at the start of the document,
    returns `("", None, content)`.
    """
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    if not text.startswith("---"):
        return "", None, content
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return "", None, content
    yaml_text = match.group(2) if match.group(2) is not None else ""
    body = match.group(4)
    fm_prefix = bom + text[: match.start(4)]
    return fm_prefix, yaml_text, body


def _has_unclosed_frontmatter_fence(content: str) -> bool:
    """Return True if `content` starts with an opening `---` line but has no closing `---` line."""
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    if not _OPENING_FENCE_ONLY_RE.match(text):
        return False
    return _FRONTMATTER_RE.match(text) is None


def _leading_spaces(line: str) -> int:
    count = 0
    for ch in line:
        if ch == " ":
            count += 1
        else:
            break
    return count


def _extract_block_header_indent_digit(header: str) -> int | None:
    """Return explicit block scalar indentation indicator digit (1..9) if present in `header`."""
    for ch in header[1:]:
        if ch.isdigit() and ch != "0":
            return int(ch)
    return None


def _strip_comment_from_block_header_tail(tail: str) -> str:
    """Strip optional `# ...` comment after a block scalar header like `| # comment`."""
    for i, ch in enumerate(tail):
        if ch == "#" and (i == 0 or tail[i - 1] in (" ", "\t")):
            return tail[:i].strip()
    return tail.strip()


def _check_forbidden_yaml_constructs(yaml_text: str, *, strict: bool = True) -> None:
    """Stateful YAML pre-scanner rejecting anchors (&), aliases (*), merge keys (<<:), and tab indents.

    Accurately tracks block scalars (including `- k: |` sequence item mappings and `|2` indicators),
    multi-line single/double-quoted scalars, flow collections, and plain scalars so quotes or `*`/`&`
    inside plain scalars (`title: Trends of the '90s`, `description: Fast, *really* fast`,
    `x: [p "q, &a0 [lol], z" w]`) are never misclassified.
    """
    in_block_scalar = False
    block_parent_indent = 0
    block_base_indent: int | None = None

    in_quote: str | None = None
    escaped = False
    flow_stack: list[str] = []
    at_node_start = True
    in_plain_scalar = False
    just_closed_quote = False

    for idx, raw_line in enumerate(yaml_text.splitlines(), start=1):
        # 1. Handle active block scalar lines
        if in_block_scalar:
            if not raw_line.strip():
                continue
            leading_sp = _leading_spaces(raw_line)
            if leading_sp > block_parent_indent and (
                block_base_indent is None or leading_sp >= block_base_indent
            ):
                if block_base_indent is None:
                    block_base_indent = leading_sp
                continue
            in_block_scalar = False
            block_base_indent = None

        # 2. Outside multi-line quotes, check tab indentation and reset block-line state
        if in_quote is None:
            if not raw_line.strip():
                if len(flow_stack) == 0:
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                continue

            if strict and re.match(r"^ *\t", raw_line):
                raise OKFParseError(
                    f"Tab indentation is not allowed in YAML frontmatter (line {idx})"
                )

            if len(flow_stack) == 0:
                stripped_line = raw_line.strip()
                if _leading_spaces(raw_line) == 0 and (
                    stripped_line == "..."
                    or stripped_line.startswith("... ")
                    or stripped_line.startswith("...\t")
                    or stripped_line.startswith("...#")
                ):
                    break
                at_node_start = True
                in_plain_scalar = False
                just_closed_quote = False

        # Track key column on the current block line for block scalar parent indentation
        line_indent = _leading_spaces(raw_line)
        if strict and line_indent > MAX_YAML_NESTING_DEPTH * 2:
            raise OKFParseError(
                f"YAML block indentation depth ({line_indent}) exceeds maximum allowed limit (line {idx})"
            )
        current_key_col = line_indent
        saw_colon_on_line = False
        pending_node_col: int | None = None

        i = 0
        n = len(raw_line)
        while i < n:
            ch = raw_line[i]

            if in_quote == '"':
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_quote = None
                    at_node_start = False
                    in_plain_scalar = False
                    just_closed_quote = True
                i += 1
                continue

            if in_quote == "'":
                if ch == "'":
                    if i + 1 < n and raw_line[i + 1] == "'":
                        i += 2
                        continue
                    in_quote = None
                    at_node_start = False
                    in_plain_scalar = False
                    just_closed_quote = True
                i += 1
                continue

            # Outside quotes: check inline comment
            if ch == "#" and (i == 0 or raw_line[i - 1] in (" ", "\t")):
                break

            if ch in (" ", "\t"):
                if (
                    strict
                    and ch == "\t"
                    and in_plain_scalar
                    and len(flow_stack) == 0
                    and raw_line[i:].strip() == ""
                ):
                    raise OKFParseError(
                        f"Trailing tab character after plain scalar is not allowed in YAML (line {idx})"
                    )
                i += 1
                continue

            if at_node_start:
                # Sequence `- ` or complex key `? ` indicator in block context
                if (
                    len(flow_stack) == 0
                    and ch in ("-", "?")
                    and (i + 1 == n or raw_line[i + 1] in (" ", "\t"))
                ):
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    pending_node_col = None
                    i += 1
                    continue

                if pending_node_col is None and not saw_colon_on_line:
                    pending_node_col = i

                # Merge key `<<:`
                if raw_line[i:].startswith("<<") and re.match(
                    r"^<<[ \t]*:(?:[ \t,\]\}]|\Z)", raw_line[i:]
                ):
                    raise OKFParseError(
                        f"YAML merge keys ('<<:') are forbidden in OKF frontmatter (line {idx})"
                    )

                # Forbidden anchor `&` or alias `*`
                if ch in ("&", "*"):
                    kind = "anchor" if ch == "&" else "alias"
                    raise OKFParseError(
                        f"YAML {kind} is forbidden in OKF frontmatter (line {idx})"
                    )

                # YAML tag `!tag`
                if ch == "!":
                    while i < n and raw_line[i] not in (" ", "\t", ",", "]", "}"):
                        i += 1
                    continue

                # Quoted scalar opener `"` or `'`
                if ch in ('"', "'"):
                    in_quote = ch
                    escaped = False
                    at_node_start = False
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

                # Flow collection opener `[` or `{`
                if ch in ("[", "{"):
                    flow_stack.append("]" if ch == "[" else "}")
                    if strict and len(flow_stack) > MAX_YAML_NESTING_DEPTH:
                        raise OKFParseError(
                            f"YAML flow collection nesting depth exceeds maximum allowed limit ({MAX_YAML_NESTING_DEPTH}) at line {idx}"
                        )
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

                # Flow collection closer `]` or `}` (e.g. empty `[]` / `{}` or after trailing `,`)
                if ch in ("]", "}") and len(flow_stack) > 0:
                    if flow_stack[-1] != ch:
                        if strict:
                            raise OKFParseError(
                                f"Mismatched closing bracket '{ch}' in YAML frontmatter (line {idx})"
                            )
                    else:
                        flow_stack.pop()
                    at_node_start = False
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

                # Comma inside flow collection
                if ch == "," and len(flow_stack) > 0:
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

                # Block scalar header `|` or `>` in block context
                if len(flow_stack) == 0 and ch in ("|", ">"):
                    hdr = _strip_comment_from_block_header_tail(raw_line[i:])
                    if _BLOCK_SCALAR_HEADER_RE.match(hdr):
                        in_block_scalar = True
                        block_parent_indent = (
                            current_key_col if saw_colon_on_line else line_indent
                        )
                        explicit_digit = _extract_block_header_indent_digit(hdr)
                        block_base_indent = (
                            block_parent_indent + explicit_digit
                            if explicit_digit is not None
                            else None
                        )
                        break

                # Bare mapping value indicator `: ` at start of line (after `? key`)
                if ch == ":" and (i + 1 == n or raw_line[i + 1] in (" ", "\t")):
                    saw_colon_on_line = True
                    current_key_col = pending_node_col if pending_node_col is not None else line_indent
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

                # Reserved YAML indicators `@` and `` ` `` cannot start a plain scalar
                if strict and ch in ("@", "`"):
                    raise OKFParseError(
                        f"Reserved YAML indicator '{ch}' cannot start a plain scalar (line {idx})"
                    )

                # Otherwise this character starts a plain scalar
                at_node_start = False
                in_plain_scalar = True
                just_closed_quote = False
                i += 1
                continue

            # Not at_node_start: check for mapping separator `:` or flow delimiters
            if ch == ":":
                is_map_colon = (
                    i + 1 == n
                    or raw_line[i + 1] in (" ", "\t")
                    or just_closed_quote
                    or (len(flow_stack) > 0 and raw_line[i + 1] in (",", "]", "}"))
                )
                if is_map_colon:
                    if not saw_colon_on_line and len(flow_stack) == 0:
                        saw_colon_on_line = True
                        current_key_col = (
                            pending_node_col
                            if pending_node_col is not None
                            else line_indent
                        )
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

            if len(flow_stack) > 0:
                if ch == ",":
                    at_node_start = True
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue
                if ch in ("]", "}"):
                    if flow_stack[-1] != ch:
                        if strict:
                            raise OKFParseError(
                                f"Mismatched closing bracket '{ch}' in YAML frontmatter (line {idx})"
                            )
                    else:
                        flow_stack.pop()
                    at_node_start = False
                    in_plain_scalar = False
                    just_closed_quote = False
                    i += 1
                    continue

            if just_closed_quote and len(flow_stack) == 0:
                if strict:
                    raise OKFParseError(
                        f"Unexpected trailing characters after quoted YAML scalar (line {idx})"
                    )

            just_closed_quote = False
            i += 1

    if strict and in_quote is not None:
        raise OKFParseError("Unclosed quoted string in YAML frontmatter")
    if strict and len(flow_stack) > 0:
        raise OKFParseError("Unclosed flow collection in YAML frontmatter")


def _strip_inline_comment(line: str) -> str:
    """Strip `# ...` comments outside node-start quotes, preserving quotes mid-plain-scalar."""
    in_quote: str | None = None
    escaped = False
    flow_stack: list[str] = []
    at_node_start = True
    just_closed_quote = False
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]
        if in_quote == '"':
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue

        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and line[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue

        if ch == "#" and (i == 0 or line[i - 1] in (" ", "\t")):
            return line[:i].rstrip(" \t")

        if ch in (" ", "\t"):
            i += 1
            continue

        if at_node_start:
            if (
                len(flow_stack) == 0
                and ch in ("-", "?")
                and (i + 1 == n or line[i + 1] in (" ", "\t"))
            ):
                i += 1
                continue
            if ch in ("!", "&"):
                while i < n and line[i] not in (" ", "\t", ",", "]", "}"):
                    i += 1
                continue
            if ch in ('"', "'"):
                in_quote = ch
                escaped = False
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch in ("[", "{"):
                flow_stack.append("]" if ch == "[" else "}")
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch in ("]", "}") and len(flow_stack) > 0:
                flow_stack.pop()
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch == "," and len(flow_stack) > 0:
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch == ":" and (i + 1 == n or line[i + 1] in (" ", "\t")):
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            at_node_start = False
            just_closed_quote = False
            i += 1
            continue

        if ch == ":" and (
            i + 1 == n
            or line[i + 1] in (" ", "\t")
            or just_closed_quote
            or (len(flow_stack) > 0 and line[i + 1] in (",", "]", "}"))
        ):
            at_node_start = True
            just_closed_quote = False
            i += 1
            continue

        if len(flow_stack) > 0:
            if ch == ",":
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch in ("]", "}"):
                flow_stack.pop()
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue

        just_closed_quote = False
        i += 1

    return line.rstrip(" \t")


def _find_top_level_colon(text: str) -> int:
    """Find index of the first mapping key separator `:` outside node-start quotes/brackets."""
    in_quote: str | None = None
    escaped = False
    depth = 0
    at_node_start = True
    just_closed_quote = False
    n = len(text)
    i = 0
    while i < n:
        ch = text[i]
        if in_quote == '"':
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue

        if ch in (" ", "\t"):
            i += 1
            continue

        if at_node_start:
            if ch in ('"', "'"):
                in_quote = ch
                escaped = False
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch in ("[", "{"):
                depth += 1
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch in ("]", "}") and depth > 0:
                depth -= 1
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch == "," and depth > 0:
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch == ":" and depth == 0 and (i + 1 == n or text[i + 1] in (" ", "\t")):
                return i
            at_node_start = False
            just_closed_quote = False
            i += 1
            continue

        if ch in ("[", "{") and depth > 0:
            depth += 1
            just_closed_quote = False
        elif ch in ("]", "}") and depth > 0:
            depth -= 1
            just_closed_quote = False
        elif ch == "," and depth > 0:
            at_node_start = True
            just_closed_quote = False
        elif ch == ":" and depth == 0:
            if i + 1 == n or text[i + 1] in (" ", "\t") or just_closed_quote:
                return i
            just_closed_quote = False
        elif ch == ":" and depth > 0 and (i + 1 == n or text[i + 1] in (" ", "\t")):
            at_node_start = True
            just_closed_quote = False
        else:
            just_closed_quote = False
        i += 1
    return -1


def _flow_bracket_balance(text: str) -> int:
    """Return net open bracket count (`[` and `{` minus `]` and `}`) outside node-start quotes."""
    stack: list[str] = []
    in_quote: str | None = None
    escaped = False
    at_node_start = True
    just_closed_quote = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_quote == '"':
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue

        if ch in (" ", "\t", "\r", "\n"):
            i += 1
            continue

        if at_node_start:
            if ch in ('"', "'"):
                in_quote = ch
                escaped = False
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch in ("[", "{"):
                stack.append("]" if ch == "[" else "}")
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch in ("]", "}"):
                if not stack or stack[-1] != ch:
                    raise OKFParseError(
                        f"Mismatched closing bracket '{ch}' in YAML flow collection"
                    )
                stack.pop()
                at_node_start = False
                just_closed_quote = False
                i += 1
                continue
            if ch == "," and len(stack) > 0:
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            at_node_start = False
            just_closed_quote = False
            i += 1
            continue

        if ch in ("]", "}"):
            if not stack or stack[-1] != ch:
                raise OKFParseError(
                    f"Mismatched closing bracket '{ch}' in YAML flow collection"
                )
            stack.pop()
            at_node_start = False
            just_closed_quote = False
        elif ch == "," and len(stack) > 0:
            at_node_start = True
            just_closed_quote = False
        elif ch == ":" and (
            i + 1 == n
            or text[i + 1] in (" ", "\t", "\r", "\n", ",", "]", "}")
            or just_closed_quote
        ):
            at_node_start = True
            just_closed_quote = False
        else:
            just_closed_quote = False
        i += 1
    if in_quote is not None:
        raise OKFParseError("Unclosed quoted string inside YAML flow collection")
    return len(stack)


def _split_flow_items(inner: str) -> list[str]:
    """Split contents of `[...]` or `{...}` on top-level commas outside node-start quotes and nested brackets."""
    items: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    escaped = False
    depth = 0
    at_node_start = True
    just_closed_quote = False
    i = 0
    n = len(inner)
    while i < n:
        ch = inner[i]
        if in_quote == '"':
            buf.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue
        if in_quote == "'":
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and inner[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_quote = None
                at_node_start = False
                just_closed_quote = True
            i += 1
            continue

        if ch in (" ", "\t", "\r", "\n"):
            buf.append(ch)
            i += 1
            continue

        if at_node_start:
            if ch in ('"', "'"):
                in_quote = ch
                escaped = False
                at_node_start = False
                just_closed_quote = False
                buf.append(ch)
                i += 1
                continue
            if ch in ("[", "{"):
                depth += 1
                at_node_start = True
                just_closed_quote = False
                buf.append(ch)
                i += 1
                continue
            if ch in ("]", "}") and depth > 0:
                depth -= 1
                at_node_start = False
                just_closed_quote = False
                buf.append(ch)
                i += 1
                continue
            if ch == "," and depth == 0:
                items.append("".join(buf).strip())
                buf = []
                at_node_start = True
                just_closed_quote = False
                i += 1
                continue
            if ch in ("&", "!"):
                m_prop = re.match(r"^(?:&[A-Za-z0-9_-]+|![^\s,\[\]\{\}]+)", inner[i:])
                if m_prop:
                    buf.append(m_prop.group(0))
                    i += len(m_prop.group(0))
                    at_node_start = True
                    just_closed_quote = False
                    continue
            at_node_start = False
            just_closed_quote = False
            buf.append(ch)
            i += 1
            continue

        if ch in ("]", "}") and depth > 0:
            depth -= 1
            just_closed_quote = False
            buf.append(ch)
        elif ch == "," and depth == 0:
            items.append("".join(buf).strip())
            buf = []
            at_node_start = True
            just_closed_quote = False
        elif ch == "," and depth > 0:
            at_node_start = True
            just_closed_quote = False
            buf.append(ch)
        elif ch == ":" and (
            i + 1 == n
            or inner[i + 1] in (" ", "\t", "\r", "\n", ",", "]", "}")
            or just_closed_quote
        ):
            at_node_start = True
            just_closed_quote = False
            buf.append(ch)
        else:
            just_closed_quote = False
            buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        items.append(tail)
    return items


def _unescape_double_quoted(inner: str) -> str:
    """Unescape YAML double-quoted string escapes."""
    out: list[str] = []
    i = 0
    n = len(inner)
    escapes = {
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "\\": "\\",
        '"': '"',
        "/": "/",
        "0": "\0",
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "f": "\f",
        "v": "\v",
        " ": " ",
        "_": "\xa0",
        "N": "\x85",
        "L": "\u2028",
        "P": "\u2029",
    }
    while i < n:
        ch = inner[i]
        if ch == "\\" and i + 1 < n:
            nxt = inner[i + 1]
            if nxt in escapes:
                out.append(escapes[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < n:
                try:
                    out.append(chr(int(inner[i + 2 : i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt == "u" and i + 5 < n:
                try:
                    out.append(chr(int(inner[i + 2 : i + 6], 16)))
                    i += 6
                    continue
                except ValueError:
                    pass
            if nxt == "U" and i + 9 < n:
                try:
                    out.append(chr(int(inner[i + 2 : i + 10], 16)))
                    i += 10
                    continue
                except ValueError:
                    pass
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _find_closing_quote(s: str, quote_ch: str, start_idx: int = 1) -> int:
    """Find closing quote index in `s` starting at `start_idx`, or return `-1` if unclosed on this line."""
    i = start_idx
    n = len(s)
    if quote_ch == '"':
        escaped = False
        while i < n:
            ch = s[i]
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                return i
            i += 1
        return -1

    while i < n:
        if s[i] == "'":
            if i + 1 < n and s[i + 1] == "'":
                i += 2
                continue
            return i
        i += 1
    return -1


def _fold_quoted_segments(segments: list[str], quote_ch: str) -> str:
    """Fold multi-line quoted scalar segments according to YAML flow line-folding rules."""
    if not segments:
        return ""
    if len(segments) == 1:
        raw_inner = segments[0]
    else:
        out_parts: list[str] = [segments[0]]
        i = 1
        n = len(segments)
        while i < n:
            if segments[i] == "":
                blanks = 0
                while i < n and segments[i] == "":
                    blanks += 1
                    i += 1
                # In double-quoted strings, an unescaped trailing `\` before newline escapes the break
                prev = out_parts[-1]
                if quote_ch == '"' and (len(prev) - len(prev.rstrip("\\"))) % 2 == 1:
                    out_parts[-1] = prev[:-1]
                    out_parts.append("\n" * blanks)
                else:
                    out_parts.append("\n" * blanks)
                if i < n:
                    out_parts.append(segments[i])
                    i += 1
                continue

            prev = out_parts[-1]
            if quote_ch == '"' and (len(prev) - len(prev.rstrip("\\"))) % 2 == 1:
                out_parts[-1] = prev[:-1]
                out_parts.append(segments[i])
            else:
                out_parts.append(" ")
                out_parts.append(segments[i])
            i += 1
        raw_inner = "".join(out_parts)

    if quote_ch == '"':
        return _unescape_double_quoted(raw_inner)
    return raw_inner.replace("''", "'")


def _consume_multiline_quoted(
    raw_lines: list[str],
    first_val: str,
    next_idx: int,
    quote_ch: str,
    *,
    strict: bool = True,
) -> tuple[str, int]:
    """Consume a single-quoted or double-quoted scalar that spans one or more lines."""
    close_idx = _find_closing_quote(first_val, quote_ch, 1)
    if close_idx >= 0:
        trailing = first_val[close_idx + 1 :].strip()
        if trailing and not trailing.startswith("#"):
            if strict:
                raise OKFParseError(
                    f"Unexpected trailing characters after quoted YAML scalar: {first_val!r}"
                )
        return _fold_quoted_segments([first_val[1:close_idx]], quote_ch), next_idx

    segments: list[str] = [first_val[1:].rstrip(" \t")]
    idx = next_idx
    n = len(raw_lines)
    while idx < n:
        raw = raw_lines[idx]
        if not raw.strip():
            segments.append("")
            idx += 1
            continue
        trimmed = raw.lstrip(" \t")
        c_idx = _find_closing_quote(trimmed, quote_ch, 0)
        if c_idx >= 0:
            trailing = trimmed[c_idx + 1 :].strip()
            if trailing and not trailing.startswith("#"):
                if strict:
                    raise OKFParseError(
                        f"Unexpected trailing characters after multi-line quoted scalar at line {idx + 1}"
                    )
            segments.append(trimmed[:c_idx])
            idx += 1
            return _fold_quoted_segments(segments, quote_ch), idx
        segments.append(trimmed.rstrip(" \t"))
        idx += 1

    if strict:
        raise OKFParseError("Unclosed multi-line quoted string in YAML frontmatter")
    return _fold_quoted_segments(segments, quote_ch), idx


def _parse_key_token(raw_key: str, *, strict: bool = True) -> str:
    """Parse a mapping key token (quoted or unquoted)."""
    k = _strip_yaml_node_properties(raw_key.strip())
    if not k:
        if strict:
            raise OKFParseError("Empty mapping key in YAML frontmatter")
        return ""
    if k.startswith('"'):
        close_idx = _find_closing_quote(k, '"', 1)
        if close_idx != len(k) - 1:
            if strict:
                raise OKFParseError(f"Unclosed double quote in YAML key: {raw_key!r}")
            return k.strip('"')
        return _unescape_double_quoted(k[1:-1])
    if k.startswith("'"):
        close_idx = _find_closing_quote(k, "'", 1)
        if close_idx != len(k) - 1:
            if strict:
                raise OKFParseError(f"Unclosed single quote in YAML key: {raw_key!r}")
            return k.strip("'")
        return k[1:-1].replace("''", "'")
    if strict and any(ch in k for ch in ("[", "]", "{", "}")):
        raise OKFParseError(f"Invalid flow bracket in unquoted YAML key: {raw_key!r}")
    return k


def _parse_scalar_or_flow(val_str: str, *, strict: bool = True) -> Any:
    """Parse a scalar value, inline flow list `[...]`, or inline flow mapping `{...}`."""
    s = val_str.strip()
    if not s:
        return None

    # Strip explicit leading YAML tags (`!tag`, `!!str`, `!!seq`, `!!map`)
    force_str = False
    while s.startswith("!"):
        m_tag = re.match(r"^![^\s,\[\]\{\}]*[ \t]*(.*)$", s, flags=re.DOTALL)
        if not m_tag:
            break
        tag_tok = s[: len(s) - len(m_tag.group(1))].strip()
        if tag_tok == "!!str":
            force_str = True
        s = m_tag.group(1).strip()
        if not s:
            return "" if force_str else None

    if s.startswith("["):
        if not s.endswith("]"):
            if strict:
                raise OKFParseError(f"Unclosed flow sequence: {val_str!r}")
            s = s + "]"
        _flow_bracket_balance(s)
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [
            _parse_scalar_or_flow(item, strict=strict)
            for item in _split_flow_items(inner)
        ]

    if s.startswith("{"):
        if not s.endswith("}"):
            if strict:
                raise OKFParseError(f"Unclosed flow mapping: {val_str!r}")
            s = s + "}"
        _flow_bracket_balance(s)
        inner = s[1:-1].strip()
        if not inner:
            return {}
        result: dict[str, Any] = {}
        for entry in _split_flow_items(inner):
            if not entry:
                continue
            colon_idx = _find_top_level_colon(entry)
            if colon_idx < 0:
                if strict:
                    raise OKFParseError(
                        f"Missing ':' in flow mapping entry: {entry!r}"
                    )
                continue
            k = _parse_key_token(entry[:colon_idx], strict=strict)
            v_raw = entry[colon_idx + 1 :].strip()
            result[k] = _parse_scalar_or_flow(v_raw, strict=strict)
        return result

    if s.startswith('"'):
        close_pos = _find_closing_quote(s, '"', 1)
        if close_pos != len(s) - 1:
            if strict:
                raise OKFParseError(f"Malformed double-quoted YAML scalar: {val_str!r}")
            return s.strip('"')
        return _unescape_double_quoted(s[1:-1])

    if s.startswith("'"):
        close_pos = _find_closing_quote(s, "'", 1)
        if close_pos != len(s) - 1:
            if strict:
                raise OKFParseError(f"Malformed single-quoted YAML scalar: {val_str!r}")
            return s.strip("'")
        return s[1:-1].replace("''", "'")

    if strict:
        if s[0] in ("@", "`"):
            raise OKFParseError(
                f"Reserved YAML indicator '{s[0]}' cannot start a plain scalar: {val_str!r}"
            )
        if s == "-" or s.startswith(("- ", "-\t", "? ", "?\t")):
            raise OKFParseError(
                f"Block indicator cannot start an inline YAML scalar value: {val_str!r}"
            )
        if _find_top_level_colon(s) >= 0:
            raise OKFParseError(
                f"Invalid unquoted colon in YAML scalar value: {val_str!r}"
            )

    if force_str:
        return s
    return _coerce_unquoted_scalar(s)


def _fold_block_lines(content_lines: list[str]) -> str:
    """Fold lines according to YAML `>` / `>-` folded block scalar rules."""
    if not content_lines:
        return ""
    out: list[str] = []
    i = 0
    n = len(content_lines)
    while i < n:
        line = content_lines[i]
        if line == "":
            start_blank = i
            blanks = 0
            while i < n and content_lines[i] == "":
                blanks += 1
                i += 1
            prev_more_indented = start_blank > 0 and content_lines[
                start_blank - 1
            ].startswith((" ", "\t"))
            next_more_indented = i < n and content_lines[i].startswith((" ", "\t"))
            if start_blank > 0 and i < n and (prev_more_indented or next_more_indented):
                out.append("\n" * (blanks + 1))
            else:
                out.append("\n" * blanks)
            continue

        is_more_indented = line.startswith((" ", "\t"))
        out.append(line)
        if i + 1 < n:
            nxt = content_lines[i + 1]
            if nxt == "":
                pass
            elif is_more_indented or nxt.startswith((" ", "\t")):
                out.append("\n")
            else:
                out.append(" ")
        i += 1
    return "".join(out)


def _consume_block_scalar(
    raw_lines: list[str], start_idx: int, parent_indent: int, header: str
) -> tuple[str, int]:
    """Consume an indented YAML block scalar (`|`, `|-`, `|+`, `|2`, `>`, `>-`, `>+`)."""
    style = header[0]
    chomp = "-" if "-" in header else ("+" if "+" in header else "clip")
    explicit_digit = _extract_block_header_indent_digit(header)

    collected_raw: list[str] = []
    idx = start_idx
    n = len(raw_lines)
    base_indent: int | None = (
        parent_indent + explicit_digit if explicit_digit is not None else None
    )

    while idx < n:
        line = raw_lines[idx]
        if not line.strip():
            collected_raw.append("")
            idx += 1
            continue
        indent = _leading_spaces(line)
        if indent <= parent_indent:
            break
        if base_indent is None:
            base_indent = indent
        elif indent < base_indent:
            break
        collected_raw.append(line[base_indent:])
        idx += 1

    trailing_empty = 0
    while collected_raw and collected_raw[-1] == "":
        collected_raw.pop()
        trailing_empty += 1

    if not collected_raw:
        return ("", idx)

    if style == "|":
        body_text = "\n".join(collected_raw)
    else:
        body_text = _fold_block_lines(collected_raw)

    if chomp == "-":
        return body_text, idx
    if chomp == "+":
        return body_text + "\n" * (1 + trailing_empty), idx
    return body_text + "\n", idx


def _accumulate_multiline_flow(
    raw_lines: list[str],
    start_val: str,
    next_idx: int,
    *,
    strict: bool = True,
) -> tuple[str, int]:
    """Accumulate lines in O(N) time until flow brackets `[...]` or `{...}` balance."""
    parts = [start_val]
    idx = next_idx
    n = len(raw_lines)

    # Track open bracket stack incrementally across lines in O(N) total time
    stack: list[str] = []
    in_quote: str | None = None
    escaped = False
    at_node_start = True
    just_closed_quote = False

    def _feed_segment(seg: str) -> None:
        nonlocal in_quote, escaped, at_node_start, just_closed_quote
        i = 0
        seg_len = len(seg)
        while i < seg_len:
            ch = seg[i]
            if in_quote == '"':
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_quote = None
                    at_node_start = False
                    just_closed_quote = True
                i += 1
                continue
            if in_quote == "'":
                if ch == "'":
                    if i + 1 < seg_len and seg[i + 1] == "'":
                        i += 2
                        continue
                    in_quote = None
                    at_node_start = False
                    just_closed_quote = True
                i += 1
                continue
            if ch in (" ", "\t", "\r", "\n"):
                i += 1
                continue
            if at_node_start:
                if ch in ('"', "'"):
                    in_quote = ch
                    escaped = False
                    at_node_start = False
                    just_closed_quote = False
                elif ch in ("[", "{"):
                    stack.append("]" if ch == "[" else "}")
                    at_node_start = True
                    just_closed_quote = False
                elif ch in ("]", "}"):
                    if not stack or stack[-1] != ch:
                        raise OKFParseError(
                            f"Mismatched closing bracket '{ch}' in YAML flow collection"
                        )
                    stack.pop()
                    at_node_start = False
                    just_closed_quote = False
                elif ch == "," and len(stack) > 0:
                    at_node_start = True
                    just_closed_quote = False
                else:
                    at_node_start = False
                    just_closed_quote = False
                i += 1
                continue
            if ch in ("]", "}"):
                if not stack or stack[-1] != ch:
                    raise OKFParseError(
                        f"Mismatched closing bracket '{ch}' in YAML flow collection"
                    )
                stack.pop()
                at_node_start = False
                just_closed_quote = False
            elif ch == "," and len(stack) > 0:
                at_node_start = True
                just_closed_quote = False
            elif ch == ":" and (
                i + 1 == seg_len
                or seg[i + 1] in (" ", "\t", "\r", "\n", ",", "]", "}")
                or just_closed_quote
            ):
                at_node_start = True
                just_closed_quote = False
            else:
                just_closed_quote = False
            i += 1

    _feed_segment(start_val)
    while (len(stack) > 0 or in_quote is not None) and idx < n:
        cleaned = (
            raw_lines[idx].strip()
            if in_quote is not None
            else _strip_inline_comment(raw_lines[idx]).strip()
        )
        if cleaned:
            parts.append(cleaned)
            _feed_segment(cleaned)
        idx += 1
    if (len(stack) > 0 or in_quote is not None) and strict:
        raise OKFParseError("Unclosed multi-line flow collection in YAML frontmatter")
    return " ".join(parts), idx


def _next_nonempty_line(
    raw_lines: list[str], start_idx: int
) -> tuple[int, int, str] | None:
    """Find next non-empty, non-comment line returning `(line_idx, indent, cleaned_stripped)`."""
    idx = start_idx
    n = len(raw_lines)
    while idx < n:
        raw = raw_lines[idx]
        cleaned = _strip_inline_comment(raw)
        stripped = cleaned.strip()
        if stripped:
            indent = _leading_spaces(raw)
            if indent == 0 and (
                stripped == "..."
                or stripped.startswith("... ")
                or stripped.startswith("...\t")
            ):
                return None
            return idx, indent, stripped
        idx += 1
    return None


def _parse_block_sequence(
    raw_lines: list[str],
    start_idx: int,
    seq_indent: int,
    *,
    strict: bool = True,
) -> tuple[list[Any], int]:
    """Parse an indented YAML block sequence starting at `start_idx` with `seq_indent`."""
    items: list[Any] = []
    idx = start_idx
    n = len(raw_lines)

    while idx < n:
        nxt = _next_nonempty_line(raw_lines, idx)
        if nxt is None:
            idx = n
            break
        line_idx, indent, stripped = nxt
        if indent < seq_indent:
            idx = line_idx
            break
        if indent > seq_indent:
            if strict:
                raise OKFParseError(
                    f"Unexpected indentation inside YAML sequence at line {line_idx + 1}"
                )
            idx = line_idx + 1
            continue

        if not (stripped == "-" or stripped.startswith("- ")):
            idx = line_idx
            break

        after_dash = stripped[1:].strip()
        idx = line_idx + 1

        if not after_dash:
            peek = _next_nonempty_line(raw_lines, idx)
            if peek is None or peek[1] <= seq_indent:
                items.append(None)
                continue
            p_idx, p_indent, p_stripped = peek
            if p_stripped == "-" or p_stripped.startswith("- "):
                sub_seq, idx = _parse_block_sequence(
                    raw_lines, p_idx, p_indent, strict=strict
                )
                items.append(sub_seq)
            else:
                sub_map, idx = _parse_block_mapping(
                    raw_lines, p_idx, p_indent, strict=strict
                )
                items.append(sub_map)
            continue

        # Nested inline block sequence item `- - a\n  - b`
        if after_dash == "-" or after_dash.startswith("- "):
            dash_offset = raw_lines[line_idx].find("-")
            inner_dash_offset = raw_lines[line_idx].find("-", dash_offset + 1)
            patched_lines = list(raw_lines)
            patched_lines[line_idx] = (
                " " * inner_dash_offset + raw_lines[line_idx][inner_dash_offset:]
            )
            sub_seq, idx = _parse_block_sequence(
                patched_lines, line_idx, inner_dash_offset, strict=strict
            )
            items.append(sub_seq)
            continue

        # Block scalar sequence item `- |\n  lit` or `- >-\n  fold`
        if _BLOCK_SCALAR_HEADER_RE.match(after_dash):
            block_str, idx = _consume_block_scalar(
                raw_lines, idx, seq_indent, after_dash
            )
            items.append(block_str)
            continue

        if after_dash.startswith(("[", "{")):
            flow_str, idx = _accumulate_multiline_flow(
                raw_lines, after_dash, idx, strict=strict
            )
            items.append(_parse_scalar_or_flow(flow_str, strict=strict))
            continue

        # Single-line or multi-line quoted scalar sequence item (unless followed by `: ` as a quoted key)
        if after_dash[0] in ('"', "'"):
            q_ch = after_dash[0]
            c_idx = _find_closing_quote(after_dash, q_ch, 1)
            if c_idx < 0:
                q_val, idx = _consume_multiline_quoted(
                    raw_lines, after_dash, idx, q_ch, strict=strict
                )
                items.append(q_val)
                continue
            after_q = after_dash[c_idx + 1 :].strip()
            if not after_q.startswith(":"):
                q_val, idx = _consume_multiline_quoted(
                    raw_lines, after_dash, idx, q_ch, strict=strict
                )
                items.append(q_val)
                continue

        colon_pos = _find_top_level_colon(after_dash)
        if colon_pos >= 0:
            # Inline mapping inside sequence item (e.g. `- id: ga4\n    resource: ...`)
            k = _parse_key_token(after_dash[:colon_pos], strict=strict)
            v_str = after_dash[colon_pos + 1 :].strip()
            dash_offset = raw_lines[line_idx].find("-")
            after_dash_raw = raw_lines[line_idx][dash_offset + 1 :]
            content_offset = len(after_dash_raw) - len(after_dash_raw.lstrip(" "))
            item_map_indent = dash_offset + 1 + max(1, content_offset)

            item_dict: dict[str, Any] = {}
            val, idx = _resolve_mapping_value(
                raw_lines, idx, item_map_indent, v_str, strict=strict
            )
            item_dict[k] = val

            # Consume any continuation keys aligned at item_map_indent
            peek = _next_nonempty_line(raw_lines, idx)
            if (
                peek is not None
                and peek[1] == item_map_indent
                and not (peek[2] == "-" or peek[2].startswith("- "))
            ):
                more_map, idx = _parse_block_mapping(
                    raw_lines, peek[0], item_map_indent, strict=strict
                )
                item_dict.update(more_map)
            elif (
                peek is not None
                and peek[1] > seq_indent
                and peek[1] != item_map_indent
            ):
                if strict:
                    raise OKFParseError(
                        f"Inconsistent indentation in sequence item mapping at line {peek[0] + 1}"
                    )
            items.append(item_dict)
            continue

        items.append(_parse_scalar_or_flow(after_dash, strict=strict))

    return items, idx


def _resolve_mapping_value(
    raw_lines: list[str],
    next_idx: int,
    key_indent: int,
    v_str: str,
    *,
    strict: bool = True,
) -> tuple[Any, int]:
    """Resolve the value of a `key: <v_str>` entry at `key_indent`."""
    had_str_tag = False
    while v_str.startswith("!"):
        m_tag = re.match(r"^![^\s,\[\]\{\}]*[ \t]*(.*)$", v_str, flags=re.DOTALL)
        if not m_tag:
            break
        tag_tok = v_str[: len(v_str) - len(m_tag.group(1))].strip()
        if tag_tok == "!!str":
            had_str_tag = True
        v_str = m_tag.group(1).strip()

    if _BLOCK_SCALAR_HEADER_RE.match(v_str):
        return _consume_block_scalar(raw_lines, next_idx, key_indent, v_str)

    if v_str.startswith(("[", "{")):
        flow_str, idx = _accumulate_multiline_flow(
            raw_lines, v_str, next_idx, strict=strict
        )
        return _parse_scalar_or_flow(flow_str, strict=strict), idx

    if v_str.startswith(('"', "'")):
        return _consume_multiline_quoted(
            raw_lines, v_str, next_idx, v_str[0], strict=strict
        )

    if not v_str:
        peek = _next_nonempty_line(raw_lines, next_idx)
        if peek is None:
            return ("" if had_str_tag else None), len(raw_lines)
        p_idx, p_indent, p_stripped = peek
        if p_indent >= key_indent and (
            p_stripped == "-" or p_stripped.startswith("- ")
        ):
            return _parse_block_sequence(raw_lines, p_idx, p_indent, strict=strict)
        if p_indent > key_indent:
            p_clean = _strip_inline_comment(p_stripped).strip()
            if (
                _find_top_level_colon(p_clean) < 0
                and not p_clean.startswith(("?", "-"))
            ):
                return _resolve_mapping_value(
                    raw_lines,
                    p_idx + 1,
                    key_indent,
                    f"!!str {p_clean}" if had_str_tag else p_clean,
                    strict=strict,
                )
            return _parse_block_mapping(raw_lines, p_idx, p_indent, strict=strict)
        return ("" if had_str_tag else None), p_idx

    val = (
        _parse_scalar_or_flow(f"!!str {v_str}", strict=strict)
        if had_str_tag
        else _parse_scalar_or_flow(v_str, strict=strict)
    )

    # Check if subsequent lines are improperly indented or plain scalar continuations
    idx = next_idx
    while idx < len(raw_lines):
        peek = _next_nonempty_line(raw_lines, idx)
        if peek is None or peek[1] <= key_indent:
            break
        p_idx, _p_indent, p_stripped = peek
        if strict:
            if (
                p_stripped == "-"
                or p_stripped.startswith("- ")
                or _find_top_level_colon(p_stripped) >= 0
            ):
                raise OKFParseError(
                    f"Unexpected indented block under scalar value at line {p_idx + 1}"
                )
        if isinstance(val, str):
            blank_count = sum(
                1 for k in range(idx, p_idx) if not raw_lines[k].strip()
            )
            if blank_count > 0:
                val = val + ("\n" * blank_count) + p_stripped
            else:
                val = f"{val} {p_stripped}".strip()
        idx = p_idx + 1

    return val, idx


def _parse_block_mapping(
    raw_lines: list[str],
    start_idx: int,
    base_indent: int,
    *,
    strict: bool = True,
) -> tuple[dict[str, Any], int]:
    """Parse an indented YAML block mapping starting at `start_idx` with `base_indent`."""
    mapping: dict[str, Any] = {}
    idx = start_idx
    n = len(raw_lines)

    while idx < n:
        nxt = _next_nonempty_line(raw_lines, idx)
        if nxt is None:
            idx = n
            break
        line_idx, indent, stripped = nxt
        if indent < base_indent:
            idx = line_idx
            break
        if indent > base_indent:
            if strict:
                raise OKFParseError(
                    f"Unexpected indentation in YAML mapping at line {line_idx + 1}"
                )
            idx = line_idx + 1
            continue

        if stripped == "-" or stripped.startswith("- "):
            if strict:
                raise OKFParseError(
                    f"Expected YAML mapping key:value, got sequence item at line {line_idx + 1}"
                )
            idx = line_idx + 1
            continue

        # Complex mapping key `? key\n: value`
        if stripped == "?" or stripped.startswith("? "):
            k = _parse_key_token(stripped[1:].strip(), strict=strict)
            after_q = _next_nonempty_line(raw_lines, line_idx + 1)
            if (
                after_q is not None
                and after_q[1] == base_indent
                and (after_q[2] == ":" or after_q[2].startswith(": "))
            ):
                v_str = after_q[2][1:].strip()
                val, idx = _resolve_mapping_value(
                    raw_lines, after_q[0] + 1, base_indent, v_str, strict=strict
                )
                mapping[k] = val
                continue
            mapping[k] = None
            idx = line_idx + 1
            continue

        colon_pos = _find_top_level_colon(stripped)
        if colon_pos < 0:
            if strict:
                raise OKFParseError(
                    f"Missing ':' in YAML mapping entry at line {line_idx + 1}: {stripped!r}"
                )
            idx = line_idx + 1
            continue

        k = _parse_key_token(stripped[:colon_pos], strict=strict)
        v_str = stripped[colon_pos + 1 :].strip()
        val, idx = _resolve_mapping_value(
            raw_lines, line_idx + 1, base_indent, v_str, strict=strict
        )
        mapping[k] = val

    return mapping, idx


def _stdlib_parse_yaml(yaml_text: str, *, strict: bool = True) -> dict[str, Any]:
    """Pure-Python stdlib parser for OKF v0.2 YAML frontmatter with PyYAML parity."""
    raw_lines = yaml_text.splitlines()
    first = _next_nonempty_line(raw_lines, 0)
    if first is None:
        return {}

    first_idx, first_indent, first_stripped = first
    if first_stripped.startswith("{"):
        flow_str, next_idx = _accumulate_multiline_flow(
            raw_lines, first_stripped, first_idx + 1, strict=strict
        )
        rem = _next_nonempty_line(raw_lines, next_idx)
        if rem is not None and strict:
            raise OKFParseError(
                f"Trailing content after top-level flow mapping at line {rem[0] + 1}"
            )
        parsed = _parse_scalar_or_flow(flow_str, strict=strict)
        if not isinstance(parsed, dict):
            if strict:
                raise OKFParseError("Top-level YAML frontmatter must be a mapping")
            return {}
        return parsed

    if (
        first_stripped.startswith("[")
        or first_stripped == "-"
        or first_stripped.startswith("- ")
    ):
        if strict:
            raise OKFParseError(
                "Top-level YAML frontmatter must be a mapping, not a sequence"
            )
        return {}

    mapping, _ = _parse_block_mapping(
        raw_lines, first_idx, first_indent, strict=strict
    )
    return mapping


def parse_frontmatter(
    yaml_text: str,
    *,
    strict: bool = True,
    use_pyyaml: bool = True,
) -> dict[str, Any]:
    """Parse YAML frontmatter text into a Python dictionary.

    Enforces `MAX_FRONTMATTER_BYTES` (16 KiB) and rejects YAML `&` anchors, `*` aliases,
    and `<<:` merge keys outside quoted strings. Uses PyYAML with YAML 1.2 Core Schema
    normalization when available, and falls back to the pure-stdlib OKF YAML parser when
    `yaml is None` or `use_pyyaml=False`.
    """
    if not isinstance(yaml_text, str):
        if strict:
            raise OKFParseError("Frontmatter YAML input must be a string")
        return {}

    bom = "\ufeff" if yaml_text.startswith("\ufeff") else ""
    text = yaml_text[len(bom) :]

    # If caller passed a fenced frontmatter block or full document `---\n...\n---`, unwrap the YAML body
    if text.startswith("---"):
        m = _FRONTMATTER_RE.match(text)
        if m:
            text = m.group(2) if m.group(2) is not None else ""
        elif _OPENING_FENCE_ONLY_RE.match(text):
            if strict:
                raise OKFParseError("Unclosed YAML frontmatter fence")
            return {}

    byte_len = len(text.encode("utf-8"))
    if byte_len > MAX_FRONTMATTER_BYTES:
        if strict:
            raise OKFParseError(
                f"YAML frontmatter size ({byte_len} bytes) exceeds 16 KiB limit ({MAX_FRONTMATTER_BYTES} bytes)"
            )
        return {}

    try:
        _check_forbidden_yaml_constructs(text, strict=True)
    except OKFParseError:
        if strict:
            raise
        return {}

    if not text.strip():
        return {}

    active_yaml = _get_yaml_module(use_pyyaml=use_pyyaml)
    if active_yaml is not None:
        try:
            loader_cls = _build_okf_safe_loader(active_yaml)
            if loader_cls is not None:
                parsed = active_yaml.load(text, Loader=loader_cls)
            else:
                parsed = active_yaml.safe_load(text)
            if parsed is None:
                if _next_nonempty_line(text.splitlines(), 0) is not None:
                    if strict:
                        raise OKFParseError(
                            "Top-level YAML frontmatter must be a mapping, got null"
                        )
                return {}
            if not isinstance(parsed, dict):
                if strict:
                    raise OKFParseError(
                        f"Top-level YAML frontmatter must be a mapping, got {type(parsed).__name__}"
                    )
                return {}
            normalized = _normalize_parsed_obj(parsed)
            return normalized if isinstance(normalized, dict) else {}
        except OKFParseError:
            if strict:
                raise
            return {}
        except Exception:
            # When PyYAML's YAML 1.1 scanner rejects valid YAML 1.2 constructs (e.g. `?` inside a
            # flow plain scalar URL) after `_check_forbidden_yaml_constructs` passed, fall through
            # to `_stdlib_parse_yaml(text, strict=strict)` so both modes agree 100% on validity.
            pass

    try:
        return _stdlib_parse_yaml(text, strict=strict)
    except OKFParseError:
        if strict:
            raise
        try:
            return _stdlib_parse_yaml(text, strict=False)
        except BaseException:
            return {}
    except RecursionError as exc:
        if strict:
            raise OKFParseError(
                f"YAML frontmatter exceeds maximum nesting depth ({MAX_YAML_NESTING_DEPTH})"
            ) from exc
        return {}


def parse_okf_document(
    content: str,
    *,
    strict: bool = False,
    use_pyyaml: bool = True,
) -> dict[str, Any]:
    """Extract and parse YAML frontmatter and Markdown body from an OKF document."""
    errors: list[str] = []
    if _has_unclosed_frontmatter_fence(content):
        msg = "Unclosed YAML frontmatter fence (missing closing '---')"
        if strict:
            raise OKFParseError(msg)
        return {
            "has_frontmatter": False,
            "raw_frontmatter": "",
            "yaml_text": None,
            "frontmatter": {},
            "body": content,
            "errors": [msg],
        }

    fm_prefix, yaml_text, body = split_frontmatter(content)
    if yaml_text is None:
        if strict:
            raise OKFParseError("Document is missing YAML frontmatter block")
        return {
            "has_frontmatter": False,
            "raw_frontmatter": "",
            "yaml_text": None,
            "frontmatter": {},
            "body": content,
            "errors": ["Document is missing YAML frontmatter block"],
        }

    try:
        fm = parse_frontmatter(yaml_text, strict=True, use_pyyaml=use_pyyaml)
    except OKFParseError as exc:
        if strict:
            raise
        errors.append(str(exc))
        fm = {}

    return {
        "has_frontmatter": len(errors) == 0,
        "raw_frontmatter": fm_prefix,
        "yaml_text": yaml_text,
        "frontmatter": fm,
        "body": body,
        "errors": errors,
    }


def _matches_top_level_key(line: str, key: str) -> int:
    """If `line` is a top-level mapping entry for `key`, return the colon index; else `-1`."""
    if not line or line.startswith((" ", "\t", "-")):
        return -1
    head = line[: len(key) + 48]
    if key not in head and "\\" not in head:
        return -1
    cleaned = _strip_inline_comment(line)
    colon_idx = _find_top_level_colon(cleaned)
    if colon_idx <= 0:
        return -1
    raw_key_part = _strip_yaml_node_properties(cleaned[:colon_idx])
    parsed_key = _parse_key_token(raw_key_part, strict=False)
    return colon_idx if parsed_key == key else -1


def _strip_yaml_node_properties(s: str) -> str:
    """Strip leading `&anchor` and `!tag` YAML node properties from a scalar or flow token."""
    out = s.strip()
    while out:
        m = re.match(
            r"^(?:&[A-Za-z0-9_-]+|![^\s,\[\]\{\}]*)[ \t]*(.*)$",
            out,
            flags=re.DOTALL,
        )
        if not m:
            break
        out = m.group(1).strip()
    return out


def _clean_fallback_token(tok: str) -> str:
    """Strip node properties and unquote/unescape a single fallback token."""
    t = _strip_yaml_node_properties(tok)
    if not t:
        return ""
    while t.startswith("[") and t.endswith("]"):
        t = _strip_yaml_node_properties(t[1:-1].strip())
    if t.startswith("[") or t.endswith("]"):
        t = _strip_yaml_node_properties(t.strip("[] \t\r\n"))
    if not t:
        return ""
    if t.startswith('"'):
        inner = t[1:-1] if (len(t) >= 2 and t.endswith('"')) else t[1:]
        return _unescape_double_quoted(inner).strip()
    if t.startswith("'"):
        inner = t[1:-1] if (len(t) >= 2 and t.endswith("'")) else t[1:]
        return inner.replace("''", "'").strip()
    return t.strip("\"'").strip()


def _truncate_at_flow_delimiter(s: str) -> str:
    """Return prefix of `s` up to the first unquoted top-level `,`, `]`, or `}`."""
    in_quote: str | None = None
    escaped = False
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        ch = s[i]
        if in_quote == '"':
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = None
            i += 1
            continue
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and s[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch in ("[", "{"):
            depth += 1
        elif ch in ("]", "}"):
            if depth == 0:
                return s[:i].strip()
            depth -= 1
        elif ch == "," and depth == 0:
            return s[:i].strip()
        i += 1
    return s.strip()


_ANCHOR_DEF_RE = re.compile(
    r"(?:^|[\s:\[,\{])(&([A-Za-z0-9_-]+)(?![A-Za-z0-9_-]))[ \t]*"
)
_DEEP_BRACKET_RE = re.compile(r"(?:\[\s*){65}|(?:\{\s*){65}")


def _dedent_ignoring_comments(text: str) -> str:
    """Dedent `text` based on common leading spaces of non-empty, non-comment lines."""
    stripped_leading = text.lstrip("\r\n")
    if not stripped_leading:
        return ""
    # Fast check: if the first line is not a comment and has 0 indentation, no dedent needed
    if not stripped_leading.startswith((" ", "\t", "#")):
        return stripped_leading.rstrip("\r\n")
    lines = stripped_leading.rstrip("\r\n").splitlines()
    min_indent: int | None = None
    for ln in lines:
        s = ln.lstrip(" \t")
        if not s or s.startswith("#"):
            continue
        ind = len(ln) - len(s)
        if ind == 0:
            return "\n".join(lines)
        if min_indent is None or ind < min_indent:
            min_indent = ind
    if not min_indent:
        return "\n".join(lines)
    out_lines: list[str] = []
    for ln in lines:
        s = ln.lstrip(" \t")
        if not s:
            out_lines.append("")
        elif len(ln) - len(s) >= min_indent:
            out_lines.append(ln[min_indent:])
        else:
            out_lines.append(s)
    return "\n".join(out_lines)


class _AnchorResolver:
    """Single-pass indexed, memoized YAML anchor resolver for fail-closed egress extraction."""

    def __init__(self, fm_text: str) -> None:
        self.fm_text = fm_text
        self.lines: list[str] = []
        self.defs: dict[str, list[tuple[int, int, str]]] | None = None
        self.memo: dict[tuple[str, str | None], list[str]] = {}
        self.in_progress: set[tuple[str, str | None]] = set()
        self.warmed_keys: set[str | None] = set()

    def _ensure_index(self) -> None:
        if self.defs is not None:
            return
        self.lines = self.fm_text.splitlines()
        self.defs = {}
        for idx, raw_line in enumerate(self.lines):
            if "&" not in raw_line:
                continue
            line_no_comment = _strip_inline_comment(raw_line)
            if "&" not in line_no_comment:
                continue
            for m in _ANCHOR_DEF_RE.finditer(line_no_comment):
                anc = m.group(2)
                rest = _strip_yaml_node_properties(line_no_comment[m.end() :].strip())
                self.defs.setdefault(anc, []).append((idx, m.start(1), rest))

    def resolve(self, anchor_name: str, key: str | None = None) -> list[str]:
        self._ensure_index()
        assert self.defs is not None
        if len(self.defs) > 8 and key not in self.warmed_keys:
            self.warmed_keys.add(key)
            for anc in self.defs:
                self._resolve_single(anc, key, depth=46)
            for anc in reversed(list(self.defs)):
                self._resolve_single(anc, key, depth=46)
        return self._resolve_single(anchor_name, key, depth=0)

    def _resolve_single(
        self, anchor_name: str, key: str | None, depth: int = 0
    ) -> list[str]:
        cache_key = (anchor_name, key)
        if cache_key in self.memo:
            return self.memo[cache_key]
        if cache_key in self.in_progress or depth > 48:
            return []
        assert self.defs is not None
        entries = self.defs.get(anchor_name)
        if not entries:
            self.memo[cache_key] = []
            return []

        self.in_progress.add(cache_key)
        results: list[str] = []
        seen_res: set[str] = set()
        seen_alias_refs: set[str] = set()
        clipped_by_depth = [False]
        lines = self.lines

        def _add_or_resolve(tok_str: str) -> None:
            cleaned = _clean_fallback_token(_strip_inline_comment(tok_str).strip())
            if not cleaned:
                return
            m_alias = re.match(r"^\*([A-Za-z0-9_-]+)$", cleaned)
            if m_alias:
                ref_name = m_alias.group(1)
                if ref_name in seen_alias_refs:
                    return
                seen_alias_refs.add(ref_name)
                ref_cache = (ref_name, key)
                if ref_cache not in self.memo and depth + 1 > 48:
                    clipped_by_depth[0] = True
                    return
                sub_vals = self._resolve_single(ref_name, key, depth=depth + 1)
                if not sub_vals and ref_cache not in self.memo:
                    clipped_by_depth[0] = True
                for sub in sub_vals:
                    if sub not in seen_res:
                        seen_res.add(sub)
                        results.append(sub)
            elif cleaned not in seen_res:
                seen_res.add(cleaned)
                results.append(cleaned)

        for line_idx, amp_col, rest in entries:
            raw_line = lines[line_idx]
            line_no_comment = _strip_inline_comment(raw_line)
            prefix = line_no_comment[:amp_col]
            line_indent = len(raw_line) - len(raw_line.lstrip(" \t"))

            # Case 1: `&anchor` at end of line -> indented block sequence or block mapping
            if not rest:
                block_lines: list[str] = []
                j = line_idx + 1
                while j < len(lines):
                    j_raw = lines[j]
                    j_strip = j_raw.strip()
                    if not j_strip or j_strip.startswith("#"):
                        block_lines.append(j_raw)
                        j += 1
                        continue
                    j_indent = len(j_raw) - len(j_raw.lstrip(" \t"))
                    if j_indent > line_indent or (
                        j_indent == line_indent
                        and (j_strip == "-" or j_strip.startswith("- "))
                    ):
                        block_lines.append(j_raw)
                        j += 1
                        continue
                    break
                if block_lines:
                    for bl in block_lines:
                        b_clean = _strip_inline_comment(bl).strip()
                        if key and b_clean.startswith("<<:"):
                            for m_ref in re.findall(r"\*([A-Za-z0-9_-]+)", b_clean[3:]):
                                _add_or_resolve(f"*{m_ref}")
                        elif b_clean.startswith("- "):
                            _add_or_resolve(b_clean[2:])
                    if key:
                        dedented_block = _dedent_ignoring_comments("\n".join(block_lines))
                        for sv in _extract_key_block_fallback(
                            dedented_block, key, use_pyyaml=False, resolver=self
                        ):
                            if isinstance(sv, list):
                                for item in sv:
                                    _add_or_resolve(str(item))
                            elif sv is not None:
                                _add_or_resolve(str(sv))
                continue

            # Case 2: `&anchor [...]` or `&anchor {...}` (single-line or multi-line flow collection)
            if rest.startswith(("[", "{")):
                flow_parts = [rest]
                j = line_idx + 1
                while j < len(lines):
                    try:
                        if _flow_bracket_balance("\n".join(flow_parts)) <= 0:
                            break
                    except OKFParseError:
                        break
                    flow_parts.append(_strip_inline_comment(lines[j]).strip())
                    j += 1
                flow_str = " ".join(flow_parts).strip()
                if flow_str.startswith("["):
                    inner = flow_str[1:]
                    if inner.endswith("]"):
                        inner = inner[:-1]
                    for item in _split_flow_items(inner):
                        _add_or_resolve(item)
                elif flow_str.startswith("{"):
                    inner = flow_str[1:]
                    if inner.endswith("}"):
                        inner = inner[:-1]
                    for entry in _split_flow_items(inner):
                        c_idx = _find_top_level_colon(entry)
                        if c_idx > 0:
                            e_key = _parse_key_token(entry[:c_idx], strict=False)
                            e_val = entry[c_idx + 1 :].strip()
                            if key is None or e_key == key:
                                if e_val.startswith("[") and e_val.endswith("]"):
                                    for sub_it in _split_flow_items(e_val[1:-1]):
                                        _add_or_resolve(sub_it)
                                else:
                                    _add_or_resolve(e_val)
                            elif key is not None and e_key == "<<":
                                for m_ref in re.findall(r"\*([A-Za-z0-9_-]+)", e_val):
                                    _add_or_resolve(f"*{m_ref}")
                continue

            # Case 3: `&anchor <scalar>` on the same line
            try:
                in_flow = _flow_bracket_balance(prefix) > 0
            except OKFParseError:
                in_flow = "[" in prefix or "{" in prefix
            if in_flow:
                rest = _truncate_at_flow_delimiter(rest)
            _add_or_resolve(rest)

        self.in_progress.discard(cache_key)
        if not clipped_by_depth[0]:
            self.memo[cache_key] = results
        return results


def _extract_key_block_fallback(
    fm_text: str,
    key: str,
    *,
    use_pyyaml: bool = True,
    resolver: _AnchorResolver | None = None,
) -> list[Any]:
    """Isolate all top-level `key:` blocks even when `fm_text` has YAML errors or node properties."""
    lines = fm_text.splitlines()
    collected_values: list[Any] = []
    for i, line in enumerate(lines):
        # Support complex key `? <key>\n: <value>`
        if line.startswith("?"):
            q_key = _parse_key_token(
                _strip_yaml_node_properties(_strip_inline_comment(line[1:]).strip()),
                strict=False,
            )
            if q_key == key and i + 1 < len(lines):
                nxt_line = lines[i + 1].lstrip()
                if nxt_line.startswith(":"):
                    line = f"{key}:{nxt_line[1:]}"
                    i = i + 1

        colon_idx = _matches_top_level_key(line, key)
        if colon_idx < 0:
            continue
        cleaned_first = _strip_inline_comment(line)
        after_colon_raw = cleaned_first[colon_idx + 1 :].strip()
        after_colon = _strip_yaml_node_properties(after_colon_raw)
        normalized_first = f"{key}: {after_colon}" if after_colon else f"{key}:"
        snippet_lines = [normalized_first]

        # Check if value is a YAML alias `*anchor_name`
        if after_colon.startswith("*"):
            anchor_ref = after_colon[1:].split()[0].strip(",]}")
            if anchor_ref:
                if resolver is None:
                    resolver = _AnchorResolver(fm_text)
                resolved = resolver.resolve(
                    anchor_ref, key=(key if key != "<<" else None)
                )
                if not resolved and key != "<<":
                    resolved = resolver.resolve(anchor_ref, key=None)
                if resolved:
                    collected_values.append(resolved)
                continue

        j = i + 1
        while j < len(lines):
            j_line = lines[j]
            j_strip = j_line.strip()
            if j_strip.startswith("#"):
                j += 1
                continue
            if not j_strip:
                if snippet_lines and snippet_lines[-1].strip():
                    snippet_lines.append("")
                j += 1
                continue
            if (
                j_line.startswith((" ", "\t"))
                or j_strip == "-"
                or j_strip.startswith("- ")
                or j_strip.startswith("]")
            ):
                snippet_lines.append(j_line)
                j += 1
                continue
            # Stop if `j_line` is a new top-level mapping key (`other_key: ...`)
            j_cleaned = _strip_inline_comment(j_line)
            if not j_line.startswith((" ", "\t", "-")) and _find_top_level_colon(j_cleaned) > 0:
                break
            if after_colon.startswith("["):
                try:
                    if _flow_bracket_balance(" ".join(snippet_lines)) > 0:
                        snippet_lines.append(j_line)
                        j += 1
                        continue
                except OKFParseError:
                    pass
            break

        isolated = "\n".join(snippet_lines)
        if (
            len(isolated) <= MAX_FRONTMATTER_BYTES
            and not re.search(r"(?:^|[\s,\[\{:])\*[A-Za-z0-9_-]+", isolated)
            and not _DEEP_BRACKET_RE.search(isolated)
        ):
            active_yaml = _get_yaml_module(use_pyyaml=use_pyyaml)
            base_loader = (
                getattr(active_yaml, "BaseLoader", None)
                if active_yaml is not None
                else None
            )
            if active_yaml is not None and base_loader is not None:
                try:
                    raw_iso = active_yaml.load(isolated, Loader=base_loader)
                    if (
                        isinstance(raw_iso, dict)
                        and key in raw_iso
                        and raw_iso[key] is not None
                    ):
                        collected_values.append(raw_iso[key])
                        continue
                except Exception:
                    pass
            if "&" not in isolated:
                parsed = parse_frontmatter(
                    isolated, strict=False, use_pyyaml=use_pyyaml
                )
                if (
                    isinstance(parsed, dict)
                    and key in parsed
                    and parsed[key] is not None
                ):
                    collected_values.append(parsed[key])
                    continue

        if after_colon.startswith("["):
            flow_joined = " ".join(
                [after_colon]
                + [_strip_inline_comment(sl).strip() for sl in snippet_lines[1:]]
            ).strip()
            inner = flow_joined[1:]
            if inner.endswith("]"):
                inner = inner[:-1]
            if inner.startswith("[") and "," not in inner:
                cleaned_nested = _clean_fallback_token(inner)
                if cleaned_nested:
                    collected_values.append([cleaned_nested])
                continue
            toks: list[str] = []
            seen_toks: set[str] = set()
            for tok in _split_flow_items(inner):
                t_strip = _strip_yaml_node_properties(tok)
                sub_toks = (
                    _split_flow_items(t_strip[1:-1])
                    if (t_strip.startswith("[") and t_strip.endswith("]"))
                    else [tok]
                )
                for st_tok in sub_toks:
                    ct = _clean_fallback_token(st_tok)
                    if ct and ct not in seen_toks:
                        seen_toks.add(ct)
                        toks.append(ct)
                        if len(seen_toks) >= 8192:
                            break
                if len(seen_toks) >= 8192:
                    break
            if toks:
                collected_values.append(toks)
                continue

        if len(isolated) <= MAX_FRONTMATTER_BYTES and not _DEEP_BRACKET_RE.search(
            isolated
        ):
            parsed = parse_frontmatter(
                isolated, strict=False, use_pyyaml=use_pyyaml
            )
            if isinstance(parsed, dict) and key in parsed and parsed[key] is not None:
                collected_values.append(parsed[key])
                continue

        items: list[str] = []
        s_idx = 1
        while s_idx < len(snippet_lines):
            sl = snippet_lines[s_idx]
            st = _strip_inline_comment(sl).strip()
            if st.startswith("- "):
                item_body = st[2:].strip()
                if _BLOCK_SCALAR_HEADER_RE.match(item_body):
                    item_indent = len(sl) - len(sl.lstrip(" \t"))
                    b_lines: list[str] = []
                    s_idx += 1
                    while s_idx < len(snippet_lines):
                        nxt_sl = snippet_lines[s_idx]
                        nxt_st = nxt_sl.strip()
                        if not nxt_st:
                            s_idx += 1
                            continue
                        nxt_ind = len(nxt_sl) - len(nxt_sl.lstrip(" \t"))
                        if nxt_ind <= item_indent or nxt_st.startswith("- "):
                            break
                        b_lines.append(nxt_st)
                        s_idx += 1
                    if b_lines:
                        items.append(" ".join(b_lines))
                    continue
                cleaned_item = _clean_fallback_token(item_body)
                if cleaned_item:
                    items.append(cleaned_item)
            s_idx += 1
        if items:
            collected_values.append(items)
            continue
        if after_colon and not _BLOCK_SCALAR_HEADER_RE.match(after_colon):
            cleaned_after = _clean_fallback_token(after_colon)
            if cleaned_after:
                collected_values.append(cleaned_after)
    return collected_values


def extract_string_list(
    fm_text: str,
    key: str,
    *,
    use_pyyaml: bool = True,
) -> list[str]:
    """Extract a list of string values for `key` (e.g. `aliases` or `tags`) from YAML frontmatter.

    Supports scalar string, block list, single-line flow list (`["Acme, Inc", FinCorp]`),
    multi-line flow list (`aliases: [\\n  NWB,\\n  Initech\\n]`), YAML 1.1 boolean-like
    strings (`[ON, Off, Yes, No]`), and ignores `null`/`~`/`"-"`.
    Fault-tolerant: if another key in the frontmatter has malformed YAML, tab indentation,
    or anchors, isolates the target `key:` block so security egress checks never fail open.
    """
    cleaned_fm = fm_text.lstrip("\ufeff")
    if cleaned_fm.lstrip().startswith("---"):
        _raw, fm_opt, _body = split_frontmatter(cleaned_fm.lstrip())
        if fm_opt is not None:
            cleaned_fm = fm_opt
        else:
            parts = cleaned_fm.lstrip().split("---", 2)
            if len(parts) >= 2:
                cleaned_fm = parts[1]
    stripped_fm = _dedent_ignoring_comments(cleaned_fm)

    ignored_tokens = {"null", "~", "None", "[", "]", "-"}
    results: list[str] = []
    seen_results: set[str] = set()
    seen_containers: set[int] = set()
    seen_alias_tokens: set[str] = set()
    unique_budget = [8192]
    step_budget = [65536]
    resolver = _AnchorResolver(stripped_fm)

    def _collect(root_val: Any) -> None:
        stack: list[Any] = [root_val]
        while stack and unique_budget[0] > 0 and step_budget[0] > 0:
            val = stack.pop()
            if val is None:
                continue
            step_budget[0] -= 1
            if isinstance(val, bool):
                s_bool = "true" if val else "false"
                if s_bool not in seen_results:
                    seen_results.add(s_bool)
                    results.append(s_bool)
                    unique_budget[0] -= 1
                continue
            if isinstance(val, (list, tuple, set)):
                cid = id(val)
                if cid in seen_containers:
                    continue
                seen_containers.add(cid)
                seq_items = list(val)
                for item in reversed(seq_items[:16384]):
                    stack.append(item)
                continue
            if isinstance(val, dict):
                cid = id(val)
                if cid in seen_containers:
                    continue
                seen_containers.add(cid)
                dict_vals = list(val.values())
                for dv in reversed(dict_vals[:16384]):
                    stack.append(dv)
                continue
            v = str(val).strip()
            if not v or v in ignored_tokens:
                continue
            m_alias = re.match(r"^\*([A-Za-z0-9_-]+)(?:\s+#.*)?$", v)
            if m_alias:
                ref_name = m_alias.group(1)
                if ref_name in seen_alias_tokens:
                    continue
                seen_alias_tokens.add(ref_name)
                resolved = resolver.resolve(ref_name, key=None)
                if resolved:
                    for r_item in reversed(resolved):
                        stack.append(r_item)
                continue
            if v not in seen_results:
                seen_results.add(v)
                results.append(v)
                unique_budget[0] -= 1

    # Fast path for JSON / flow-mapping root frontmatter `{...}`
    if stripped_fm.startswith("{"):
        try:
            j_data = json.loads(stripped_fm)
            if isinstance(j_data, dict) and key in j_data:
                _collect(j_data[key])
        except Exception:
            if len(stripped_fm) <= 256 * 1024 and not _DEEP_BRACKET_RE.search(
                stripped_fm
            ):
                try:
                    f_data = _stdlib_parse_yaml(stripped_fm, strict=False)
                    if isinstance(f_data, dict) and key in f_data:
                        _collect(f_data[key])
                except Exception:
                    pass

    can_run_base_loader = (
        len(stripped_fm) <= 256 * 1024
        and not _DEEP_BRACKET_RE.search(stripped_fm)
    )

    active_yaml = _get_yaml_module(use_pyyaml=use_pyyaml)
    if active_yaml is not None and can_run_base_loader:
        base_loader = getattr(active_yaml, "BaseLoader", None)
        if base_loader is not None:
            try:
                raw_loaded = active_yaml.load(stripped_fm, Loader=base_loader)
                if isinstance(raw_loaded, dict):
                    if key in raw_loaded:
                        _collect(raw_loaded[key])
                    # Follow `<<` merge chains iteratively up to 64 hops
                    merge_queue: list[Any] = [raw_loaded.get("<<")]
                    seen_merges: set[int] = set()
                    hops = 0
                    while merge_queue and hops < 64:
                        m_curr = merge_queue.pop(0)
                        if m_curr is None:
                            continue
                        hops += 1
                        mid = id(m_curr)
                        if mid in seen_merges:
                            continue
                        seen_merges.add(mid)
                        if isinstance(m_curr, dict):
                            if key in m_curr:
                                _collect(m_curr[key])
                            if "<<" in m_curr:
                                merge_queue.append(m_curr["<<"])
                        elif isinstance(m_curr, list):
                            merge_queue.extend(m_curr)
            except Exception:
                pass

    if len(stripped_fm) <= MAX_FRONTMATTER_BYTES:
        data = parse_frontmatter(stripped_fm, strict=False, use_pyyaml=use_pyyaml)
        raw_primary = data.get(key) if isinstance(data, dict) else None
        _collect(raw_primary)

    fallback_blocks = _extract_key_block_fallback(
        stripped_fm, key, use_pyyaml=use_pyyaml, resolver=resolver
    )
    for fb_val in fallback_blocks:
        _collect(fb_val)

    # Check YAML `<<:` merge keys when target `key` is provided via merged anchor mapping
    if key != "<<" and "<<" in stripped_fm:
        for line in stripped_fm.splitlines():
            c_idx = _matches_top_level_key(line, "<<")
            if c_idx > 0:
                after_merge = _strip_inline_comment(line)[c_idx + 1 :].strip()
                for m_ref in re.findall(r"\*([A-Za-z0-9_-]+)", after_merge):
                    for merged_item in resolver.resolve(m_ref, key=key):
                        _collect(merged_item)

    return results


def is_valid_actor(val: Any) -> bool:
    """Validate an OKF v0.3 §7 actor (`<producer>/<version>` or `<scheme>:<id>`)."""
    if not isinstance(val, str):
        return False
    s = val.strip()
    if not s or not _ACTOR_RE.match(s):
        return False
    if ":" in s and not s.split(":", 1)[1].strip():
        return False
    return True


def _parse_okf_version_tuple(version_val: Any) -> tuple[int, ...] | None:
    """Parse an `okf_version` string like `'0.2'` or `'0.3'` into an integer tuple."""
    if version_val is None:
        return None
    parts = re.findall(r"\d+", str(version_val).strip())
    if not parts:
        return None
    return tuple(int(p) for p in parts)


def normalize_verified_list(verified_val: Any) -> list[dict[str, Any]]:
    """Normalize frontmatter `verified` value per OKF v0.3 §5.2 & §11.2.

    A bare mapping `verified: { by: ..., at: ... }` is treated as a 1-element list.
    """
    if verified_val is None:
        return []
    if isinstance(verified_val, dict):
        return [dict(verified_val)]
    if isinstance(verified_val, list):
        return [dict(item) for item in verified_val if isinstance(item, dict)]
    return []


def _extract_generated_at(frontmatter: dict[str, Any]) -> datetime | None:
    """Extract parseable `generated.at` UTC datetime if present in frontmatter."""
    generated = frontmatter.get("generated")
    if not isinstance(generated, dict):
        return None
    gen_at_raw = generated.get("at")
    if gen_at_raw is None or (isinstance(gen_at_raw, str) and not gen_at_raw.strip()):
        return None
    return parse_iso_datetime(gen_at_raw, require_offset=True)


def has_stale_verifications(frontmatter: dict[str, Any]) -> bool:
    """Return True if `verified` events exist but every dated event is older than `generated.at` (OKF v0.3 §5.3 / I204)."""
    if not isinstance(frontmatter, dict):
        return False
    gen_at = _extract_generated_at(frontmatter)
    if gen_at is None:
        return False
    entries = normalize_verified_list(frontmatter.get("verified"))
    dated_times: list[datetime] = []
    for entry in entries:
        by_raw = entry.get("by")
        if not isinstance(by_raw, str) or not by_raw.strip():
            continue
        ver_at = parse_iso_datetime(entry.get("at"), require_offset=True)
        if ver_at is not None:
            dated_times.append(ver_at)
    return bool(dated_times) and all(t < gen_at for t in dated_times)


def derive_trust_tier(frontmatter: dict[str, Any]) -> str:
    """Derive OKF v0.3 §5.3 trust tier strictly from current `verified` events.

    An event is current when `verified[].at >= generated.at`, or when `generated.at`
    is absent (preserving full OKF v0.2 backward compatibility).

    Returns:
      - `"human-reviewed"` if any current valid entry has `by` starting with `"human:"` and a non-empty ID.
      - `"machine-confirmed"` if current valid entries contain only non-`human:` actors (e.g. `process:`, `team:`, `<tool>/<ver>`).
      - `"unverified"` if no current valid `verified` entries exist.
    """
    if not isinstance(frontmatter, dict):
        return "unverified"
    entries = normalize_verified_list(frontmatter.get("verified"))
    gen_at = _extract_generated_at(frontmatter)
    has_machine = False
    for entry in entries:
        by_raw = entry.get("by")
        if not isinstance(by_raw, str):
            continue
        by_val = by_raw.strip()
        if not by_val:
            continue
        if gen_at is not None:
            ver_at = parse_iso_datetime(entry.get("at"), require_offset=True)
            if ver_at is None or ver_at < gen_at:
                continue
        if by_val.startswith("human:"):
            human_id = by_val[len("human:") :].strip()
            if human_id:
                return "human-reviewed"
        else:
            has_machine = True
    return "machine-confirmed" if has_machine else "unverified"


def parse_iso_datetime(
    val: Any, *, require_offset: bool = False
) -> datetime | None:
    """Parse an RFC 3339 date (`YYYY-MM-DD`, 00:00:00Z UTC) or timestamp (`...Z` / `...+HH:MM`) into UTC `datetime`.

    When `require_offset=True` (OKF v0.3 §5 strict mode), naive date-times without an
    explicit UTC offset return `None`, while date-only `YYYY-MM-DD` stays valid as UTC midnight.
    """
    if val is None:
        return None
    if isinstance(val, datetime):
        if require_offset and val.tzinfo is None:
            return None
        try:
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            return None
    if isinstance(val, date):
        return datetime(val.year, val.month, val.day, 0, 0, 0, tzinfo=timezone.utc)
    if not isinstance(val, str):
        return None

    if any(
        ord(c) < 32 or ord(c) == 0x7F or c in ("\x85", "\u2028", "\u2029")
        for c in val
    ):
        return None

    s = val.strip()
    if not s:
        return None

    m_date = _ISO_DATE_ONLY_RE.match(s)
    if m_date:
        try:
            return datetime(
                int(m_date.group(1)),
                int(m_date.group(2)),
                int(m_date.group(3)),
                0,
                0,
                0,
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None

    if require_offset and not _ISO_DATETIME_WITH_OFFSET_RE.match(s):
        return None

    norm = s
    if norm.endswith(("Z", "z")):
        norm = norm[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            if require_offset:
                return None
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def is_stale(frontmatter: dict[str, Any], now: datetime | None = None) -> bool:
    """Evaluate OKF v0.3 §5.5 & §11.2 staleness (`now >= stale_after`, unparseable counts as stale)."""
    if not isinstance(frontmatter, dict):
        return False
    raw_stale = frontmatter.get("stale_after")
    if raw_stale is None or (isinstance(raw_stale, str) and not raw_stale.strip()):
        return False
    stale_dt = parse_iso_datetime(raw_stale, require_offset=True)
    if stale_dt is None:
        # OKF v0.3 §5.5 & §11.2: MUST NOT treat an unparseable stale_after as fresh.
        return True

    ref_now = now if now is not None else datetime.now(timezone.utc)
    try:
        if ref_now.tzinfo is None:
            ref_now = ref_now.replace(tzinfo=timezone.utc)
        else:
            ref_now = ref_now.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return True
    return ref_now >= stale_dt


def is_current_status(frontmatter: dict[str, Any]) -> bool:
    """Return True if concept `status` is current (`stable`, `draft`, or omitted) per OKF v0.3 §5.4."""
    if not isinstance(frontmatter, dict):
        return True
    raw = frontmatter.get("status")
    if raw is None:
        return True
    if not isinstance(raw, str):
        return False
    cleaned = raw.strip()
    if not cleaned:
        return True
    return cleaned in ("stable", "draft")


def resolve_okf_path(
    bundle_root: Path,
    source_file: Path,
    target: str,
    *,
    field: bool = True,
    okf_version: str | None = None,
) -> tuple[str, Path | None]:
    """Resolve an OKF v0.3 §6 link or path field with §12.1 v0.2 bundle-root fallback.

    Returns `(kind, resolved_path)` where `kind` is one of:
      - `"external"`: URL scheme, protocol-relative URL, or path escaping `bundle_root`.
      - `"found"`: resolved inside `bundle_root` and exists on disk.
      - `"fallback"`: bare path field that resolved only from `bundle_root` under `v0.2`/unversioned fallback.
      - `"missing"`: in-bundle target does not exist on disk.
    """
    if not isinstance(target, str):
        return "missing", None
    raw = target.strip()
    if not raw or _PATH_SCHEME_RE.match(raw) or raw.startswith("//"):
        return "external", None
    clean = urllib.parse.unquote(raw.split("#", 1)[0].split("?", 1)[0])
    if not clean:
        return "found", source_file

    bundle_resolved = bundle_root.resolve()
    base = bundle_resolved if clean.startswith("/") else source_file.resolve().parent
    candidate = Path(os.path.normpath(str(base / clean.lstrip("/"))))
    try:
        candidate.relative_to(bundle_resolved)
    except ValueError:
        return "external", None
    if candidate.exists():
        return "found", candidate

    declared = _parse_okf_version_tuple(okf_version)
    allow_v02_fallback = declared is None or declared <= (0, 2)
    if field and allow_v02_fallback and not clean.startswith("/"):
        alt = Path(os.path.normpath(str(bundle_resolved / clean)))
        try:
            alt.relative_to(bundle_resolved)
        except ValueError:
            return "missing", None
        if alt.exists():
            return "fallback", alt
    return "missing", None


def _count_computation_fences(body: str) -> int:
    """Count fenced code blocks inside a `Computation` heading section (OKF v0.3 §10.3)."""
    level: int | None = None
    count = 0
    fence_ch = ""
    fence_len = 0
    in_fence = False
    for line in body.splitlines():
        m_fence = _FENCE_LINE_RE.match(line)
        if in_fence:
            if m_fence:
                marker = m_fence.group(1)
                tail = m_fence.group(2).strip()
                if marker[0] == fence_ch and len(marker) >= fence_len and not tail:
                    in_fence = False
            continue
        if m_fence:
            marker = m_fence.group(1)
            info = m_fence.group(2)
            if not (marker[0] == "`" and "`" in info):
                in_fence = True
                fence_ch = marker[0]
                fence_len = len(marker)
                if level is not None:
                    count += 1
                continue
        m_heading = _ATX_HEADING_RE.match(line)
        if m_heading:
            depth = len(m_heading.group(1))
            if level is not None and depth <= level:
                break
            if level is None and m_heading.group(2).strip().lower() == "computation":
                level = depth
    return count


def canonical_content_hash(content: str, *, use_pyyaml: bool = True) -> str:
    """Compute a deterministic SHA-256 hash over substantive frontmatter + body.

    Strips volatile timestamp fields (`updated` and `generated.at`) from frontmatter
    and normalizes CRLF to LF so writers can skip `updated:` churn when substantive
    content has not changed. Falls back to hashing normalized raw frontmatter lines
    if the frontmatter contains invalid YAML so distinct broken frontmatters never collide.
    """
    _fm_prefix, yaml_text, body = split_frontmatter(content)
    norm_body = body.replace("\r\n", "\n")
    if yaml_text is None:
        payload = "\n---\n" + norm_body
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    try:
        fm = parse_frontmatter(yaml_text, strict=True, use_pyyaml=use_pyyaml)
    except OKFParseError:
        norm_yaml = "\n".join(
            line
            for line in yaml_text.replace("\r\n", "\n").splitlines()
            if not re.match(r"^updated[ \t]*:", line)
        )
        payload = "RAW_YAML:\n" + norm_yaml + "\n---\n" + norm_body
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    clean_fm: dict[str, Any] = {}
    for k, v in fm.items():
        if k == "updated":
            continue
        if k == "generated" and isinstance(v, dict):
            clean_fm[k] = {gk: gv for gk, gv in v.items() if gk != "at"}
        else:
            clean_fm[k] = v

    fm_json = json.dumps(clean_fm, sort_keys=True, ensure_ascii=False, default=str)
    payload = fm_json + "\n---\n" + norm_body
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _strip_html_comments_linear(text: str) -> str:
    """Strip `<!-- ... -->` HTML comments in O(N) time without regex backtracking on unclosed `<!--`."""
    if "<!--" not in text:
        return text
    out: list[str] = []
    pos = 0
    n = len(text)
    while pos < n:
        start = text.find("<!--", pos)
        if start < 0:
            out.append(text[pos:])
            break
        out.append(text[pos:start])
        end = text.find("-->", start + 4)
        if end < 0:
            # No closing `-->` exists anywhere in the remainder of `text`
            out.append(text[start:])
            break
        pos = end + 3
    return "".join(out)


def _strip_fenced_code_linear(text: str) -> str:
    """Strip fenced code blocks (``` or ~~~, including blockquoted fences) in O(N) single-pass line time."""
    if "```" not in text and "~~~" not in text:
        return text
    out_lines: list[str] = []
    in_fence = False
    fence_ch = ""
    fence_len = 0

    for line in text.splitlines(keepends=True):
        m = _FENCE_LINE_RE.match(line.rstrip("\r\n"))
        if not in_fence:
            if m:
                marker = m.group(1)
                info = m.group(2)
                # In CommonMark, backtick fence info strings cannot contain backticks
                if marker[0] == "`" and "`" in info:
                    out_lines.append(line)
                    continue
                in_fence = True
                fence_ch = marker[0]
                fence_len = len(marker)
                continue
            out_lines.append(line)
        else:
            if m:
                marker = m.group(1)
                tail = m.group(2).strip()
                if marker[0] == fence_ch and len(marker) >= fence_len and not tail:
                    in_fence = False
                    fence_ch = ""
                    fence_len = 0
            continue
    return "".join(out_lines)


def _strip_inline_code_linear(text: str) -> str:
    """Strip single-line inline code spans (`...`) in O(N) time using per-length run indexing."""
    if "`" not in text:
        return text
    out_lines: list[str] = []
    for line in text.splitlines(keepends=True):
        if "`" not in line:
            out_lines.append(line)
            continue
        runs = [
            (m.start(), m.end(), m.end() - m.start())
            for m in _BACKTICK_RUN_RE.finditer(line)
        ]
        if len(runs) < 2:
            out_lines.append(line)
            continue

        by_len: dict[int, list[int]] = {}
        for idx, (_s, _e, rlen) in enumerate(runs):
            by_len.setdefault(rlen, []).append(idx)

        # Cursor into `by_len[rlen]` so finding the next matching run of length `rlen` is O(1) amortized
        cursors: dict[int, int] = {rlen: 0 for rlen in by_len}
        pieces: list[str] = []
        last_char_pos = 0
        i = 0
        n_runs = len(runs)
        while i < n_runs:
            s_i, _e_i, rlen = runs[i]
            idx_list = by_len[rlen]
            if len(idx_list) < 2:
                i += 1
                continue
            cur = cursors[rlen]
            while cur < len(idx_list) and idx_list[cur] <= i:
                cur += 1
            cursors[rlen] = cur
            if cur >= len(idx_list):
                i += 1
                continue
            match_run_idx = idx_list[cur]
            cursors[rlen] = cur + 1
            _s_j, e_j, _ = runs[match_run_idx]
            pieces.append(line[last_char_pos:s_i])
            last_char_pos = e_j
            i = match_run_idx + 1

        if last_char_pos == 0:
            out_lines.append(line)
        else:
            pieces.append(line[last_char_pos:])
            out_lines.append("".join(pieces))
    return "".join(out_lines)


def _strip_code_and_comments_from_body(body: str) -> str:
    """Strip HTML comments, fenced code blocks, and inline code spans in linear O(N) time."""
    cleaned = _strip_html_comments_linear(body)
    cleaned = _strip_fenced_code_linear(cleaned)
    cleaned = _strip_inline_code_linear(cleaned)
    return cleaned


def validate_okf_concept(
    content: str,
    *,
    is_reserved: bool = False,
    now: datetime | None = None,
    use_pyyaml: bool = True,
    bundle_root: Path | None = None,
    file_path: Path | None = None,
    okf_version: str | None = None,
) -> dict[str, Any]:
    """Validate an OKF v0.3 concept document against §4–§11 conformance rules (v0.2 compatible)."""
    if is_reserved:
        _fm_prefix, yaml_text, _body = split_frontmatter(content)
        fm = (
            parse_frontmatter(yaml_text, strict=False, use_pyyaml=use_pyyaml)
            if yaml_text is not None
            else {}
        )
        return {
            "valid": True,
            "has_frontmatter": yaml_text is not None,
            "errors": [],
            "warnings": [],
            "legacy_sources": False,
            "frontmatter": fm,
            "trust_tier": derive_trust_tier(fm),
            "is_stale": False,
            "stale_after": None,
            "missing_footnotes": [],
            "is_current_status": is_current_status(fm),
            "stale_verifications": False,
            "superseded_by": None,
            "okf_version": okf_version or SUPPORTED_OKF_VERSION,
        }

    errors: list[str] = []
    warnings: list[str] = []
    legacy_sources = False
    missing_footnotes: list[str] = []

    if _has_unclosed_frontmatter_fence(content):
        return {
            "valid": False,
            "has_frontmatter": False,
            "errors": ["Unclosed YAML frontmatter fence (missing closing '---')"],
            "warnings": [],
            "legacy_sources": False,
            "frontmatter": {},
            "trust_tier": "unverified",
            "is_stale": False,
            "stale_after": None,
            "missing_footnotes": [],
            "is_current_status": True,
            "stale_verifications": False,
            "superseded_by": None,
            "okf_version": okf_version or SUPPORTED_OKF_VERSION,
        }

    _fm_prefix, yaml_text, body = split_frontmatter(content)
    if yaml_text is None:
        return {
            "valid": False,
            "has_frontmatter": False,
            "errors": ["Missing YAML frontmatter block"],
            "warnings": [],
            "legacy_sources": False,
            "frontmatter": {},
            "trust_tier": "unverified",
            "is_stale": False,
            "stale_after": None,
            "missing_footnotes": [],
            "is_current_status": True,
            "stale_verifications": False,
            "superseded_by": None,
            "okf_version": okf_version or SUPPORTED_OKF_VERSION,
        }

    try:
        frontmatter = parse_frontmatter(
            yaml_text, strict=True, use_pyyaml=use_pyyaml
        )
    except OKFParseError as exc:
        return {
            "valid": False,
            "has_frontmatter": False,
            "errors": [str(exc)],
            "warnings": [],
            "legacy_sources": False,
            "frontmatter": {},
            "trust_tier": "unverified",
            "is_stale": False,
            "stale_after": None,
            "missing_footnotes": [],
            "is_current_status": True,
            "stale_verifications": False,
            "superseded_by": None,
            "okf_version": okf_version or SUPPORTED_OKF_VERSION,
        }

    def _check_path_field_warn(field_name: str, raw_val: Any) -> None:
        if bundle_root is None or file_path is None or not isinstance(raw_val, str):
            return
        val_s = raw_val.strip()
        if not val_s or re.search(r"\s", val_s):
            return
        if val_s.startswith("[[") and val_s.endswith("]]"):
            return
        kind, _resolved = resolve_okf_path(
            bundle_root,
            file_path,
            val_s,
            field=True,
            okf_version=okf_version,
        )
        if kind == "missing":
            warnings.append(
                f"{field_name} {val_s!r} does not resolve to a file in the bundle (OKF v0.3 §6.2)"
            )
        elif kind == "fallback":
            warnings.append(
                f"{field_name} {val_s!r} resolves only via v0.2 bundle-root fallback; prefix with '/' as '/{val_s}' (OKF v0.3 §6.2)"
            )

    # 1. Required `type` field (OKF v0.3 §4.1 & §11)
    concept_type = frontmatter.get("type")
    if not isinstance(concept_type, str) or not concept_type.strip():
        errors.append(
            "Missing or invalid required frontmatter field 'type' (must be a non-empty string)"
        )
        concept_type_str = ""
    else:
        concept_type_str = concept_type.strip()

    # 1b. `tags` scalar warning (§4.1, §11.2)
    raw_tags = frontmatter.get("tags")
    if isinstance(raw_tags, str) and raw_tags.strip():
        if "," in raw_tags:
            warnings.append(
                f"Write 'tags' as a YAML list (OKF v0.3 §4.1/§11.2); scalar {raw_tags!r} is read as a single tag"
            )
    elif raw_tags is not None and not isinstance(raw_tags, list):
        warnings.append("Write 'tags' as a YAML list of strings (OKF v0.3 §4.1)")

    # 1c. `status` & `superseded_by` lifecycle (§5.4)
    raw_status = frontmatter.get("status")
    status_str = raw_status.strip() if isinstance(raw_status, str) else ""
    if raw_status is not None and (not isinstance(raw_status, str) or (status_str and status_str not in OKF_VALID_STATUSES)):
        warnings.append(
            f"Unknown 'status' value {raw_status!r} (expected draft, stable, or deprecated; treated as not current per OKF v0.3 §5.4)"
        )
    superseded_by_raw = frontmatter.get("superseded_by")
    superseded_by_str: str | None = None
    if isinstance(superseded_by_raw, str) and superseded_by_raw.strip():
        superseded_by_str = superseded_by_raw.strip()
        if status_str != "deprecated":
            warnings.append(
                "'superseded_by' has a meaning only with 'status: deprecated' (OKF v0.3 §5.4)"
            )
        _check_path_field_warn("superseded_by", superseded_by_str)

    if frontmatter.get("resource"):
        _check_path_field_warn("resource", frontmatter.get("resource"))

    # 2. `sources` and `usage_window` validation (OKF v0.3 §5.1 & §11.2 + 1.x Legacy String Profile)
    shared_window = frontmatter.get("usage_window")
    if shared_window is not None and shared_window != "" and shared_window != []:
        if (
            not isinstance(shared_window, dict)
            or parse_iso_datetime(shared_window.get("from"), require_offset=True) is None
            or parse_iso_datetime(shared_window.get("to"), require_offset=True) is None
        ):
            warnings.append(
                "'usage_window' must be a {from, to} mapping of RFC 3339 timestamps (OKF v0.3 §5.1)"
            )

    source_ids: set[str] = set()
    if "sources" in frontmatter and frontmatter["sources"] is not None:
        raw_sources = frontmatter["sources"]
        if isinstance(raw_sources, dict):
            raw_sources_list: list[Any] | None = [raw_sources]
        elif isinstance(raw_sources, list):
            raw_sources_list = raw_sources
        else:
            raw_sources_list = None
            errors.append("Frontmatter 'sources' must be a list")

        if raw_sources_list is not None:
            for idx, item in enumerate(raw_sources_list):
                if isinstance(item, str):
                    if item.strip():
                        legacy_sources = True
                        warnings.append(
                            f"sources[{idx}] uses legacy string format; run 'vault-lint --fix --migrate-sources' to upgrade to {{id, resource}}"
                        )
                    else:
                        warnings.append(
                            f"sources[{idx}] is an empty placeholder string"
                        )
                elif isinstance(item, dict):
                    res_val = item.get("resource")
                    if not isinstance(res_val, str) or not res_val.strip():
                        errors.append(
                            f"sources[{idx}] mapping is missing required non-empty 'resource' field"
                        )
                    else:
                        _check_path_field_warn(f"sources[{idx}].resource", res_val)
                    if "id" in item and item["id"] is not None:
                        id_val = item["id"]
                        if not isinstance(id_val, str) or not id_val.strip():
                            errors.append(
                                f"sources[{idx}] mapping 'id' must be a non-empty string"
                            )
                        else:
                            sid = id_val.strip()
                            if sid in source_ids:
                                warnings.append(
                                    f"sources[{idx}].id {sid!r} is duplicated (OKF v0.3 §5.1)"
                                )
                            source_ids.add(sid)
                    if item.get("author") not in (None, "") and not is_valid_actor(item.get("author")):
                        warnings.append(
                            f"sources[{idx}].author {item.get('author')!r} is not a valid OKF actor (OKF v0.3 §7)"
                        )
                    if item.get("last_modified") not in (None, "") and parse_iso_datetime(
                        item.get("last_modified"), require_offset=True
                    ) is None:
                        warnings.append(
                            f"sources[{idx}].last_modified {item.get('last_modified')!r} is not a valid RFC 3339 date/timestamp (OKF v0.3 §5)"
                        )
                    item_win = item.get("usage_window")
                    if item_win not in (None, "", []):
                        if (
                            not isinstance(item_win, dict)
                            or parse_iso_datetime(item_win.get("from"), require_offset=True) is None
                            or parse_iso_datetime(item_win.get("to"), require_offset=True) is None
                        ):
                            warnings.append(
                                f"sources[{idx}].usage_window must be a {{from, to}} mapping of RFC 3339 timestamps (OKF v0.3 §5.1)"
                            )
                    if (
                        item.get("usage_count") not in (None, "")
                        and shared_window in (None, "", [])
                        and item_win in (None, "", [])
                    ):
                        warnings.append(
                            f"sources[{idx}].usage_count requires a 'usage_window' period (OKF v0.3 §5.1)"
                        )
                else:
                    errors.append(
                        f"sources[{idx}] must be a mapping or string, got {type(item).__name__}"
                    )

    # 3. `generated` & `verified` validation (OKF v0.3 §5.2, §5.3 & §11)
    generated_val = frontmatter.get("generated")
    if generated_val not in (None, "", []):
        if not isinstance(generated_val, dict) or not str(generated_val.get("by") or "").strip():
            warnings.append("'generated' should be a mapping with a non-empty 'by' actor (OKF v0.3 §5.2)")
        else:
            if not is_valid_actor(generated_val.get("by")):
                warnings.append(
                    f"generated.by {generated_val.get('by')!r} is not a valid OKF actor (OKF v0.3 §7)"
                )
            gen_at_raw = generated_val.get("at")
            if gen_at_raw not in (None, "") and parse_iso_datetime(gen_at_raw, require_offset=True) is None:
                warnings.append(
                    f"generated.at {gen_at_raw!r} must be an RFC 3339 date-time with UTC offset (OKF v0.3 §5)"
                )

    if "verified" in frontmatter and frontmatter["verified"] is not None:
        raw_ver = frontmatter["verified"]
        if not isinstance(raw_ver, (dict, list)):
            errors.append("Frontmatter 'verified' must be a mapping or list of mappings")
        else:
            if isinstance(raw_ver, list) and any(
                not isinstance(v, dict) for v in raw_ver
            ):
                errors.append("Every entry in frontmatter 'verified' must be a mapping")
            for idx, v_entry in enumerate(normalize_verified_list(raw_ver)):
                by_val = v_entry.get("by")
                if not isinstance(by_val, str) or not by_val.strip():
                    errors.append(
                        f"verified[{idx}] is missing required non-empty 'by' field"
                    )
                elif by_val.strip() == "human:":
                    errors.append(
                        f"verified[{idx}] has empty human actor identifier 'human:'"
                    )
                elif not is_valid_actor(by_val):
                    warnings.append(
                        f"verified[{idx}].by {by_val!r} is not a valid OKF actor (OKF v0.3 §7)"
                    )
                at_val = v_entry.get("at")
                if at_val in (None, ""):
                    warnings.append(
                        f"verified[{idx}] is missing 'at' timestamp (OKF v0.3 §5.2)"
                    )
                elif parse_iso_datetime(at_val, require_offset=True) is None:
                    warnings.append(
                        f"verified[{idx}].at {at_val!r} must be an RFC 3339 date-time with UTC offset (OKF v0.3 §5)"
                    )

    stale_ver_flag = has_stale_verifications(frontmatter)
    if stale_ver_flag:
        warnings.append(
            "No verification is current: every verified[].at is older than generated.at, so trust_tier is unverified (OKF v0.3 §5.3)"
        )

    # 4. `stale_after` validation (OKF v0.3 §5.5 & §11.2)
    stale_after_raw = frontmatter.get("stale_after")
    stale_after_str: str | None = None
    stale_flag = False
    if stale_after_raw is not None and str(stale_after_raw).strip() != "":
        stale_after_str = str(stale_after_raw).strip()
        if parse_iso_datetime(stale_after_raw, require_offset=True) is None:
            stale_flag = True
            errors.append(
                f"Invalid RFC 3339 date/datetime in 'stale_after': {stale_after_raw!r}"
            )
        else:
            stale_flag = is_stale(frontmatter, now=now)
            if stale_flag:
                warnings.append(
                    f"Concept is stale (stale_after: {stale_after_str})"
                )

    # 5. Body footnote citation resolution (`[^id]` vs `sources[].id` or `[^id]:` defs, §5.1 & §11)
    prose_body = _strip_code_and_comments_from_body(body)
    body_defs = {m.group(1).strip() for m in _FOOTNOTE_DEF_RE.finditer(prose_body)}
    valid_targets = source_ids | body_defs
    referenced_ids: list[str] = []
    seen_unresolved: set[str] = set()
    for m in _FOOTNOTE_REF_RE.finditer(prose_body):
        ref_id = m.group(1).strip()
        if ref_id and ref_id not in valid_targets and ref_id not in seen_unresolved:
            seen_unresolved.add(ref_id)
            referenced_ids.append(ref_id)
    if referenced_ids:
        missing_footnotes = referenced_ids
        errors.append(
            f"Unresolved footnote citation(s) in body matching neither sources[].id nor [^id]: definitions: {', '.join(missing_footnotes)}"
        )

    # 6. Attested Computation profile (OKF v0.3 §10.2 & §10.3)
    if concept_type_str == "Attested Computation":
        runtime_val = frontmatter.get("runtime")
        has_runtime = (isinstance(runtime_val, str) and bool(runtime_val.strip())) or (
            isinstance(runtime_val, dict) and len(runtime_val) > 0
        )
        if not has_runtime:
            errors.append(
                "Attested Computation concept is missing required 'runtime' field in frontmatter (OKF v0.3 §10.2)"
            )
        comp_val = frontmatter.get("computation")
        has_fm_comp = (isinstance(comp_val, str) and bool(comp_val.strip())) or (
            isinstance(comp_val, dict) and len(comp_val) > 0
        )
        comp_fences = _count_computation_fences(body)
        has_body_comp = comp_fences > 0 or bool(_COMPUTATION_HEADING_RE.search(prose_body))
        if has_fm_comp:
            if isinstance(comp_val, str):
                _check_path_field_warn("computation", comp_val)
            if comp_fences > 0:
                warnings.append(
                    "Attested Computation declares both 'computation' file path and an inline fenced block in '# Computation' (OKF v0.3 §10.3)"
                )
        elif not has_body_comp:
            errors.append(
                "Attested Computation concept requires either a 'computation' frontmatter field or a '# Computation' heading with a fenced code block in the body (OKF v0.3 §10.3)"
            )
        elif comp_fences == 0:
            warnings.append(
                "Attested Computation '# Computation' section has no fenced code block (OKF v0.3 §10.3)"
            )
        elif comp_fences > 1:
            warnings.append(
                f"Attested Computation '# Computation' section has {comp_fences} fenced blocks; consumers use only the first (OKF v0.3 §10.3)"
            )

        raw_params = frontmatter.get("parameters")
        if raw_params not in (None, "", []):
            param_list = raw_params if isinstance(raw_params, list) else [raw_params]
            for pidx, pitem in enumerate(param_list):
                if (
                    not isinstance(pitem, dict)
                    or not str(pitem.get("name") or "").strip()
                    or not str(pitem.get("type") or "").strip()
                ):
                    warnings.append(
                        f"parameters[{pidx}] requires non-empty 'name' and 'type' fields (OKF v0.3 §10.2)"
                    )

        for ac_key in ("executor", "attester"):
            ac_val = frontmatter.get(ac_key)
            if ac_val in (None, "", []):
                continue
            if not isinstance(ac_val, dict) or not str(ac_val.get("resource") or "").strip():
                warnings.append(
                    f"'{ac_key}' must be a mapping with a non-empty 'resource' path (OKF v0.3 §10.2)"
                )
            else:
                _check_path_field_warn(f"{ac_key}.resource", ac_val.get("resource"))
                if ac_key == "executor" and ac_val.get("receipt") is not None and not isinstance(ac_val.get("receipt"), list):
                    warnings.append(
                        "'executor.receipt' must list the receipt fields returned by a run (OKF v0.3 §10.2)"
                    )

    trust_tier = derive_trust_tier(frontmatter)
    return {
        "valid": len(errors) == 0,
        "has_frontmatter": True,
        "errors": errors,
        "warnings": warnings,
        "legacy_sources": legacy_sources,
        "frontmatter": frontmatter,
        "trust_tier": trust_tier,
        "is_stale": stale_flag,
        "stale_after": stale_after_str,
        "missing_footnotes": missing_footnotes,
        "is_current_status": is_current_status(frontmatter),
        "stale_verifications": stale_ver_flag,
        "superseded_by": superseded_by_str,
        "okf_version": okf_version or SUPPORTED_OKF_VERSION,
    }


def _derive_unique_source_id(
    resource_str: str, used_ids: set[str], index: int
) -> str:
    """Derive a deterministic, unique slug ID from a source resource string."""
    cleaned = resource_str.strip()
    if cleaned.startswith("[[") and cleaned.endswith("]]"):
        cleaned = cleaned[2:-2].split("|", 1)[0].strip()
    cleaned = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", cleaned)
    cleaned = cleaned.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = [p for p in cleaned.split("/") if p]
    candidate_raw = parts[-1] if parts else f"src-{index + 1}"
    candidate_raw = re.sub(
        r"\.(?:md|pptx|pdf|docx|xlsx|html|mhtml|txt|json|yaml|yml|csv)$",
        "",
        candidate_raw,
        flags=re.IGNORECASE,
    )
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", candidate_raw.lower()).strip("-")
    if not slug or slug[0].isdigit() or slug in (
        "null",
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "y",
        "n",
    ):
        slug = f"src-{slug}" if slug else f"src-{index + 1}"
    slug = slug[:32].rstrip("-")
    base_slug = slug
    counter = 2
    while slug in used_ids:
        slug = f"{base_slug}-{counter}"
        counter += 1
    used_ids.add(slug)
    return slug


def _escape_double_quoted_yaml_str(s: str) -> str:
    """Escape a Python string for safe single-line YAML double-quoted emission."""
    out: list[str] = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\0":
            out.append("\\0")
        elif ch == "\x85":
            out.append("\\x85")
        elif ch == "\u2028":
            out.append("\\u2028")
        elif ch == "\u2029":
            out.append("\\u2029")
        elif ord(ch) < 32 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _format_yaml_scalar(val: Any) -> str:
    """Format a scalar value safely for surgical YAML emission (YAML 1.1 & 1.2 safe)."""
    if val is None:
        return "null"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    low = s.lower()
    special_chars = frozenset(
        (
            ":",
            "#",
            "[",
            "]",
            "{",
            "}",
            ",",
            '"',
            "'",
            "\n",
            "\r",
            "\t",
            "\\",
            "\x85",
            "\u2028",
            "\u2029",
        )
    )
    needs_quotes = (
        not s
        or any(
            ch in special_chars or ord(ch) < 32 or ord(ch) == 0x7F
            for ch in s
        )
        or s.startswith(
            (" ", "\t", "-", "&", "*", "?", "|", ">", "!", "%", "@", "`", ".", "+", "=")
        )
        or s.endswith((" ", "\t"))
        or bool(re.match(r"^[+-]?[0-9]", s))
        or low
        in (
            "null",
            "~",
            "true",
            "false",
            "yes",
            "no",
            "on",
            "off",
            "y",
            "n",
            ".inf",
            "+.inf",
            "-.inf",
            ".nan",
            "=",
            "<<",
        )
    )
    if needs_quotes:
        return f'"{_escape_double_quoted_yaml_str(s)}"'
    return s


def _format_yaml_value(val: Any) -> str:
    """Format a scalar, list, or nested mapping value safely as inline YAML."""
    if isinstance(val, dict):
        if not val:
            return "{}"
        pairs = [
            f"{_format_yaml_scalar(str(dk))}: {_format_yaml_value(dv)}"
            for dk, dv in val.items()
        ]
        return "{ " + ", ".join(pairs) + " }"
    if isinstance(val, list):
        if not val:
            return "[]"
        return "[" + ", ".join(_format_yaml_value(item) for item in val) + "]"
    return _format_yaml_scalar(val)


def _replace_top_level_key_block(
    yaml_text: str, key: str, replacement_block: str, nl: str
) -> str:
    """Surgically replace a top-level `key:` block in `yaml_text`, or append it if absent."""
    lines = yaml_text.splitlines()
    start_line: int | None = None
    end_line: int = len(lines)

    in_block_scalar = False
    block_parent_indent = 0
    block_base_indent: int | None = None

    for i, line in enumerate(lines):
        if in_block_scalar:
            if not line.strip():
                continue
            sp = _leading_spaces(line)
            if sp > block_parent_indent and (
                block_base_indent is None or sp >= block_base_indent
            ):
                if block_base_indent is None:
                    block_base_indent = sp
                continue
            in_block_scalar = False
            block_base_indent = None

        cleaned = _strip_inline_comment(line)
        if ":" in cleaned:
            after_c = cleaned.split(":", 1)[1].strip()
            if _BLOCK_SCALAR_HEADER_RE.match(after_c):
                in_block_scalar = True
                block_parent_indent = _leading_spaces(line)
                digit = _extract_block_header_indent_digit(after_c)
                block_base_indent = (
                    block_parent_indent + digit if digit is not None else None
                )

        colon_idx = _matches_top_level_key(line, key)
        if colon_idx >= 0:
            start_line = i
            after = cleaned[colon_idx + 1 :].strip()
            flow_balance = 0
            if after.startswith(("[", "{")):
                try:
                    flow_balance = _flow_bracket_balance(after)
                except OKFParseError:
                    flow_balance = 0

            j = i + 1
            while j < len(lines):
                j_line = lines[j]
                j_stripped = j_line.strip()
                if flow_balance > 0:
                    try:
                        flow_balance = _flow_bracket_balance(
                            " ".join(
                                _strip_inline_comment(ln) for ln in lines[i : j + 1]
                            )
                        )
                    except OKFParseError:
                        flow_balance = 0
                    j += 1
                    continue
                if not j_stripped or j_stripped.startswith("#"):
                    if j_stripped.startswith("#") and not j_line.startswith((" ", "\t")):
                        break
                    k = j + 1
                    while k < len(lines) and not lines[k].strip():
                        k += 1
                    if k < len(lines) and (
                        lines[k].startswith((" ", "\t"))
                        or lines[k].strip() == "-"
                        or lines[k].strip().startswith("- ")
                    ):
                        j += 1
                        continue
                    break
                if (
                    j_line.startswith((" ", "\t"))
                    or j_stripped == "-"
                    or j_stripped.startswith("- ")
                ):
                    j += 1
                    continue
                break
            end_line = j
            break

    repl_lines = replacement_block.splitlines()
    if start_line is not None:
        new_lines = lines[:start_line] + repl_lines + lines[end_line:]
    else:
        while lines and not lines[-1].strip():
            lines.pop()
        new_lines = lines + repl_lines
    return nl.join(new_lines)


def migrate_legacy_sources_in_frontmatter(
    content: str, *, use_pyyaml: bool = True
) -> tuple[str, bool]:
    """Deterministically upgrade legacy string `sources:` entries to `{id, resource}` mappings.

    Preserves Markdown body byte-for-byte, existing dict entries in `sources:`, and all other
    frontmatter keys. Idempotent: returns `(content, False)` if no non-empty legacy string
    entries exist.
    """
    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return content, False

    nl = match.group(1)
    yaml_text = match.group(2) if match.group(2) is not None else ""
    close_nl = match.group(3)
    body = match.group(4)

    try:
        fm = parse_frontmatter(yaml_text, strict=True, use_pyyaml=use_pyyaml)
    except OKFParseError:
        return content, False

    raw_sources = fm.get("sources")
    if not isinstance(raw_sources, list):
        return content, False

    has_legacy_str = any(
        isinstance(item, str) and bool(item.strip()) for item in raw_sources
    )
    if not has_legacy_str:
        return content, False

    used_ids: set[str] = {
        str(item["id"]).strip()
        for item in raw_sources
        if isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and item["id"].strip()
    }

    migrated_items: list[dict[str, Any]] = []
    for idx, item in enumerate(raw_sources):
        if isinstance(item, str):
            res = item.strip()
            if not res:
                continue
            sid = _derive_unique_source_id(res, used_ids, idx)
            migrated_items.append({"id": sid, "resource": res})
        elif isinstance(item, dict):
            migrated_items.append(dict(item))

    block_lines = ["sources:"]
    for entry in migrated_items:
        first_kv = True
        ordered_keys = []
        for preferred in ("id", "resource"):
            if preferred in entry:
                ordered_keys.append(preferred)
        for k in entry:
            if k not in ordered_keys:
                ordered_keys.append(k)
        for k in ordered_keys:
            formatted_v = _format_yaml_value(entry[k])
            prefix = "  - " if first_kv else "    "
            block_lines.append(f"{prefix}{k}: {formatted_v}")
            first_kv = False

    new_yaml = _replace_top_level_key_block(
        yaml_text, "sources", nl.join(block_lines), nl
    )
    if new_yaml == yaml_text:
        return content, False

    new_content = f"{bom}---{nl}{new_yaml}{nl}---{close_nl}{body}"
    return new_content, True


def stamp_human_verification(
    content: str,
    actor: str,
    at_iso: str | None = None,
    *,
    use_pyyaml: bool = True,
) -> str:
    """Deterministically stamp a `human:<id>` entry into frontmatter `verified:`.

    Preserves Markdown body byte-for-byte and existing frontmatter keys.
    """
    if not isinstance(actor, str) or any(
        ord(c) < 32 or ord(c) == 0x7F or c in ("\x85", "\u2028", "\u2029")
        for c in actor
    ):
        raise OKFParseError(
            f"Invalid control or newline character in verification actor: {actor!r}"
        )

    clean_actor = actor.strip()
    if not clean_actor:
        raise OKFParseError("Human verification actor cannot be empty")
    if ":" in clean_actor and not clean_actor.startswith("human:"):
        raise OKFParseError(
            f"Human verification actor must use 'human:<id>' namespace, got {actor!r}"
        )
    if not clean_actor.startswith("human:"):
        clean_actor = f"human:{clean_actor}"
    human_id = clean_actor[len("human:") :].strip()
    if not human_id:
        raise OKFParseError("Human verification actor ID after 'human:' cannot be empty")
    if not _HUMAN_ID_RE.match(human_id):
        raise OKFParseError(
            f"Invalid characters in human verification actor ID: {human_id!r}"
        )
    clean_actor = f"human:{human_id}"

    if at_iso is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    else:
        if not isinstance(at_iso, str) or any(
            ord(c) < 32 or ord(c) == 0x7F or c in ("\x85", "\u2028", "\u2029")
            for c in at_iso
        ):
            raise OKFParseError(f"Invalid ISO-8601 verification timestamp: {at_iso!r}")
        timestamp = at_iso.strip()
        if parse_iso_datetime(timestamp) is None:
            raise OKFParseError(f"Invalid ISO-8601 verification timestamp: {at_iso!r}")

    bom = "\ufeff" if content.startswith("\ufeff") else ""
    text = content[len(bom) :]
    match = _FRONTMATTER_RE.match(text)
    if not match:
        raise OKFParseError(
            "Cannot stamp human verification on document without valid YAML frontmatter"
        )

    nl = match.group(1)
    yaml_text = match.group(2) if match.group(2) is not None else ""
    close_nl = match.group(3)
    body = match.group(4)

    fm = parse_frontmatter(yaml_text, strict=True, use_pyyaml=use_pyyaml)
    existing = normalize_verified_list(fm.get("verified"))

    updated_list: list[dict[str, Any]] = []
    matched = False
    for entry in existing:
        entry_copy = dict(entry)
        if str(entry_copy.get("by", "")).strip() == clean_actor:
            entry_copy["by"] = clean_actor
            entry_copy["at"] = timestamp
            matched = True
        updated_list.append(entry_copy)

    if not matched:
        updated_list.append({"by": clean_actor, "at": timestamp})

    block_lines = ["verified:"]
    for entry in updated_list:
        first_kv = True
        ordered_keys = []
        for preferred in ("by", "at"):
            if preferred in entry:
                ordered_keys.append(preferred)
        for k in entry:
            if k not in ordered_keys:
                ordered_keys.append(k)
        for k in ordered_keys:
            formatted_v = _format_yaml_value(entry[k])
            prefix = "  - " if first_kv else "    "
            block_lines.append(f"{prefix}{k}: {formatted_v}")
            first_kv = False

    new_yaml = _replace_top_level_key_block(
        yaml_text, "verified", nl.join(block_lines), nl
    )
    return f"{bom}---{nl}{new_yaml}{nl}---{close_nl}{body}"
