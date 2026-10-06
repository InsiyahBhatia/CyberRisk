"""Parse -> clean -> chunk. Markdown documents are split by heading, then into overlapping paragraph windows."""
from __future__ import annotations

import re
from dataclasses import dataclass

HEADER_RE = re.compile(r"^(?P<key>Framework|Version|Source type):\s*(?P<val>.+)$", re.M)


@dataclass
class ParsedDoc:
    title: str
    framework: str
    version: str
    source_type: str
    text: str


def clean(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"^>.*$", "", text, flags=re.M)   # drop blockquote disclaimers from chunk bodies (kept in metadata/title)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_markdown(raw: str, fallback_title: str) -> ParsedDoc:
    title_m = re.search(r"^#\s+(.+)$", raw, re.M)
    meta = {m.group("key"): m.group("val").strip() for m in HEADER_RE.finditer(raw)}
    body = HEADER_RE.sub("", raw)
    return ParsedDoc(title_m.group(1).strip() if title_m else fallback_title, meta.get("Framework", "Internal"), meta.get("Version", "1"),
                     meta.get("Source type", "document"), clean(body))


def chunk_sections(text: str, max_chars: int = 900, overlap: int = 120) -> list[tuple[str, str]]:
    """Returns [(section, chunk_text)]."""
    sections: list[tuple[str, str]] = []
    current_title, buf = "Introduction", []
    for line in text.split("\n"):
        h = re.match(r"^#{2,4}\s+(.+)$", line)
        if h:
            if "".join(buf).strip():
                sections.append((current_title, "\n".join(buf).strip()))
            current_title, buf = h.group(1).strip(), []
        elif not line.startswith("# "):
            buf.append(line)
    if "".join(buf).strip():
        sections.append((current_title, "\n".join(buf).strip()))

    chunks: list[tuple[str, str]] = []
    for title, body in sections:
        if len(body) <= max_chars:
            chunks.append((title, body))
            continue
        start = 0
        while start < len(body):
            end = min(len(body), start + max_chars)
            if end < len(body):  # prefer to break on a sentence boundary
                cut = max(body.rfind(". ", start, end), body.rfind("\n", start, end))
                if cut > start + max_chars // 2:
                    end = cut + 1
            chunks.append((title, body[start:end].strip()))
            if end >= len(body):
                break
            start = max(end - overlap, start + 1)
    return [(s, c) for s, c in chunks if c]
