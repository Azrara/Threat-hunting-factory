"""Turning a fetched page into the text an agent can read.

Publishers wrap the article in navigation, cookie banners, related links and
newsletter forms. Feeding all of that to a model wastes context and adds text an
attacker can write into. The reader below keeps the elements that carry prose and
drops the rest, which is cruder than a full readability implementation and has the
advantage of being ours, bounded, and with no dependency.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_TEXT_LENGTH = 200_000
MAX_PDF_PAGES = 60
# Control characters and the direction marks that let text lie about its order.
_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
_SPACES = re.compile(r"[ \t\u00a0]+")
_BLANK_LINES = re.compile(r"\n{3,}")

SKIP_ELEMENTS = {
    "script", "style", "noscript", "svg", "canvas", "iframe", "form",
    "nav", "header", "footer", "aside", "button", "select", "template",
}
BLOCK_ELEMENTS = {
    "p", "div", "section", "article", "br", "li", "tr", "td", "th",
    "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote", "figcaption", "dd", "dt",
}


@dataclass
class Article:
    title: str
    text: str
    kind: str  # html, pdf, text

    @property
    def characters(self) -> int:
        return len(self.text)


def sanitise(text: str) -> str:
    """Strip what has no business in prose, and bound the length."""
    cleaned = _UNSAFE.sub("", text)
    cleaned = _SPACES.sub(" ", cleaned)
    cleaned = "\n".join(line.strip() for line in cleaned.splitlines())
    cleaned = _BLANK_LINES.sub("\n\n", cleaned).strip()
    return cleaned[:MAX_TEXT_LENGTH]


class _Reader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title_parts: list[str] = []
        # Publishers put the better headline in og:title and the site name in
        # <title>, so the two are kept apart rather than concatenated.
        self.og_title: str = ""
        self._skip_depth = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in SKIP_ELEMENTS:
            self._skip_depth += 1
            return
        if tag == "title":
            self._in_title = True
        if tag in BLOCK_ELEMENTS:
            self.parts.append("\n")
        if tag == "meta":
            values = dict(attrs)
            key = (values.get("property") or values.get("name") or "").lower()
            if key in ("og:title", "twitter:title") and values.get("content") and not self.og_title:
                self.og_title = values["content"] or ""

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIP_ELEMENTS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if tag == "title":
            self._in_title = False
        if tag in BLOCK_ELEMENTS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title_parts.append(data)
            return
        if data.strip():
            self.parts.append(data)


def from_html(payload: str) -> Article:
    reader = _Reader()
    try:
        reader.feed(payload)
        reader.close()
    except Exception:  # noqa: BLE001 - malformed markup must not stop a run
        pass
    raw_title = reader.og_title or " ".join(reader.title_parts)
    title = html.unescape(" ".join(raw_title.split()))[:400]
    return Article(title=title, text=sanitise("".join(reader.parts)), kind="html")


def from_pdf(payload: bytes) -> Article:
    """Extract text from a research paper. Requires pypdf, which is optional."""
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise RuntimeError(
            "Reading PDF sources needs pypdf. Install it, or the collector skips them."
        ) from error
    import io

    reader = PdfReader(io.BytesIO(payload))
    pages = reader.pages[:MAX_PDF_PAGES]
    chunks = []
    for page in pages:
        try:
            chunks.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001 - one unreadable page is not a failure
            continue
    title = ""
    try:
        title = str((reader.metadata or {}).get("/Title", "") or "")
    except Exception:  # noqa: BLE001
        title = ""
    return Article(title=title[:400], text=sanitise("\n".join(chunks)), kind="pdf")


def read(content: bytes, content_type: str, url: str = "") -> Article:
    """Choose a reader from the declared type, falling back on the bytes themselves."""
    declared = (content_type or "").split(";")[0].strip().lower()
    looks_pdf = content[:5] == b"%PDF-" or declared == "application/pdf" or url.lower().endswith(".pdf")
    if looks_pdf:
        return from_pdf(content)
    text = content.decode("utf-8", errors="replace")
    if declared in ("text/plain", "text/markdown") and "<html" not in text[:2000].lower():
        return Article(title="", text=sanitise(text), kind="text")
    return from_html(text)
