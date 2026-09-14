"""Reading RSS, Atom and the arXiv API with the standard library.

Feed formats are simple enough that a dependency is not worth it, and the parser
being ours means a malformed feed produces a skipped source rather than a stack
trace in the middle of an unattended run.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .http import canonical

ATOM = "{http://www.w3.org/2005/Atom}"
DC = "{http://purl.org/dc/elements/1.1/}"
# RFC 5005 paged feeds. Very few publishers implement it, which is why a feed that
# has rotated is reported rather than silently paged through.
NEXT_REL = "next"


@dataclass
class FeedItem:
    title: str
    url: str
    published_at: datetime | None = None
    summary: str = ""

    @property
    def key(self) -> str:
        return canonical(self.url)


@dataclass
class Feed:
    title: str = ""
    items: list[FeedItem] = field(default_factory=list)
    next_page: str = ""

    @property
    def oldest(self) -> datetime | None:
        stamps = [item.published_at for item in self.items if item.published_at]
        return min(stamps) if stamps else None


def parse_datetime(value: str) -> datetime | None:
    """RSS dates are RFC 822, Atom dates are ISO 8601. Both arrive here."""
    text = (value or "").strip()
    if not text:
        return None
    try:
        parsed = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        parsed = None
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return " ".join("".join(node.itertext()).split())


def parse(payload: bytes | str) -> Feed:
    """Parse an RSS or Atom document. Raises ValueError on anything else."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    try:
        # A feed is data from somebody else's server. Entity expansion is the one
        # way an XML document attacks its parser, and the standard parser has it
        # switched off, which is exactly why it is used here.
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise ValueError(f"not a readable feed: {error}") from error

    if root.tag == f"{ATOM}feed":
        return _parse_atom(root)
    if root.tag == "rss":
        channel = root.find("channel")
        if channel is not None:
            return _parse_rss(channel)
    if root.tag == "channel":
        return _parse_rss(root)
    raise ValueError(f"unknown feed root element {root.tag}")


def _parse_rss(channel: ET.Element) -> Feed:
    feed = Feed(title=_text(channel.find("title")))
    for node in channel.findall("item"):
        url = _text(node.find("link")) or _text(node.find("guid"))
        if not url.lower().startswith(("http://", "https://")):
            continue
        published = (
            parse_datetime(_text(node.find("pubDate")))
            or parse_datetime(_text(node.find(f"{DC}date")))
        )
        feed.items.append(
            FeedItem(
                title=_text(node.find("title")),
                url=url,
                published_at=published,
                summary=_text(node.find("description"))[:2000],
            )
        )
    return feed


def _parse_atom(root: ET.Element) -> Feed:
    feed = Feed(title=_text(root.find(f"{ATOM}title")))
    for link in root.findall(f"{ATOM}link"):
        if link.get("rel") == NEXT_REL and link.get("href"):
            feed.next_page = link.get("href", "")
    for node in root.findall(f"{ATOM}entry"):
        url = ""
        for link in node.findall(f"{ATOM}link"):
            relation = link.get("rel") or "alternate"
            if relation == "alternate" and link.get("href"):
                url = link.get("href", "")
                break
        if not url:
            url = _text(node.find(f"{ATOM}id"))
        if not url.lower().startswith(("http://", "https://")):
            continue
        published = (
            parse_datetime(_text(node.find(f"{ATOM}published")))
            or parse_datetime(_text(node.find(f"{ATOM}updated")))
        )
        feed.items.append(
            FeedItem(
                title=_text(node.find(f"{ATOM}title")),
                url=url,
                published_at=published,
                summary=(
                    _text(node.find(f"{ATOM}summary")) or _text(node.find(f"{ATOM}content"))
                )[:2000],
            )
        )
    return feed


def items_since(feed: Feed, since: datetime | None) -> list[FeedItem]:
    """Items published after ``since``. An item without a date is always kept."""
    if since is None:
        return list(feed.items)
    return [
        item
        for item in feed.items
        if item.published_at is None or item.published_at > since
    ]


def has_rotated(feed: Feed, since: datetime | None) -> bool:
    """True when the feed's oldest item is newer than the previous run.

    That is the observable symptom of a publisher writing more in one week than
    its feed holds: everything between the previous run and the oldest item still
    listed has scrolled off unseen.
    """
    if since is None or not feed.items:
        return False
    oldest = feed.oldest
    return oldest is not None and oldest > since
