"""A deliberately polite HTTP client for reading public publications.

The collector reads other people's websites unattended, once a week. Three things
follow from that and are enforced here rather than left to good intentions:
robots.txt is honoured, one host is never hit faster than a fixed rate, and no
response is read past a size cap. A conditional request means a feed that has not
changed costs one round trip and no parsing.
"""

from __future__ import annotations

import threading
import time
import urllib.robotparser
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

import httpx

USER_AGENT = "ThreatHuntingFactory/1.0 (hypothesis collector; +https://github.com/)"
MAX_BYTES = 8 * 1024 * 1024
MIN_HOST_INTERVAL = 1.5
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 45.0
MAX_REDIRECTS = 5


class FetchError(RuntimeError):
    """The resource could not be read. Never fatal to a run."""


class NotModified(Exception):
    """The server says nothing changed since the stored validators."""


class Forbidden(FetchError):
    """robots.txt asks us not to read this."""


@dataclass
class Response:
    url: str
    status: int
    content: bytes
    content_type: str
    etag: str = ""
    last_modified: str = ""

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


def canonical(url: str) -> str:
    """A stable key for one article.

    Tracking parameters, fragments and a trailing slash make the same article look
    like several, which would mean extracting it more than once.
    """
    parts = urlsplit(url.strip())
    # The same article reachable over both schemes is one article, so the key uses
    # one of them. Only the key is normalised: the address actually requested is
    # whatever the feed gave.
    scheme = "https"
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    for port in (":80", ":443"):
        if host.endswith(port):
            host = host[: -len(port)]
    query = "&".join(
        piece
        for piece in parts.query.split("&")
        if piece and not piece.split("=", 1)[0].lower().startswith(("utm_", "mc_", "fbclid", "gclid"))
    )
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((scheme, host, path, query, ""))


@dataclass
class PoliteClient:
    """Rate limited, robots aware, size capped."""

    transport: httpx.BaseTransport | None = None
    min_interval: float = MIN_HOST_INTERVAL
    max_bytes: int = MAX_BYTES
    respect_robots: bool = True
    _last_call: dict[str, float] = field(default_factory=dict, repr=False)
    _robots: dict[str, urllib.robotparser.RobotFileParser | None] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _client: httpx.Client | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self._client = httpx.Client(
            timeout=httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT),
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
            transport=self.transport,
        )

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def __enter__(self) -> "PoliteClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- politeness -------------------------------------------------------

    def _wait_turn(self, host: str) -> None:
        with self._lock:
            previous = self._last_call.get(host, 0.0)
            now = time.monotonic()
            delay = previous + self.min_interval - now
            self._last_call[host] = now + max(delay, 0.0)
        if delay > 0:
            time.sleep(delay)

    def allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._robots:
            self._robots[origin] = self._load_robots(origin)
        parser = self._robots[origin]
        if parser is None:
            # No robots.txt, or it could not be read. The convention is that
            # everything is allowed, and being unable to ask is not consent to
            # ignore the question, so it is recorded rather than assumed.
            return True
        return parser.can_fetch(USER_AGENT, url)

    def _load_robots(self, origin: str) -> urllib.robotparser.RobotFileParser | None:
        try:
            self._wait_turn(urlsplit(origin).netloc)
            response = self._client.get(f"{origin}/robots.txt")
        except httpx.HTTPError:
            return None
        if response.status_code != 200 or not response.text.strip():
            return None
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser

    # -- fetching ---------------------------------------------------------

    def get(self, url: str, etag: str = "", last_modified: str = "") -> Response:
        if not url.lower().startswith(("http://", "https://")):
            raise FetchError(f"Refusing a non HTTP address: {url[:120]}")
        if not self.allowed(url):
            raise Forbidden(f"robots.txt disallows {url}")

        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        self._wait_turn(urlsplit(url).netloc)
        try:
            with self._client.stream("GET", url, headers=headers) as response:
                if response.status_code == 304:
                    raise NotModified(url)
                if response.status_code >= 400:
                    raise FetchError(f"{url} returned {response.status_code}")
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise FetchError(
                            f"{url} is larger than the {self.max_bytes // (1024 * 1024)} MB limit"
                        )
                    chunks.append(chunk)
                return Response(
                    url=str(response.url),
                    status=response.status_code,
                    content=b"".join(chunks),
                    content_type=response.headers.get("content-type", ""),
                    etag=response.headers.get("etag", ""),
                    last_modified=response.headers.get("last-modified", ""),
                )
        except httpx.HTTPError as error:
            raise FetchError(f"{url} could not be read: {error}") from error
