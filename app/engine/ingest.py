"""Archive extraction and safe log file reading."""

from __future__ import annotations

import gzip
import os
import shutil
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

try:  # optional, unlocks native Windows event log support
    import Evtx.Evtx as evtx_module  # type: ignore

    EVTX_AVAILABLE = True
except Exception:  # pragma: no cover - depends on the deployment
    evtx_module = None
    EVTX_AVAILABLE = False

TEXT_EXTENSIONS = {
    ".log", ".txt", ".json", ".ndjson", ".jsonl", ".csv", ".tsv", ".xml", ".evt",
    ".syslog", ".out", ".err", ".audit", ".access", ".error", ".events", ".dat",
    ".msg", ".yaml", ".yml", ".conf", ".cef", ".leef", ".w3c", ".psv", ".eve",
}
BINARY_SKIP_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".zip", ".rar", ".7z", ".iso",
    ".mp3", ".mp4", ".avi", ".mov", ".ttf", ".woff", ".woff2", ".so", ".dylib",
    ".pyc", ".class", ".jar", ".db", ".sqlite", ".pcap", ".pcapng", ".bin",
}
MAX_FILE_BYTES = 400 * 1024 * 1024


@dataclass
class ExtractionResult:
    root: Path
    files: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    total_bytes: int = 0
    archive_type: str = "unknown"
    warnings: list[str] = field(default_factory=list)


def _safe_join(root: Path, member_name: str) -> Path | None:
    """Resolve an archive member inside the extraction root, or reject it."""
    candidate = (root / member_name).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def extract_archive(archive_path: Path, destination: Path, max_uncompressed: int) -> ExtractionResult:
    """Unpack an uploaded archive into ``destination`` with hard safety limits."""
    destination.mkdir(parents=True, exist_ok=True)
    result = ExtractionResult(root=destination)
    suffix = archive_path.suffix.lower()
    name = archive_path.name.lower()

    if zipfile.is_zipfile(archive_path):
        result.archive_type = "zip"
        with zipfile.ZipFile(archive_path) as archive:
            total = 0
            for info in archive.infolist():
                if info.is_dir():
                    continue
                target = _safe_join(destination, info.filename)
                if target is None:
                    result.skipped.append(f"{info.filename} (unsafe path)")
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    result.skipped.append(f"{info.filename} (file too large)")
                    continue
                total += info.file_size
                if total > max_uncompressed:
                    result.warnings.append("Extraction stopped at the configured size limit")
                    break
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, open(target, "wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 256)
                result.files.append(target)
            result.total_bytes = total
    elif tarfile.is_tarfile(archive_path):
        result.archive_type = "tar"
        with tarfile.open(archive_path) as archive:
            total = 0
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                target = _safe_join(destination, member.name)
                if target is None:
                    result.skipped.append(f"{member.name} (unsafe path)")
                    continue
                if member.size > MAX_FILE_BYTES:
                    result.skipped.append(f"{member.name} (file too large)")
                    continue
                total += member.size
                if total > max_uncompressed:
                    result.warnings.append("Extraction stopped at the configured size limit")
                    break
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with extracted, open(target, "wb") as sink:
                    shutil.copyfileobj(extracted, sink, length=1024 * 256)
                result.files.append(target)
            result.total_bytes = total
    elif suffix == ".gz" or name.endswith(".gz"):
        result.archive_type = "gzip"
        target = destination / archive_path.name[:-3]
        with gzip.open(archive_path, "rb") as source, open(target, "wb") as sink:
            shutil.copyfileobj(source, sink, length=1024 * 256)
        result.files.append(target)
        result.total_bytes = target.stat().st_size
    else:
        # A single log file uploaded without any container.
        result.archive_type = "file"
        target = destination / archive_path.name
        if target.resolve() != archive_path.resolve():
            shutil.copy2(archive_path, target)
        result.files.append(target)
        result.total_bytes = target.stat().st_size

    result.files = [path for path in result.files if path.exists()]
    return result


def collect_log_files(root: Path) -> tuple[list[Path], list[str]]:
    """Walk an extracted tree and return the files worth parsing."""
    selected: list[Path] = []
    skipped: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"__MACOSX", ".git", "node_modules"}]
        for filename in sorted(filenames):
            path = Path(dirpath) / filename
            suffix = path.suffix.lower()
            if suffix == ".evtx":
                if EVTX_AVAILABLE:
                    selected.append(path)
                else:
                    skipped.append(f"{path.name} (binary evtx support unavailable, export to XML)")
                continue
            if suffix in BINARY_SKIP_EXTENSIONS:
                skipped.append(f"{path.name} (unsupported binary type)")
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0:
                skipped.append(f"{path.name} (empty)")
                continue
            if size > MAX_FILE_BYTES:
                skipped.append(f"{path.name} (file too large)")
                continue
            if suffix in TEXT_EXTENSIONS or suffix == "" or _looks_textual(path):
                selected.append(path)
            else:
                skipped.append(f"{path.name} (not a log file)")
    return selected, skipped


def _looks_textual(path: Path, probe: int = 4096) -> bool:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(probe)
    except OSError:
        return False
    if not chunk:
        return False
    if b"\x00" in chunk[:1024]:
        return False
    printable = sum(1 for byte in chunk if 9 <= byte <= 13 or 32 <= byte <= 126 or byte >= 160)
    return printable / len(chunk) > 0.85


def detect_encoding(path: Path) -> str:
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return "utf-8"
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-8"


def read_lines(path: Path, limit: int | None = None) -> Iterator[str]:
    """Yield decoded lines, transparently handling gzip and Windows event logs."""
    suffix = path.suffix.lower()
    if suffix == ".evtx" and EVTX_AVAILABLE:
        yield from _read_evtx(path, limit)
        return
    opener = gzip.open if suffix == ".gz" else open
    encoding = "utf-8" if suffix == ".gz" else detect_encoding(path)
    try:
        with opener(path, "rt", encoding=encoding, errors="replace", newline="") as handle:  # type: ignore[arg-type]
            for index, line in enumerate(handle):
                if limit is not None and index >= limit:
                    return
                yield line
    except (OSError, EOFError, UnicodeError):
        return


def _read_evtx(path: Path, limit: int | None = None) -> Iterator[str]:
    if evtx_module is None:  # pragma: no cover
        return
    try:
        with evtx_module.Evtx(str(path)) as log:
            for index, record in enumerate(log.records()):
                if limit is not None and index >= limit:
                    return
                try:
                    yield record.xml().replace("\n", " ") + "\n"
                except Exception:
                    continue
    except Exception:  # pragma: no cover - corrupted evidence should not stop a hunt
        return


def sample_lines(path: Path, count: int = 40) -> list[str]:
    return [line for line in read_lines(path, limit=count)]
