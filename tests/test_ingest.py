"""Archive handling, including the protections against hostile archives."""

from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.engine.ingest import collect_log_files, extract_archive, read_lines, sample_lines

LIMIT = 50 * 1024 * 1024


def make_zip(path: Path, files: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return path


class TestExtraction:
    def test_zip_archive(self, tmp_path):
        archive = make_zip(tmp_path / "evidence.zip", {"logs/auth.log": "line one\n", "logs/app.json": '{"a":1}\n'})
        result = extract_archive(archive, tmp_path / "out", LIMIT)
        assert result.archive_type == "zip"
        assert len(result.files) == 2

    def test_tar_gz_archive(self, tmp_path):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = b"hello\n"
            info = tarfile.TarInfo("logs/app.log")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        target = tmp_path / "evidence.tar.gz"
        target.write_bytes(buffer.getvalue())
        result = extract_archive(target, tmp_path / "out", LIMIT)
        assert result.archive_type == "tar"
        assert result.files[0].read_text() == "hello\n"

    def test_single_gzip_file(self, tmp_path):
        target = tmp_path / "auth.log.gz"
        with gzip.open(target, "wt") as handle:
            handle.write("Mar 11 08:15:22 host sshd[1]: Failed password\n")
        result = extract_archive(target, tmp_path / "out", LIMIT)
        assert result.archive_type == "gzip"
        assert result.files[0].name == "auth.log"

    def test_plain_file_upload(self, tmp_path):
        target = tmp_path / "single.log"
        target.write_text("one line\n")
        result = extract_archive(target, tmp_path / "out", LIMIT)
        assert result.archive_type == "file"
        assert len(result.files) == 1

    def test_path_traversal_is_rejected(self, tmp_path):
        archive = tmp_path / "evil.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../../escape.log", "malicious\n")
            handle.writestr("safe.log", "fine\n")
        result = extract_archive(archive, tmp_path / "out", LIMIT)
        assert any("unsafe path" in note for note in result.skipped)
        assert not (tmp_path.parent / "escape.log").exists()
        assert len(result.files) == 1

    def test_size_limit_stops_extraction(self, tmp_path):
        archive = make_zip(tmp_path / "big.zip", {f"file{index}.log": "x" * 5000 for index in range(10)})
        result = extract_archive(archive, tmp_path / "out", 12000)
        assert result.warnings
        assert len(result.files) < 10


class TestCollection:
    def test_binary_files_are_skipped(self, tmp_path):
        root = tmp_path / "tree"
        (root / "sub").mkdir(parents=True)
        (root / "sub" / "app.log").write_text("a log line\n")
        (root / "sub" / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
        (root / "sub" / "tool.exe").write_bytes(b"MZ" + b"\x00" * 64)
        files, skipped = collect_log_files(root)
        assert [file.name for file in files] == ["app.log"]
        assert len(skipped) == 2

    def test_empty_files_are_skipped(self, tmp_path):
        root = tmp_path / "tree"
        root.mkdir()
        (root / "empty.log").write_text("")
        files, skipped = collect_log_files(root)
        assert files == []
        assert any("empty" in note for note in skipped)

    def test_macos_metadata_is_ignored(self, tmp_path):
        root = tmp_path / "tree"
        (root / "__MACOSX").mkdir(parents=True)
        (root / "__MACOSX" / "junk.log").write_text("noise\n")
        (root / "real.log").write_text("data\n")
        files, _ = collect_log_files(root)
        assert [file.name for file in files] == ["real.log"]


class TestReading:
    def test_utf16_is_decoded(self, tmp_path):
        target = tmp_path / "utf16.log"
        target.write_bytes("héllo wörld\n".encode("utf-16"))
        assert "héllo" in "".join(read_lines(target))

    def test_gzip_is_read_transparently(self, tmp_path):
        target = tmp_path / "app.log.gz"
        with gzip.open(target, "wt") as handle:
            handle.write("compressed line\n")
        assert list(read_lines(target)) == ["compressed line\n"]

    def test_sampling_is_bounded(self, tmp_path):
        target = tmp_path / "big.log"
        target.write_text("\n".join(f"line {index}" for index in range(1000)))
        assert len(sample_lines(target, 25)) == 25

    def test_missing_file_yields_nothing(self, tmp_path):
        assert list(read_lines(tmp_path / "absent.log")) == []
