"""The application must start from a clean checkout.

A working tree accumulates directories and files that were never committed, so
the application can depend on something a new user will not have. That is
exactly what happened: web/assets was an empty directory, git does not track
empty directories, and the application refused to start on a fresh clone while
working perfectly here.

These tests build a tree from the tracked files alone and start the application
in it, which is the only way to see what a new user actually gets.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


SMOKE_HUNT = """
import tempfile
import zipfile
from pathlib import Path

from app.engine.catalog import get_hypothesis
from app.engine.runner import run_hunt

lines = []
for index in range(40):
    lines.append(
        "Mar 11 08:15:22 srv-01 sshd[" + str(1000 + index) + "]: Failed password "
        "for root from 91.240.118.172 port 22 ssh2"
    )
archive = Path(tempfile.mkdtemp()) / "evidence.zip"
with zipfile.ZipFile(archive, "w") as handle:
    handle.writestr("auth.log", chr(10).join(lines))

outcome = run_hunt(archive, Path(tempfile.mkdtemp()), get_hypothesis("tech-brute-force"))
assert outcome.events_parsed == 40, outcome.events_parsed
assert outcome.findings, "no detection fired on a clean checkout"
print("ok")
"""


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        pytest.skip("not a git checkout")
    return [line for line in result.stdout.splitlines() if line.strip()]


@pytest.fixture(scope="module")
def checkout(tmp_path_factory) -> Path:
    """A tree containing only what git would hand a new user."""
    files = tracked_files()
    if not files:
        pytest.skip("no tracked files")
    destination = tmp_path_factory.mktemp("checkout")
    for relative in files:
        source = ROOT / relative
        if not source.is_file():
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


def run_in(checkout: Path, code: str, **env_extra) -> subprocess.CompletedProcess:
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = str(checkout)
    env["THF_DATA_DIR"] = str(checkout / "runtime-data")
    env["THF_DATABASE_URL"] = f"sqlite:///{checkout / 'runtime-data' / 'fresh.db'}"
    env["THF_SEED_DEMO"] = "0"
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-c", code], cwd=checkout, capture_output=True, text=True, env=env, timeout=180
    )


class TestFreshCheckout:
    def test_the_application_imports(self, checkout):
        result = run_in(checkout, "from app.main import app; print('ok')")
        assert result.returncode == 0, (
            f"the application does not import from a clean checkout:\n{result.stderr[-2000:]}"
        )

    def test_the_application_starts_and_serves(self, checkout):
        """Start it the way a new user does and make a request."""
        code = (
            "from fastapi.testclient import TestClient\n"
            "from app.main import app\n"
            "with TestClient(app) as client:\n"
            "    assert client.get('/api/health').status_code == 200\n"
            "    assert client.get('/').status_code == 200\n"
            "    assert client.get('/css/theme.css').status_code == 200\n"
            "    assert client.get('/js/app.js').status_code == 200\n"
            "print('ok')\n"
        )
        result = run_in(checkout, code)
        assert result.returncode == 0, (
            f"the application does not serve from a clean checkout:\n{result.stderr[-2000:]}"
        )

    def test_a_hunt_runs_end_to_end(self, checkout):
        """The engine has to work with only the committed files present."""
        script = checkout / "_smoke_hunt.py"
        script.write_text(SMOKE_HUNT)
        result = run_in(checkout, "exec(open('_smoke_hunt.py').read())")
        assert result.returncode == 0, (
            f"a hunt does not run from a clean checkout:\n{result.stderr[-2000:]}"
        )

    def test_the_sample_generator_runs(self, checkout):
        """It is the first thing the README tells a new user to try."""
        result = run_in(
            checkout,
            "import sys; sys.argv = ['gen', str(__import__('pathlib').Path('sample.zip'))]\n"
            "exec(open('tools/generate_sample_evidence.py').read())\n",
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert (checkout / "sample.zip").exists()


class TestNoUntrackedDependencies:
    def test_every_directory_the_interface_needs_is_present_or_created(self, checkout):
        """Serving must not depend on a directory that was never committed."""
        for name in ("css", "js"):
            assert (checkout / "web" / name).is_dir(), f"web/{name} is missing from the checkout"
        # assets may legitimately be empty, so the application creates it.
        result = run_in(checkout, "from app.main import app\nprint((__import__('pathlib').Path('web/assets')).is_dir())")
        assert result.returncode == 0 and "True" in result.stdout

    def test_the_working_tree_has_no_untracked_empty_directories(self):
        """An empty directory here is invisible to git and breaks a new clone."""
        import os

        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [
                name for name in dirnames
                if name not in {".git", ".venv", "__pycache__", ".pytest_cache", "data", "node_modules"}
            ]
            if filenames:
                continue
            if dirnames:
                continue
            relative = Path(dirpath).relative_to(ROOT)
            if str(relative) == ".":
                continue
            offenders.append(str(relative))
        assert not offenders, (
            f"these directories are empty, so git will not carry them to a new clone: {offenders}. "
            f"Add a tracked placeholder or create them at runtime."
        )
