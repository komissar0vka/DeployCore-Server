import importlib.util
import io
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("update_server", ROOT / "deploy/scripts/update-server.py")
updater = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(updater)


def add_file(bundle, filename, content, mode=0o644):
    member = tarfile.TarInfo(filename)
    member.size = len(content)
    member.mode = mode
    bundle.addfile(member, io.BytesIO(content))


def test_release_extract_preserves_executable_scripts(tmp_path):
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for filename in sorted(updater.FILES):
            content = (ROOT / filename).read_bytes()
            add_file(bundle, filename, content, 0o755 if filename.endswith(".sh") else 0o644)
    target = tmp_path / "release"
    updater.extract(archive, target)
    assert (target / "install.sh").stat().st_mode & 0o111 == 0o111
    assert (target / "apps/server/Dockerfile").stat().st_mode & 0o004
    assert (target / "apps/server").stat().st_mode & 0o001


def test_release_extract_rejects_traversal(tmp_path):
    archive = tmp_path / "release.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        add_file(bundle, "../escape", b"invalid")
    with pytest.raises(ValueError, match="Unsafe archive entry"):
        updater.extract(archive, tmp_path / "release")
    assert not (tmp_path / "escape").exists()
