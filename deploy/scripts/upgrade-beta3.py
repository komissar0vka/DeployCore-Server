"""Bootstrap an image-based update using the installed beta.3 trust policy."""
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        sys.exit("Usage: sudo python3 upgrade-beta3.py /absolute/path/to/deploycore-server")
    root = Path(sys.argv[1]).resolve()
    local = root / "deploy/scripts/update-server.py"
    if not local.is_file():
        sys.exit("The existing DeployCore updater was not found")
    sys.path.insert(0, str(local.parent))
    spec = importlib.util.spec_from_file_location("installed_updater", local)
    installed = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installed)

    version = "1.0.0-beta.4"
    target = installed.release_plan("beta", version)
    if target is None:
        sys.exit("No trusted signed beta.4 release is available from the configured Cloud")

    with TemporaryDirectory(prefix="deploycore-upgrade-") as directory:
        staging = Path(directory)
        archive = staging / "release.tar.gz"
        source = staging / "source"
        installed.download(target, archive)
        installed.extract(archive, source)
        subprocess.run([sys.executable, str(source / "deploy/scripts/update-server.py"), "beta", version],
                       env={**os.environ, "DEPLOYCORE_INSTALL_ROOT": str(root)}, check=True)
        for name in ("update-server.py", "release_images.py", "operations.py", "enable-operations.sh"):
            target = local.parent / name
            temporary = target.with_suffix(".upgrade")
            shutil.copyfile(source / "deploy/scripts" / name, temporary)
            temporary.chmod(0o700)
            temporary.replace(target)
        if Path("/run/systemd/system").is_dir() and not (root / "deploy/.operations/compose.json").exists():
            subprocess.run([str(local.parent / "enable-operations.sh")], check=True)


if __name__ == "__main__":
    main()
