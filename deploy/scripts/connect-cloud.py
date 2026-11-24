#!/usr/bin/env python3
"""Configure outbound Cloud licensing on an installed client host."""
import argparse
import getpass
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("origin")
parser.add_argument("license_key")
parser.add_argument("release_key")
parser.add_argument("--ca", type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
compose = ["docker", "compose", "--env-file", "deploy/.env", "-f", "deploy/compose.yaml"]
settings = dict(origin=args.origin, license_key=args.license_key, release_key=args.release_key,
                token=getpass.getpass("Cloud activation token: "), ca=args.ca.read_text() if args.ca else None)
subprocess.run([*compose, "exec", "-T", "server", "python", "-m", "deploycore.cloud_link"],
               cwd=root, input=json.dumps(settings), text=True, check=True)
subprocess.run([*compose, "restart", "server"], cwd=root, check=True)
