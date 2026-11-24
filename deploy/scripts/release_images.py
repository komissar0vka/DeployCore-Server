"""Read the two pinned GHCR images in a DeployCore Server release."""
import json
import re
import sys
from pathlib import Path

IMAGES = {
    "server": "ghcr.io/komissar0vka/deploycore-server-backend",
    "web": "ghcr.io/komissar0vka/deploycore-server-web",
}


def read_images(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or set(data) != set(IMAGES):
        raise ValueError("A Server release must specify exactly two container images")
    for service, repository in IMAGES.items():
        image = data[service]
        if not isinstance(image, str) or not re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", image):
            raise ValueError(f"The {service} image must be from the release registry and pinned by SHA-256")
    return data


if __name__ == "__main__":
    images = read_images(Path(sys.argv[1]))
    print(json.dumps({"services": {service: {"image": image} for service, image in images.items()}}))
