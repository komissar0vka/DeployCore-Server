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


def load_embedded_images(deploy: Path) -> dict[str, str]:
    import subprocess

    references = json.loads((deploy / "release-image-ids.json").read_text())
    if not isinstance(references, dict) or set(references) != set(IMAGES):
        raise ValueError("Invalid embedded image inventory")
    for image in references.values():
        if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("Embedded image identity must be a SHA-256 digest")
    subprocess.run(["docker", "load", "--input", str(deploy / "release-images.tar.gz")], check=True, stdout=sys.stderr)
    images = {}
    for service, expected in references.items():
        actual = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", expected], text=True).strip()
        if actual != expected:
            raise ValueError("Loaded image does not match the embedded release inventory")
        tag = f"deploycore-embedded-{service}:{expected.removeprefix('sha256:')}"
        subprocess.run(["docker", "tag", expected, tag], check=True)
        images[service] = tag
    return images


if __name__ == "__main__":
    path = Path(sys.argv[1])
    images = load_embedded_images(path.parent) if len(sys.argv) == 3 and sys.argv[2] == "--embedded" else read_images(path)
    print(json.dumps({"services": {service: {"image": image} for service, image in images.items()}}))
