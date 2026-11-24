"""Read installer metadata from disk without running its executable."""
from pathlib import Path
from uuid import UUID

import pefile

from . import package_storage as storage


def normalized(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    return "".join(ch for ch in value if ch.isprintable()).strip()[:limit] or None


def msi_properties(path: Path) -> dict[str, str]:
    result = storage.tool(["msiinfo", "export", str(path), "Property"])
    if result.returncode:
        return {}
    return dict(line.split("\t", 1) for line in result.stdout.splitlines()[3:] if "\t" in line)


def pe_properties(path: Path) -> dict[str, str]:
    try:
        binary = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError:
        return {}
    try:
        resource_index = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
        directories = binary.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= resource_index or directories[resource_index].Size > 4 * 1024 * 1024:
            return {}
        binary.parse_data_directories(directories=[resource_index])
        result = {}
        for entries in getattr(binary, "FileInfo", []):
            for entry in entries:
                for table in getattr(entry, "StringTable", []):
                    for key, value in table.entries.items():
                        result.setdefault(key.decode("utf-8", "replace"), value.decode("utf-8", "replace"))
        return result
    except pefile.PEFormatError:
        return {}
    finally:
        binary.close()


def exe_template(path: Path, properties: dict[str, str]) -> tuple[str | None, list[str]]:
    # Expose suggestions for review. Vendor strings are metadata and carry no trust.
    metadata = "\n".join(properties.values()).casefold()
    with path.open("rb") as executable:
        length = path.stat().st_size
        sample = executable.read(1024 * 1024)
        if length > len(sample):
            executable.seek(max(len(sample), length - 1024 * 1024))
            sample += executable.read(1024 * 1024)
    if b"Inno Setup Setup Data" in sample or "inno setup" in metadata:
        return "inno", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]
    if b"\xef\xbe\xad\xdeNullsoftInst" in sample or "nullsoft install system" in metadata:
        return "nsis", ["/S"]
    if "installshield" in metadata:
        if "basic msi" in metadata:
            return "installshield_basic_msi", ["/s", '/v"/qn /norestart"']
        return "installshield", []
    return None, []


def suggest(path: Path, installer: str) -> dict:
    if installer == "exe":
        data = pe_properties(path)
        family, args = exe_template(path, data)
        return {
            "family": family, "install_args": args,
            "name": normalized(data.get("ProductName") or data.get("FileDescription"), 160),
            "version": normalized(data.get("ProductVersion") or data.get("FileVersion"), 80),
            "publisher": normalized(data.get("CompanyName"), 160),
        }
    data = msi_properties(path)
    code = data.get("ProductCode")
    try:
        product_code = str(UUID(code)) if code else None
    except ValueError:
        product_code = None
    return {
        "name": normalized(data.get("ProductName"), 160),
        "version": normalized(data.get("ProductVersion"), 80),
        "publisher": normalized(data.get("Manufacturer"), 160),
        "product_code": product_code,
        "install_args": ["/qn", "/norestart"],
        "uninstall_args": ["/qn", "/norestart"] if product_code else None,
    }
