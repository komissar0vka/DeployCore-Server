import pytest

from deploycore.package_metadata import exe_template


@pytest.mark.parametrize(("marker", "properties", "family", "arguments"), [
    (b"Inno Setup Setup Data", {}, "inno", ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]),
    (b"\xef\xbe\xad\xdeNullsoftInst", {}, "nsis", ["/S"]),
    (b"", {"Comments": "InstallShield launcher"}, "installshield", []),
    (b"", {"Comments": "InstallShield Basic MSI"}, "installshield_basic_msi", ["/s", '/v"/qn /norestart"']),
    (b"portable", {"ProductName": "WinScan2PDF"}, None, []),
])
def test_only_recognized_exe_families_get_silent_arguments(tmp_path, marker, properties, family, arguments):
    fixture = tmp_path / "fixture.exe"
    fixture.write_bytes(marker)
    assert exe_template(fixture, properties) == (family, arguments)
