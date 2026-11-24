import pytest
from pydantic import ValidationError

from deploycore.package_schemas import VersionInput


def version(**changes):
    return VersionInput.model_validate({
        "version": "1.0", "architecture":"x86", "installer":"portable",
        "install_args":[], "uninstall_args":[],
        "detection":{"kind":"portable_file","folder":"WinScan2PDF","shortcut":True},
        **changes,
    })


def test_portable_is_a_file_operation():
    assert version().detection.folder == "WinScan2PDF"
    with pytest.raises(ValidationError):
        version(install_args=["/s"])
    with pytest.raises(ValidationError):
        version(installer="exe")


@pytest.mark.parametrize("folder", ["../Windows", "CON", "a/b", "D:\\Program Files", "name."])
def test_portable_rejects_unsafe_destination(folder):
    with pytest.raises(ValidationError):
        version(detection={"kind":"portable_file","folder":folder})
