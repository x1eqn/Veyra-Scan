from __future__ import annotations

from pathlib import Path
import zipfile

from xien_control.file_classifier import classify_file


def test_file_classifier_covers_application_static_types():
    cases = {
        "client.jar": "JAVA_ARCHIVE",
        "client.jar.disabled": "JAVA_ARCHIVE",
        "tool.exe": "PE_EXE",
        "lib.dll": "PE_DLL",
        "screen.scr": "PE_SCR",
        "panel.cpl": "PE_CPL",
        "driver.sys": "PE_SYS",
        "plugin.ocx": "PE_OCX",
        "setup.msi": "INSTALLER_MSI",
        "package.msix": "INSTALLER_MSIX",
        "bundle.appxbundle": "INSTALLER_APPXBUNDLE",
        "run.ps1": "SCRIPT_PS1",
        "launch.cmd": "SCRIPT_CMD",
        "shortcut.lnk": "SHORTCUT_LNK",
        "site.url": "SHORTCUT_URL",
        "archive.zip": "ARCHIVE_ZIP",
        "archive.rar": "ARCHIVE_RAR",
        "notes.txt": "UNKNOWN",
    }

    for name, expected in cases.items():
        assert classify_file(Path(name)) == expected


def test_zip_with_java_structure_is_classified_as_java_archive(tmp_path):
    archive = tmp_path / "renamed_mod.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("fabric.mod.json", "{}")
        zf.writestr("com/example/Client.class", b"\xca\xfe\xba\xbe")

    assert classify_file(archive) == "JAVA_ARCHIVE"
