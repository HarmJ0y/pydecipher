# -*- coding: utf-8 -*-
"""Security regression tests for the PyInstaller artifact types."""

import zlib

import pytest

import pydecipher
from pydecipher.artifact_types.pyinstaller import CArchive
from pydecipher.artifact_types.pyinstaller import ZlibArchive
from pydecipher.artifact_types.pyinstaller import _safe_output_path


@pytest.mark.parametrize(
    "member_name",
    [
        "/absolute",
        r"\rooted",
        r"C:\absolute",
        r"C:drive-relative",
        "//server/share",
        "../escaped",
        "nested/../../escaped",
        r"..\escaped",
        r"nested\..\..\escaped",
    ],
)
def test_safe_output_path_rejects_escaping_names(tmp_path, member_name) -> None:
    """Archive names cannot be absolute or contain parent traversal."""
    with pytest.raises(ValueError):
        _safe_output_path(tmp_path / "output", member_name)


@pytest.mark.parametrize("member_name", ["nested/file", r"nested\file"])
def test_safe_output_path_accepts_nested_names(tmp_path, member_name) -> None:
    """Both archive path separator styles remain supported."""
    output_dir = tmp_path / "output"

    assert _safe_output_path(output_dir, member_name) == output_dir / "nested" / "file"


def test_safe_output_path_rejects_symlink_escape(tmp_path) -> None:
    """An existing symlink cannot redirect extraction outside the output root."""
    output_dir = tmp_path / "output"
    outside_dir = tmp_path / "outside"
    output_dir.mkdir()
    outside_dir.mkdir()
    (output_dir / "linked").symlink_to(outside_dir, target_is_directory=True)

    with pytest.raises(ValueError):
        _safe_output_path(output_dir, "linked/escaped")


def test_safe_output_path_checks_suffixed_destination(tmp_path) -> None:
    """Containment is checked after a generated file suffix is applied."""
    output_dir = tmp_path / "output"
    outside_file = tmp_path / "outside"
    output_dir.mkdir()
    outside_file.touch()
    (output_dir / "module.pyc").symlink_to(outside_file)

    with pytest.raises(ValueError):
        _safe_output_path(output_dir, "module", suffix=".pyc")


@pytest.mark.parametrize("member_name", ["../escaped", r"..\escaped"])
def test_carchive_skips_traversal_entries(tmp_path, member_name) -> None:
    """CArchive extraction does not write traversal entries."""
    payload = b"attacker-controlled"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.toc = [
        CArchive.CTOCEntry(
            entry_offset=0,
            compressed_data_size=len(payload),
            uncompressed_data_size=len(payload),
            compression_flag=False,
            type_code=CArchive.ArchiveItem.DATA.value,
            name=member_name,
        )
    ]

    archive.extract_files()

    assert not (tmp_path / "escaped").exists()
    assert not archive.output_dir.exists()


@pytest.mark.parametrize("member_name", ["../escaped", r"..\escaped"])
def test_zlibarchive_skips_traversal_entries(tmp_path, monkeypatch, member_name) -> None:
    """PYZ extraction does not write traversal keys."""
    payload = zlib.compress(b"attacker-controlled")
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = False
    archive.toc = {member_name: (ZlibArchive.ArchiveItem.MODULE.value, 0, len(payload))}
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")

    archive.extract_files()

    assert not (tmp_path / "escaped.pyc").exists()
    assert not archive.output_dir.exists()


def test_carchive_rejects_decompression_bomb(tmp_path) -> None:
    """CArchive extraction enforces the configured member-size limit."""
    payload = zlib.compress(b"0" * 2048)
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {"max_member_size": 1024}
    archive.toc = [
        CArchive.CTOCEntry(
            entry_offset=0,
            compressed_data_size=len(payload),
            uncompressed_data_size=2048,
            compression_flag=True,
            type_code=CArchive.ArchiveItem.DATA.value,
            name="bomb",
        )
    ]

    archive.extract_files()

    assert not (archive.output_dir / "bomb").exists()


def test_zlibarchive_rejects_decompression_bomb(tmp_path, monkeypatch) -> None:
    """PYZ extraction enforces the configured member-size limit."""
    payload = zlib.compress(b"0" * 2048)
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = False
    archive.kwargs = {"max_member_size": 1024}
    archive.toc = {"bomb": (ZlibArchive.ArchiveItem.MODULE.value, 0, len(payload))}
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")

    archive.extract_files()

    assert not (archive.output_dir / "bomb.pyc").exists()
