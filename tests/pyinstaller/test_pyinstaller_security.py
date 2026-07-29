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


def test_carchive_does_not_replace_existing_file(tmp_path) -> None:
    """A CArchive entry cannot replace a preexisting output file."""
    payload = b"replacement"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.output_dir.mkdir()
    victim = archive.output_dir / "victim"
    victim.write_bytes(b"original")
    archive.kwargs = {}
    archive.toc = [
        CArchive.CTOCEntry(
            entry_offset=0,
            compressed_data_size=len(payload),
            uncompressed_data_size=len(payload),
            compression_flag=False,
            type_code=CArchive.ArchiveItem.DATA.value,
            name="victim",
        )
    ]

    archive.extract_files()

    assert victim.read_bytes() == b"original"


def test_zlibarchive_does_not_replace_existing_file(tmp_path, monkeypatch) -> None:
    """A PYZ entry cannot replace a preexisting output file."""
    payload = zlib.compress(b"replacement")
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.output_dir.mkdir()
    victim = archive.output_dir / "victim.pyc"
    victim.write_bytes(b"original")
    archive.magic_int = 0
    archive.encrypted = False
    archive.kwargs = {}
    archive.toc = {"victim": (ZlibArchive.ArchiveItem.MODULE.value, 0, len(payload))}
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")

    archive.extract_files()

    assert victim.read_bytes() == b"original"


def test_carchive_path_shape_collision_does_not_abort_later_entries(tmp_path) -> None:
    """A file/directory collision skips one member without suppressing later output."""
    payload = b"abc"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {}
    archive.toc = [
        CArchive.CTOCEntry(0, 1, 1, False, CArchive.ArchiveItem.DATA.value, "node"),
        CArchive.CTOCEntry(1, 1, 1, False, CArchive.ArchiveItem.DATA.value, "node/child"),
        CArchive.CTOCEntry(2, 1, 1, False, CArchive.ArchiveItem.DATA.value, "final"),
    ]

    archive.extract_files()

    assert (archive.output_dir / "node").read_bytes() == b"a"
    assert (archive.output_dir / "final").read_bytes() == b"c"


def test_nested_carchives_use_distinct_output_directories(tmp_path, monkeypatch) -> None:
    """Distinct nested archive names cannot merge into one output directory."""
    payload = b"ab"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = payload
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {}
    archive.toc = [
        CArchive.CTOCEntry(0, 1, 1, False, CArchive.ArchiveItem.PYZ.value, "foo.one.pyz"),
        CArchive.CTOCEntry(1, 1, 1, False, CArchive.ArchiveItem.PYZ.value, "foo.two.pyz"),
    ]
    nested_outputs = []
    monkeypatch.setattr(
        pydecipher,
        "unpack",
        lambda path, output_dir, **kwargs: nested_outputs.append(output_dir),
    )

    archive.extract_files()

    assert len(nested_outputs) == 2
    assert nested_outputs[0] != nested_outputs[1]
    assert all(path.parent == archive.output_dir for path in nested_outputs)


def test_zlibarchive_rejects_symlinked_key_file(tmp_path, monkeypatch) -> None:
    """Ambient key discovery cannot read a symlink target outside the archive directory."""
    archive_path = tmp_path / "archive.pyz"
    outside_file = tmp_path / "outside"
    outside_file.write_bytes(b"A" * 64)
    (tmp_path / "pyimod00_crypto_key.pyc").symlink_to(outside_file)
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_path = archive_path
    archive.encrypted = False
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("symlinked key file was read")

    monkeypatch.setattr("pydecipher.artifact_types.pyinstaller.disassemble_file", fail_if_called)

    archive.check_for_password_file()

    assert archive.encrypted is False
    assert called is False
