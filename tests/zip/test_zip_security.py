# -*- coding: utf-8 -*-
"""Security regression tests for ZIP extraction."""

import io
import zipfile

import pytest

from pydecipher.artifact_types.zip import ZipFile


def _zip_bytes(member_name, payload=b"attacker-controlled"):
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member_name, payload)
    return archive_bytes.getvalue()


def test_zip_extraction_rejects_symlink_escape(tmp_path) -> None:
    """An existing symlink cannot redirect a ZIP member outside output."""
    output_dir = tmp_path / "output"
    outside_dir = tmp_path / "outside"
    output_dir.mkdir()
    outside_dir.mkdir()
    (output_dir / "linked").symlink_to(outside_dir, target_is_directory=True)
    artifact = ZipFile(io.BytesIO(_zip_bytes("linked/escaped")), output_dir=output_dir)

    artifact.unpack()

    assert not (outside_dir / "escaped").exists()


@pytest.mark.parametrize("member_name", ["../escaped", r"..\escaped"])
def test_zip_extraction_rejects_parent_traversal(tmp_path, member_name) -> None:
    """ZIP traversal names are skipped rather than rewritten."""
    output_dir = tmp_path / "output"
    artifact = ZipFile(io.BytesIO(_zip_bytes(member_name)), output_dir=output_dir)

    artifact.unpack()

    assert not (tmp_path / "escaped").exists()
    assert not (output_dir / "escaped").exists()


def test_zip_extraction_enforces_member_size_limit(tmp_path) -> None:
    """A ZIP member cannot expand beyond the configured size budget."""
    output_dir = tmp_path / "output"
    artifact = ZipFile(
        io.BytesIO(_zip_bytes("bomb", b"0" * 2048)),
        output_dir=output_dir,
        max_member_size=1024,
    )

    artifact.unpack()

    assert not (output_dir / "bomb").exists()


def test_zip_extraction_enforces_total_size_limit(tmp_path, monkeypatch) -> None:
    """The aggregate budget applies across members in the extraction tree."""
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("first", b"0" * 700)
        archive.writestr("second", b"0" * 700)
    output_dir = tmp_path / "output"
    artifact = ZipFile(
        io.BytesIO(archive_bytes.getvalue()),
        output_dir=output_dir,
        max_total_size=1000,
    )
    monkeypatch.setattr("pydecipher.unpack", lambda *args, **kwargs: None)

    artifact.unpack()

    assert (output_dir / "first").stat().st_size == 700
    assert not (output_dir / "second").exists()


def test_zip_extraction_does_not_replace_existing_file(tmp_path, monkeypatch) -> None:
    """A ZIP member cannot replace a preexisting output file."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    victim = output_dir / "victim"
    victim.write_bytes(b"original")
    artifact = ZipFile(io.BytesIO(_zip_bytes("victim", b"replacement")), output_dir=output_dir)
    monkeypatch.setattr("pydecipher.unpack", lambda *args, **kwargs: None)

    artifact.unpack()

    assert victim.read_bytes() == b"original"


def test_zip_recurses_only_into_files_extracted_by_current_run(tmp_path, monkeypatch) -> None:
    """Stale files and file symlinks in a reused output directory are ignored."""
    output_dir = tmp_path / "output"
    outside_file = tmp_path / "outside.pyc"
    output_dir.mkdir()
    (output_dir / "stale.pyc").write_bytes(b"stale")
    outside_file.write_bytes(b"outside")
    (output_dir / "linked.pyc").symlink_to(outside_file)
    unpacked = []
    monkeypatch.setattr("pydecipher.unpack", lambda path, **kwargs: unpacked.append(path))
    artifact = ZipFile(io.BytesIO(_zip_bytes("fresh.pyc", b"fresh")), output_dir=output_dir)

    artifact.unpack()

    assert unpacked == [output_dir / "fresh.pyc"]


def test_zip_does_not_create_output_through_symlinked_parent(tmp_path, monkeypatch) -> None:
    """ZIP setup cannot create directories through an output-parent symlink."""
    safe_dir = tmp_path / "safe"
    outside_dir = tmp_path / "outside"
    safe_dir.mkdir()
    outside_dir.mkdir()
    (safe_dir / "linked").symlink_to(outside_dir, target_is_directory=True)
    monkeypatch.setattr("pydecipher.unpack", lambda *args, **kwargs: None)
    artifact = ZipFile(
        io.BytesIO(_zip_bytes("member", b"payload")),
        output_dir=safe_dir / "linked" / "new-output",
    )

    artifact.unpack()

    assert not (outside_dir / "new-output").exists()
