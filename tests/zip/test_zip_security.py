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
