# -*- coding: utf-8 -*-
"""Acceptance tests for confirmed, not-yet-patched ZIP findings."""

import io
import struct
import zipfile

import pytest

from pydecipher.artifact_types.zip import ZipFile


def _known_vulnerability(finding: str):
    return pytest.mark.xfail(
        strict=True,
        reason=f"{finding} is confirmed and awaiting remediation",
    )


def _two_member_zip() -> bytes:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("bad", b"bad")
        archive.writestr("good", b"good")
    return archive_bytes.getvalue()


def _patch_first_member_compression(archive_bytes: bytes, method: int) -> bytes:
    patched = bytearray(archive_bytes)
    local_header = patched.index(b"PK\x03\x04")
    central_header = patched.index(b"PK\x01\x02")
    struct.pack_into("<H", patched, local_header + 8, method)
    struct.pack_into("<H", patched, central_header + 10, method)
    return bytes(patched)


def _corrupt_first_member_crc(archive_bytes: bytes) -> bytes:
    patched = bytearray(archive_bytes)
    local_header = patched.index(b"PK\x03\x04")
    central_header = patched.index(b"PK\x01\x02")
    struct.pack_into("<I", patched, local_header + 14, 0)
    struct.pack_into("<I", patched, central_header + 16, 0)
    return bytes(patched)


def test_unsupported_zip_member_is_skipped_and_later_member_extracts(
    tmp_path,
    monkeypatch,
) -> None:
    """Unsupported compression is isolated to the malformed member."""
    archive_bytes = _patch_first_member_compression(_two_member_zip(), 99)
    output_dir = tmp_path / "output"
    monkeypatch.setattr("pydecipher.unpack", lambda *args, **kwargs: None)
    artifact = ZipFile(io.BytesIO(archive_bytes), output_dir=output_dir)

    artifact.unpack()

    assert not (output_dir / "bad").exists()
    assert (output_dir / "good").read_bytes() == b"good"


def test_zip_crc_error_is_skipped_and_later_member_extracts(
    tmp_path,
    monkeypatch,
) -> None:
    """A corrupt early member cannot hide valid members that follow it."""
    archive_bytes = _corrupt_first_member_crc(_two_member_zip())
    output_dir = tmp_path / "output"
    monkeypatch.setattr("pydecipher.unpack", lambda *args, **kwargs: None)
    artifact = ZipFile(io.BytesIO(archive_bytes), output_dir=output_dir)

    artifact.unpack()

    assert not (output_dir / "bad").exists()
    assert (output_dir / "good").read_bytes() == b"good"
