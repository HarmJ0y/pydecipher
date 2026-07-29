# -*- coding: utf-8 -*-
"""Regression tests for malformed untrusted artifacts."""

import io
import struct

from pydecipher import utils
from pydecipher.artifact_types.pyinstaller import CArchive
from pydecipher.artifact_types.pyinstaller import ZlibArchive


def test_utf16_version_at_end_of_data_does_not_crash() -> None:
    """Version context scanning stays inside decoded string boundaries."""
    data = "3.12".encode("utf-16")

    assert utils.parse_for_version_strings(data) == [("3.12", "3.12")]


def test_truncated_carchive_toc_does_not_crash(tmp_path) -> None:
    """A CArchive that validates structurally cannot crash on a short TOC."""
    archive_bytes = b"X" + struct.pack("!8siiii", CArchive.MAGIC, 25, 0, 1, 36)
    archive = CArchive(io.BytesIO(archive_bytes), output_dir=tmp_path / "output")

    archive.unpack()

    assert archive.toc == []
    assert not archive.output_dir.exists()


def test_short_pyz_header_is_rejected(tmp_path) -> None:
    """The PYZ magic alone is insufficient to validate an archive."""
    try:
        ZlibArchive(io.BytesIO(b"PYZ\0"), output_dir=tmp_path / "output")
    except TypeError:
        pass
    else:
        raise AssertionError("short PYZ header was accepted")


def test_empty_carchive_source_entry_is_skipped(tmp_path) -> None:
    """An empty source member cannot crash extraction."""
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = b""
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {}
    archive.toc = [
        CArchive.CTOCEntry(
            entry_offset=0,
            compressed_data_size=0,
            uncompressed_data_size=0,
            compression_flag=False,
            type_code=CArchive.ArchiveItem.PYSOURCE.value,
            name="empty",
        )
    ]

    archive.extract_files()

    assert not archive.output_dir.exists()
