# -*- coding: utf-8 -*-
"""Acceptance tests for confirmed, not-yet-patched PyInstaller findings."""

import io
import struct
import zlib

import pytest
import xdis

import pydecipher
from pydecipher import utils
from pydecipher.artifact_types.pe import PortableExecutable
from pydecipher.artifact_types.pyc import Pyc
from pydecipher.artifact_types.pyinstaller import CArchive
from pydecipher.artifact_types.pyinstaller import ZlibArchive
from pydecipher.artifact_types.zip import ZipFile


def _known_vulnerability(finding: str):
    return pytest.mark.xfail(
        strict=True,
        reason=f"{finding} is confirmed and awaiting remediation",
    )


class _TrackingBytesIO(io.BytesIO):
    bytes_read = 0

    def read(self, size=-1):
        data = super().read(size)
        self.bytes_read += len(data)
        return data


@pytest.mark.parametrize(
    "artifact_type",
    [PortableExecutable, CArchive, ZlibArchive, ZipFile],
)
def test_artifact_size_limit_is_checked_before_whole_file_read(
    tmp_path,
    artifact_type,
) -> None:
    """Hostile inputs are rejected before constructors buffer the whole file."""
    stream = _TrackingBytesIO(b"X" * (64 * 1024))

    with pytest.raises(utils.ExtractionLimitError):
        artifact_type(
            stream,
            output_dir=tmp_path / "output",
            max_input_size=1024,
        )

    assert stream.bytes_read <= 1025


class _SliceTrackingBytes(bytes):
    copied_bytes = 0

    def __getitem__(self, key):
        result = super().__getitem__(key)
        if isinstance(key, slice) and isinstance(result, bytes):
            type(self).copied_bytes += len(result)
            return type(self)(result)
        return result


def _carchive_bytes(member_count: int) -> bytes:
    entries = []
    for index in range(member_count):
        name = f"m{index}".encode()
        entry_size = CArchive.CTOCEntry.ENTRYLEN + len(name)
        entries.append(
            struct.pack(
                f"!iiiiBB{len(name)}s",
                entry_size,
                0,
                0,
                0,
                0,
                ord(CArchive.ArchiveItem.DATA.value),
                name,
            )
        )
    toc = b"".join(entries)
    cookie = struct.pack(
        "!8siiii",
        CArchive.MAGIC,
        CArchive.PYINST20_COOKIE_SIZE + len(toc),
        CArchive.PYINST20_COOKIE_SIZE,
        len(toc),
        36,
    )
    return cookie + toc


def test_carchive_toc_parsing_copies_only_linear_data() -> None:
    """Parsing many small TOC entries does not repeatedly copy the suffix."""
    archive = CArchive.__new__(CArchive)
    archive.pyinstaller_version = 2.0
    archive.magic_index = 0
    archive.kwargs = {}
    archive.archive_contents = _SliceTrackingBytes(_carchive_bytes(256))
    _SliceTrackingBytes.copied_bytes = 0

    archive.parse_toc()

    assert len(archive.toc) == 256
    assert _SliceTrackingBytes.copied_bytes <= len(archive.archive_contents) * 4


def test_carchive_toc_respects_member_limit_during_parsing() -> None:
    """TOC materialization stops at the configured archive member limit."""
    archive = CArchive.__new__(CArchive)
    archive.pyinstaller_version = 2.0
    archive.magic_index = 0
    archive.kwargs = {"max_members": 2}
    archive.archive_contents = _carchive_bytes(8)

    archive.parse_toc()

    assert len(archive.toc) <= 2


class _SliceTrackingString(str):
    copied_characters = 0

    def __getitem__(self, key):
        result = super().__getitem__(key)
        if isinstance(key, slice) and isinstance(result, str):
            type(self).copied_characters += len(result)
            return type(self)(result)
        return result


def test_pyz_key_discovery_is_bounded_and_linear(tmp_path, monkeypatch) -> None:
    """A long printable key string cannot create quadratic slices/candidates."""
    key_file = tmp_path / "pyimod00_crypto_key.pyc"
    key_file.write_bytes(b"decoy")
    candidate_source = _SliceTrackingString("A" * 4096)
    _SliceTrackingString.copied_characters = 0
    monkeypatch.setattr(
        "pydecipher.artifact_types.pyinstaller.disassemble_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("invalid pyc")),
    )
    monkeypatch.setattr(utils, "parse_for_strings", lambda data: [candidate_source])
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_path = tmp_path / "archive.pyz"
    archive.encrypted = False

    archive.check_for_password_file()

    assert len(archive.potential_keys) <= 256
    assert _SliceTrackingString.copied_characters <= len(candidate_source) * 4


def test_pyc_detector_rejects_incidental_marker(tmp_path) -> None:
    """A marshal marker away from a valid PYC boundary is not sufficient."""
    payload = b"PK\x03\x04" + b"JUNK" + Pyc.MARSHALLED_CODE_OBJECT_LEADING_BYTES[0]

    with pytest.raises(TypeError):
        Pyc(io.BytesIO(payload), output_dir=tmp_path / "output")


def test_pyz_budget_accounts_for_generated_header(tmp_path, monkeypatch) -> None:
    """The exact bytes written, including the generated header, fit the budget."""
    compressed = zlib.compress(b"")
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = compressed
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = False
    archive.kwargs = {"max_member_size": 1, "max_total_size": 1}
    archive.toc = {"empty": (ZlibArchive.ArchiveItem.MODULE.value, 0, len(compressed))}
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"H" * 16)

    archive.extract_files()

    assert not (archive.output_dir / "empty.pyc").exists()


def test_truncated_encrypted_pyz_member_is_skipped(tmp_path, monkeypatch) -> None:
    """A short encrypted member is handled as a per-member parse failure."""
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = b"X"
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = True
    archive.encryption_key = ""
    archive.potential_keys = ["A" * 16]
    archive.kwargs = {}
    archive.toc = {"short": (ZlibArchive.ArchiveItem.MODULE.value, 0, 1)}
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")

    archive.extract_files()

    assert not (archive.output_dir / "short.pyc").exists()


def test_invalid_ambient_key_does_not_disable_unencrypted_pyz(
    tmp_path,
    monkeypatch,
) -> None:
    """A decoy sibling key file cannot suppress a valid unencrypted member."""
    (tmp_path / "pyimod00_crypto_key.pyc").write_bytes(b"not a key")
    monkeypatch.setattr(
        "pydecipher.artifact_types.pyinstaller.disassemble_file",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("invalid pyc")),
    )
    monkeypatch.setattr(utils, "parse_for_strings", lambda data: [])
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")
    compressed = zlib.compress(b"payload")
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_path = tmp_path / "archive.pyz"
    archive.archive_contents = compressed
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = False
    archive.kwargs = {}
    archive.toc = {"module": (ZlibArchive.ArchiveItem.MODULE.value, 0, len(compressed))}

    archive.check_for_password_file()
    archive.extract_files()

    assert (archive.output_dir / "module.pyc").read_bytes() == b"payload"


def test_carchive_source_before_module_is_extracted(tmp_path, monkeypatch) -> None:
    """Source extraction is independent of hostile TOC ordering."""
    source = xdis.marsh.TYPE_CODE.encode() + b"\0" * 7
    module = b"MAGC"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = source + module
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {}
    archive.toc = [
        CArchive.CTOCEntry(
            0,
            len(source),
            len(source),
            False,
            CArchive.ArchiveItem.PYSOURCE.value,
            "entry",
        ),
        CArchive.CTOCEntry(
            len(source),
            len(module),
            len(module),
            False,
            CArchive.ArchiveItem.PYMODULE.value,
            "module",
        ),
    ]
    monkeypatch.setattr("pydecipher.artifact_types.pyinstaller.magic2int", lambda data: 123)
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"H")

    archive.extract_files()

    assert (archive.output_dir / "entry.pyc").read_bytes() == b"H" + source
