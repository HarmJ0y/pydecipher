# -*- coding: utf-8 -*-
"""Acceptance tests for confirmed, not-yet-patched PyInstaller findings."""

import io
import importlib.util
import marshal
import struct
import zlib
from types import SimpleNamespace

import pytest
import xdis
from Crypto.Cipher import AES
from xdis.magics import by_magic

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
    cookie = _carchive_cookie(CArchive.PYINST20_COOKIE_SIZE + len(toc), 0, len(toc), 36)
    return toc + cookie


def _carchive_cookie(package_size: int, toc_offset: int, toc_size: int, python_version: int = 38) -> bytes:
    return CArchive.MAGIC + struct.pack("!iiii", package_size, toc_offset, toc_size, python_version)


def _pack_toc_entry(offset: int, compressed: int, uncompressed: int, flag: int, kind: bytes, name: bytes) -> bytes:
    entry_size = CArchive.CTOCEntry.ENTRYLEN + len(name)
    return struct.pack(
        f"!iiiiBB{len(name)}s",
        entry_size,
        offset,
        compressed,
        uncompressed,
        flag,
        ord(kind),
        name,
    )


@pytest.mark.parametrize("kind", [b"s", b"m"])
def test_carchive_python311_raw_code_uses_cookie_magic(tmp_path, kind) -> None:
    """Three-digit cookie versions recover modern raw CArchive Python entries."""
    raw_code = bytes([ord(xdis.marsh.TYPE_CODE) | xdis.unmarshal.FLAG_REF]) + b"raw-marshaled-code"
    name = b"entry"
    toc = _pack_toc_entry(0, len(raw_code), len(raw_code), 0, kind, name)
    cookie_size = CArchive.PYINST21_COOKIE_SIZE
    cookie = CArchive.MAGIC + struct.pack(
        "!iiii64s",
        len(raw_code) + len(toc) + cookie_size,
        len(raw_code),
        len(toc),
        311,
        b"python311.dll",
    )
    output_dir = tmp_path / "output"

    archive = CArchive(io.BytesIO(raw_code + toc + cookie), output_dir=output_dir)
    archive.unpack()

    assert archive.python_version == "3.11"
    extracted = (output_dir / "entry.pyc").read_bytes()
    assert extracted[:4] == xdis.magics.by_version["3.11"]
    assert extracted[16:] == raw_code


def test_carchive_toc_parsing_copies_only_linear_data() -> None:
    """Parsing many small TOC entries does not repeatedly copy the suffix."""
    archive = CArchive.__new__(CArchive)
    archive.pyinstaller_version = 2.0
    archive.kwargs = {}
    archive.archive_contents = _SliceTrackingBytes(_carchive_bytes(256))
    archive.magic_index = len(archive.archive_contents) - CArchive.PYINST20_COOKIE_SIZE
    _SliceTrackingBytes.copied_bytes = 0

    archive.parse_toc()

    assert len(archive.toc) == 256
    assert _SliceTrackingBytes.copied_bytes <= len(archive.archive_contents) * 4


def test_carchive_toc_respects_member_limit_during_parsing() -> None:
    """TOC materialization stops at the configured archive member limit."""
    archive = CArchive.__new__(CArchive)
    archive.pyinstaller_version = 2.0
    archive.kwargs = {"max_members": 2}
    archive.archive_contents = _carchive_bytes(8)
    archive.magic_index = len(archive.archive_contents) - CArchive.PYINST20_COOKIE_SIZE

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


def test_pyz_toc_respects_member_limit_during_parsing(monkeypatch) -> None:
    """A marshalled PYZ TOC is bounded before its entries are retained."""
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = b"PYZ\0" + next(iter(by_magic)) + struct.pack("!i", 12) + b"toc"
    archive.kwargs = {"max_members": 2}
    monkeypatch.setattr(
        xdis.unmarshal,
        "load_code",
        lambda *args, **kwargs: {
            f"module_{index}": (ZlibArchive.ArchiveItem.MODULE.value, 12, 0)
            for index in range(256)
        },
    )

    archive.parse_toc()

    assert len(archive.toc) <= 2


def test_carchive_magic_prescan_does_not_copy_every_member_payload(tmp_path) -> None:
    """Order-independent source recovery does not copy overlapping module payloads."""
    payload = b"M" * 4096
    _SliceTrackingBytes.copied_bytes = 0
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = _SliceTrackingBytes(payload)
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {"max_members": 1}
    archive.toc = [
        CArchive.CTOCEntry(0, len(payload), len(payload), False, CArchive.ArchiveItem.PYMODULE.value, f"m{i}")
        for i in range(64)
    ]

    archive.extract_files()

    assert _SliceTrackingBytes.copied_bytes <= len(payload) * 4


def test_pyc_detector_rejects_non_pyc_with_recognized_header(tmp_path) -> None:
    """A known magic and marker do not mask a valid archive without marshal validation."""
    prefix = importlib.util.MAGIC_NUMBER + b"\0" * 12 + marshal.dumps((lambda: None).__code__)
    cookie = _carchive_cookie(len(prefix) + CArchive.PYINST20_COOKIE_SIZE, 0, 0)
    payload = prefix + cookie
    assert CArchive(io.BytesIO(payload), output_dir=tmp_path / "carchive")

    with pytest.raises(TypeError):
        Pyc(io.BytesIO(payload), output_dir=tmp_path / "pyc")


def test_carchive_budget_accounts_for_generated_header(tmp_path, monkeypatch) -> None:
    """CArchive source reconstruction charges the exact bytes written."""
    source = xdis.marsh.TYPE_CODE.encode() + b"\0" * 7
    module = b"MAGC"
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = source + module
    archive.output_dir = tmp_path / "output"
    archive.kwargs = {"max_member_size": len(source), "max_total_size": 1024}
    archive.toc = [
        CArchive.CTOCEntry(0, len(source), len(source), False, CArchive.ArchiveItem.PYSOURCE.value, "entry"),
        CArchive.CTOCEntry(
            len(source), len(module), len(module), False, CArchive.ArchiveItem.PYMODULE.value, "module"
        ),
    ]
    monkeypatch.setattr("pydecipher.artifact_types.pyinstaller.magic2int", lambda data: 123)
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"H" * 16)

    archive.extract_files()

    assert not (archive.output_dir / "entry.pyc").exists()


def test_carchive_uses_cookie_package_start(tmp_path) -> None:
    """Leading overlay bytes do not shift package-relative TOC and member offsets."""
    member = b"data"
    toc = _pack_toc_entry(0, len(member), len(member), 0, b"x", b"good")
    package_size = len(member) + len(toc) + CArchive.PYINST20_COOKIE_SIZE
    payload = b"overlay-prefix" + member + toc + _carchive_cookie(package_size, len(member), len(toc))
    archive = CArchive(io.BytesIO(payload), output_dir=tmp_path / "output")

    archive.parse_toc()
    archive.extract_files()

    assert (archive.output_dir / "good").read_bytes() == member


def test_carchive_selects_final_valid_cookie(tmp_path) -> None:
    """A magic marker in package data cannot hide the valid final cookie."""
    member = b"X" + CArchive.MAGIC + b"A" * 128
    cookie = _carchive_cookie(len(member) + CArchive.PYINST20_COOKIE_SIZE, len(member), 0)

    archive = CArchive(io.BytesIO(member + cookie), output_dir=tmp_path / "output")

    assert archive.magic_index == len(member)


def test_pyz_key_discovery_ignores_non_string_constants(tmp_path, monkeypatch) -> None:
    """A valid key sidecar with unrelated constants cannot abort PYZ handling."""
    key_file = tmp_path / "pyimod00_crypto_key.pyc"
    key_file.write_bytes(b"sidecar")
    monkeypatch.setattr(
        "pydecipher.artifact_types.pyinstaller.disassemble_file",
        lambda *args, **kwargs: ("key.py", SimpleNamespace(co_consts=(123, None)), "3.8", 1, 0, False, 0, None),
    )
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_path = tmp_path / "archive.pyz"
    archive.encrypted = False
    archive.kwargs = {}

    archive.check_for_password_file()

    assert archive.potential_keys == []


def test_corrupt_pyz_member_does_not_discard_key_for_later_members(tmp_path, monkeypatch) -> None:
    """A malformed early member cannot suppress later encrypted modules."""
    key = "K" * 16
    iv = b"I" * 16

    def encrypt(payload: bytes) -> bytes:
        return iv + AES.new(key.encode(), AES.MODE_CFB, iv).encrypt(zlib.compress(payload))

    malformed = encrypt(b"B" * 128)
    valid = encrypt(b"good")
    archive = ZlibArchive.__new__(ZlibArchive)
    archive.archive_contents = malformed + valid
    archive.output_dir = tmp_path / "output"
    archive.magic_int = 0
    archive.encrypted = False
    archive.encryption_key = ""
    archive.potential_keys = [key]
    archive.kwargs = {"max_member_size": 64}
    archive.toc = {
        "malformed": (ZlibArchive.ArchiveItem.MODULE.value, 0, len(malformed)),
        "valid": (ZlibArchive.ArchiveItem.MODULE.value, len(malformed), len(valid)),
    }
    monkeypatch.setattr(pydecipher.bytecode, "create_pyc_header", lambda *args, **kwargs: b"")

    archive.extract_files()

    assert (archive.output_dir / "valid.pyc").read_bytes() == b"good"


def test_carchive_skips_malformed_name_and_parses_later_entry() -> None:
    """An invalid UTF-8 entry name does not suppress subsequent TOC records."""
    invalid = _pack_toc_entry(0, 0, 0, 0, b"x", b"\xff")
    valid = _pack_toc_entry(0, 0, 0, 0, b"x", b"good")
    toc = invalid + valid
    archive = CArchive.__new__(CArchive)
    archive.archive_contents = toc + _carchive_cookie(CArchive.PYINST20_COOKIE_SIZE + len(toc), 0, len(toc))
    archive.magic_index = len(toc)
    archive.pyinstaller_version = 2.0
    archive.kwargs = {}

    archive.parse_toc()

    assert [entry.name for entry in archive.toc] == ["good"]
