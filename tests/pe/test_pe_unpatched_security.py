# -*- coding: utf-8 -*-
"""Acceptance tests for confirmed, not-yet-patched PE findings."""

import struct
from types import SimpleNamespace

import pytest

from pydecipher.artifact_types.pe import PortableExecutable


def _known_vulnerability(finding: str):
    return pytest.mark.xfail(
        strict=True,
        reason=f"{finding} is confirmed and awaiting remediation",
    )


def _security_directory(offset: int, size: int):
    return SimpleNamespace(
        name="IMAGE_DIRECTORY_ENTRY_SECURITY",
        VirtualAddress=offset,
        Size=size,
    )


def test_certificate_parser_stays_within_declared_table_size(
    tmp_path,
    monkeypatch,
) -> None:
    """Bytes after the declared certificate table are never parsed as records."""
    declared_record = struct.pack("<IHH", 8, 0x0200, 0x0002)
    trailing_overlay = b"\0" * 64
    parse_attempts = 0

    def count_parse_attempt(data):
        nonlocal parse_attempts
        parse_attempts += 1
        raise ValueError("invalid certificate")

    monkeypatch.setattr(
        "pydecipher.artifact_types.pe.cms.ContentInfo.load",
        count_parse_attempt,
    )
    artifact = PortableExecutable.__new__(PortableExecutable)
    artifact.output_dir = tmp_path / "output"
    artifact.kwargs = {}
    artifact.pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=[
                _security_directory(0, len(declared_record)),
            ]
        ),
        __data__=declared_record + trailing_overlay,
    )

    artifact.dump_certificates()

    assert parse_attempts <= 1


def test_certificate_records_use_header_inclusive_aligned_lengths(
    tmp_path,
    monkeypatch,
) -> None:
    """Each aligned certificate record passes only its declared payload."""
    payloads = [b"A" * 8, b"B" * 8]
    records = [
        struct.pack("<IHH", 8 + len(payload), 0x0200, 0x0002) + payload
        for payload in payloads
    ]
    seen_payloads = []

    def capture_payload(data):
        seen_payloads.append(data)
        raise ValueError("stop after capture")

    monkeypatch.setattr("pydecipher.artifact_types.pe.cms.ContentInfo.load", capture_payload)
    table = b"".join(records)
    artifact = PortableExecutable.__new__(PortableExecutable)
    artifact.output_dir = tmp_path / "output"
    artifact.kwargs = {}
    artifact.pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=[_security_directory(0, len(table))]),
        __data__=table,
    )

    artifact.dump_certificates()

    assert seen_payloads == payloads


@_known_vulnerability("024: payload after certificate table is hidden")
def test_overlay_preserves_payload_after_certificate_table(tmp_path) -> None:
    """Only the declared certificate range is excluded from overlay output."""
    before = b"BEFORE"
    certificate = b"CERT"
    after = b"AFTER"
    certificate_offset = len(before)
    artifact = PortableExecutable.__new__(PortableExecutable)
    artifact.output_dir = tmp_path / "output"
    artifact.kwargs = {}
    artifact.pe = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=[
                _security_directory(certificate_offset, len(certificate)),
            ]
        ),
        __data__=before + certificate + after,
        get_overlay_data_start_offset=lambda: 0,
    )

    output_path = artifact.dump_overlay()

    assert output_path.read_bytes() == before + after
