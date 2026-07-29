# -*- coding: utf-8 -*-
"""Tests for bytecode compatibility helpers."""

import pytest
from xdis.magics import magicint2version

from pydecipher import bytecode


@pytest.mark.parametrize(
    ("version", "expected_module"),
    [
        ((3, 6), "uncompyle6"),
        ((3, 7), "decompyle3"),
        ((3, 8), "decompyle3"),
        ((2, 7), "uncompyle6"),
    ],
)
def test_decompiler_for_version(version, expected_module) -> None:
    """Bytecode is routed to a decompiler that supports its version."""
    assert bytecode._decompiler_for_version(version).__name__ == expected_module


def test_xdis_version_tuple_conversions() -> None:
    """xdis version tuples are accepted wherever dotted versions are needed."""
    assert bytecode.version_str_to_tuple((3, 6)) == (3, 6)
    assert bytecode.version_to_str((3, 6)) == "3.6"


def test_python_310_pyc_header_uses_modern_layout() -> None:
    """Python 3.10 PYC headers include PEP 552 flags and source size."""
    magic_int = next(
        magic
        for magic, version in magicint2version.items()
        if version.startswith("3.10")
    )

    header = bytecode.create_pyc_header(
        magic_int,
        compilation_ts=1,
        file_size=2,
    )

    assert len(header) == 16


def test_python_310_opcode_diff_uses_two_byte_instructions() -> None:
    """Python 3.10 opcode comparison ignores argument bytes as opcodes."""
    template = (lambda: None).__code__
    standard = template.replace(co_code=bytes([1, 99, 2, 88]), co_consts=())
    remapped = template.replace(co_code=bytes([4, 99, 6, 88]), co_consts=())

    remappings = bytecode.diff_opcode(
        standard,
        remapped,
        version="3.10",
    )

    assert remappings == {1: {4: 1}, 2: {6: 1}}
