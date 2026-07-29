# -*- coding: utf-8 -*-
"""Tests for bytecode compatibility helpers."""

import pytest

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
