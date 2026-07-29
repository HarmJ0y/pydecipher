# -*- coding: utf-8 -*-
"""Tests for race-resistant extraction output helpers."""

import pytest

from pydecipher import utils


def test_open_output_file_writes_nested_member_atomically(tmp_path) -> None:
    """A normal nested member is committed at its contained destination."""
    output_dir = tmp_path / "output"

    with utils.open_output_file(output_dir, "nested/member") as (output_path, output_file):
        output_file.write(b"payload")
        assert not output_path.exists()

    assert output_path.read_bytes() == b"payload"


def test_open_output_file_does_not_follow_leaf_symlink(tmp_path) -> None:
    """An existing leaf symlink cannot redirect an atomic extraction write."""
    output_dir = tmp_path / "output"
    outside_file = tmp_path / "outside"
    output_dir.mkdir()
    outside_file.write_bytes(b"original")
    (output_dir / "member").symlink_to(outside_file)

    with pytest.raises(ValueError):
        with utils.open_output_file(output_dir, "member") as (_, output_file):
            output_file.write(b"replacement")

    assert outside_file.read_bytes() == b"original"


def test_open_output_file_removes_partial_temporary_file(tmp_path) -> None:
    """A failed extraction leaves neither a destination nor temporary file."""
    output_dir = tmp_path / "output"

    with pytest.raises(RuntimeError):
        with utils.open_output_file(output_dir, "member") as (_, output_file):
            output_file.write(b"partial")
            raise RuntimeError("abort extraction")

    assert list(output_dir.iterdir()) == []


def test_open_output_file_rejects_symlink_in_output_root(tmp_path) -> None:
    """Secure platforms anchor every output-root component without symlinks."""
    if not utils._supports_secure_output_dir_fd():
        pytest.skip("descriptor-relative output operations are unavailable")
    actual_output = tmp_path / "actual"
    linked_output = tmp_path / "linked"
    actual_output.mkdir()
    linked_output.symlink_to(actual_output, target_is_directory=True)

    with pytest.raises(OSError):
        with utils.open_output_file(linked_output, "member") as (_, output_file):
            output_file.write(b"payload")

    assert not (actual_output / "member").exists()
