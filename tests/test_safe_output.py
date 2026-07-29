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


def test_open_output_file_does_not_replace_existing_file(tmp_path) -> None:
    """Archive extraction cannot silently replace an existing output file."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output_path = output_dir / "member"
    output_path.write_bytes(b"original")

    with pytest.raises(FileExistsError):
        with utils.open_output_file(output_dir, "member") as (_, output_file):
            output_file.write(b"replacement")

    assert output_path.read_bytes() == b"original"


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


def test_open_output_file_fails_closed_without_secure_dir_fd(tmp_path, monkeypatch) -> None:
    """Platforms without no-follow directory operations do not use a racy fallback."""
    monkeypatch.setattr(utils, "_supports_secure_output_dir_fd", lambda: False)

    with pytest.raises(NotImplementedError):
        with utils.open_output_file(tmp_path / "output", "member") as (_, output_file):
            output_file.write(b"payload")


def test_make_output_directory_creates_nested_directory(tmp_path) -> None:
    """A normal archive directory is created below the output root."""
    output_dir = tmp_path / "output"

    output_path = utils.make_output_directory(output_dir, "nested/member")

    assert output_path.is_dir()


def test_make_output_directory_fails_closed_without_secure_dir_fd(tmp_path, monkeypatch) -> None:
    """Directory extraction has no check-then-create symlink fallback."""
    monkeypatch.setattr(utils, "_supports_secure_output_dir_fd", lambda: False)

    with pytest.raises(NotImplementedError):
        utils.make_output_directory(tmp_path / "output", "nested/member")

    assert not (tmp_path / "output").exists()


def test_open_existing_file_appends_to_expected_inode(tmp_path) -> None:
    """A safely created log can be reopened when its identity is unchanged."""
    output_path = tmp_path / "log.txt"
    output_path.write_text("first")
    output_stat = output_path.stat(follow_symlinks=False)

    with utils.open_existing_file(
        output_path,
        expected_identity=(output_stat.st_dev, output_stat.st_ino),
    ) as output_file:
        output_file.write(" second")

    assert output_path.read_text() == "first second"


def test_open_existing_file_rejects_replaced_symlink(tmp_path) -> None:
    """A log path replaced after creation cannot redirect later appends."""
    output_path = tmp_path / "log.txt"
    victim = tmp_path / "victim"
    output_path.write_text("log")
    output_stat = output_path.stat(follow_symlinks=False)
    victim.write_text("original")
    output_path.unlink()
    output_path.symlink_to(victim)

    with pytest.raises(OSError):
        utils.open_existing_file(
            output_path,
            expected_identity=(output_stat.st_dev, output_stat.st_ino),
        )

    assert victim.read_text() == "original"


def test_open_existing_file_rejects_replaced_regular_file(tmp_path) -> None:
    """Inode binding detects replacement even when the new path is regular."""
    output_path = tmp_path / "log.txt"
    output_path.write_text("first")
    output_stat = output_path.stat(follow_symlinks=False)
    output_path.rename(tmp_path / "original-log.txt")
    output_path.write_text("replacement")

    with pytest.raises(ValueError):
        utils.open_existing_file(
            output_path,
            expected_identity=(output_stat.st_dev, output_stat.st_ino),
        )
