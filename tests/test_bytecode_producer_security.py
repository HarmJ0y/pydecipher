# -*- coding: utf-8 -*-
"""Security tests for the standard bytecode collection utility."""

import importlib.util
from pathlib import Path


def _load_producer(monkeypatch, tmp_path):
    monkeypatch.setenv("PYENV_ROOT", str(tmp_path / "pyenv"))
    monkeypatch.setenv("BYTECODE_DUMP_DIR", str(tmp_path / "output"))
    script_path = (
        Path(__file__).parents[1]
        / "other"
        / "StandardBytecodeGenerator"
        / "bytecode_producer.py"
    )
    spec = importlib.util.spec_from_file_location("bytecode_producer_test", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_bytecode_producer_copies_to_new_destination(tmp_path, monkeypatch) -> None:
    """A normal bytecode file is copied below the configured destination."""
    producer = _load_producer(monkeypatch, tmp_path)
    source_dir = tmp_path / "pyenv" / "versions" / "3.8"
    source_file = source_dir / "lib" / "module.pyc"
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"payload")

    assert producer.extract_pyc_files(source_dir) == 1
    assert (tmp_path / "output" / "3.8" / "lib" / "module.pyc").read_bytes() == b"payload"


def test_bytecode_producer_does_not_follow_destination_symlink(tmp_path, monkeypatch) -> None:
    """A preexisting output symlink cannot redirect a bytecode copy."""
    producer = _load_producer(monkeypatch, tmp_path)
    source_dir = tmp_path / "pyenv" / "versions" / "3.8"
    source_file = source_dir / "lib" / "module.pyc"
    destination_parent = tmp_path / "output" / "3.8" / "lib"
    victim = tmp_path / "victim"
    source_file.parent.mkdir(parents=True)
    destination_parent.mkdir(parents=True)
    source_file.write_bytes(b"replacement")
    victim.write_bytes(b"original")
    (destination_parent / "module.pyc").symlink_to(victim)

    assert producer.extract_pyc_files(source_dir) == 0
    assert victim.read_bytes() == b"original"
