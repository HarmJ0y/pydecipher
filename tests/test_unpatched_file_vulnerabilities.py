# -*- coding: utf-8 -*-
"""Acceptance tests for confirmed file-backed findings awaiting remediation."""

import io
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

import pydecipher
from pydecipher import bytecode, utils
from pydecipher.artifact_types.py2exe import PYTHONSCRIPT


def _known_vulnerability(finding: str):
    return pytest.mark.xfail(
        strict=True,
        reason=f"{finding} is confirmed and awaiting remediation",
    )


def test_code_object_traversal_processes_each_object_once(monkeypatch) -> None:
    """Shared code-object subtrees cannot multiply remapping work."""

    class FakeCode:
        accesses = 0

        def __init__(self, child=None):
            self.co_consts = () if child is None else (child, child)

        @property
        def co_code(self):
            type(self).accesses += 1
            return b"\x01\x00"

    root = FakeCode()
    for _ in range(9):
        root = FakeCode(root)
    FakeCode.accesses = 0
    monkeypatch.setattr(bytecode, "iscode", lambda value: isinstance(value, FakeCode))

    bytecode.diff_opcode(root, root, version="3.10")

    assert FakeCode.accesses <= 128


def test_py2exe_version_probes_are_bounded(tmp_path, monkeypatch) -> None:
    """A PYTHONSCRIPT without version evidence gets a small bounded probe set."""
    header = struct.pack("iiii", PYTHONSCRIPT.PYTHONSCRIPT_MAGIC, 0, 0, 1)
    resource = tmp_path / "PYTHONSCRIPT"
    resource.write_bytes(header + b"archive\0payload")
    artifact = PYTHONSCRIPT(resource, output_dir=tmp_path / "output")
    attempts = []
    artifact._determine_python_version = lambda: set()
    artifact.disassemble_and_dump = lambda brute_force=False: attempts.append(artifact.magic_num)

    artifact.unpack()

    assert len(attempts) <= 8


def test_py2exe_output_is_charged_to_extraction_budget(tmp_path, monkeypatch) -> None:
    """Generated Py2Exe bytecode cannot exceed the per-member limit."""
    artifact = PYTHONSCRIPT.__new__(PYTHONSCRIPT)
    artifact.resource_contents = b""
    artifact.marshalled_obj_start_idx = 0
    artifact.magic_num = next(iter(bytecode.magicint2version))
    artifact.output_dir = tmp_path / "output"
    artifact.kwargs = {"max_member_size": 8}
    code_object = SimpleNamespace(co_filename="module.py")
    monkeypatch.setattr("pydecipher.artifact_types.py2exe.load_code", lambda *args: [code_object])
    monkeypatch.setattr(
        "pydecipher.artifact_types.py2exe.xdis.load.write_bytecode_file",
        lambda path, *args: Path(path).write_bytes(b"X" * 64),
    )

    artifact.disassemble_and_dump()

    assert not (artifact.output_dir / "module.pyc").exists()


def test_py2exe_rejects_invalid_archive_name_encoding(tmp_path) -> None:
    """Invalid UTF-8 in an otherwise plausible header is a normal parser rejection."""
    header = struct.pack("iiii", PYTHONSCRIPT.PYTHONSCRIPT_MAGIC, 0, 0, 1)

    with pytest.raises(TypeError):
        PYTHONSCRIPT(
            io.BytesIO(header + b"\xff\0payload"),
            output_dir=tmp_path / "output",
        )


def test_new_logging_job_detaches_previous_file(tmp_path) -> None:
    """Starting a new job cannot append its metadata to the prior job's file."""
    prior_log = tmp_path / "prior.log"
    prior_log.write_text("prior\n")
    stat_result = prior_log.stat()
    pydecipher.set_logging_options(
        log_path=prior_log,
        log_identity=(stat_result.st_dev, stat_result.st_ino),
    )
    try:
        pydecipher.set_logging_options(verbose=False, quiet=False)
        pydecipher.logger.warning("second-job-sensitive-metadata")
    finally:
        handler = pydecipher._log_file_handler
        if handler is not None:
            pydecipher.logger.removeHandler(handler)
            handler.close()
            pydecipher._log_file_handler = None
            pydecipher.log_path = None
            pydecipher.log_identity = None

    assert "second-job-sensitive-metadata" not in prior_log.read_text()


def test_atomic_output_rejects_replaced_temporary_name(tmp_path, monkeypatch) -> None:
    """A same-user race cannot replace the written inode before publication."""
    output_dir = tmp_path / "output"
    outside_file = tmp_path / "outside"
    outside_file.write_bytes(b"outside")
    real_link = os.link

    def replace_before_link(source, destination, *, src_dir_fd, dst_dir_fd, follow_symlinks):
        os.unlink(source, dir_fd=src_dir_fd)
        os.symlink(outside_file, source, dir_fd=src_dir_fd)
        return real_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(utils.os, "link", replace_before_link)
    monkeypatch.setattr(utils, "_supports_secure_output_dir_fd", lambda: True)
    with pytest.raises(ValueError):
        with utils.open_output_file(output_dir, "member") as (_, output_file):
            output_file.write(b"trusted")

    destination = output_dir / "member"
    assert not destination.exists()


def test_member_path_depth_is_bounded(tmp_path) -> None:
    """One member name cannot create an excessive directory chain."""
    member_name = "/".join(["directory"] * 128 + ["member"])

    with pytest.raises((ValueError, utils.ExtractionLimitError)):
        with utils.open_output_file(tmp_path / "output", member_name):
            pass
