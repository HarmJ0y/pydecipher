# -*- coding: utf-8 -*-
"""Regression tests for filesystem overwrite and deletion vulnerabilities."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import pydecipher
from pydecipher import bytecode, main, remap
from pydecipher.artifact_types.py2exe import PYTHONSCRIPT
from pydecipher.artifact_types.pyc import Pyc


def test_log_write_rejects_symlink_destination(tmp_path) -> None:
    """A predictable log path cannot redirect a write through a symlink."""
    output_dir = tmp_path / "output"
    victim = tmp_path / "victim"
    output_dir.mkdir()
    victim.write_text("original")
    (output_dir / "log.txt").symlink_to(victim)

    with pytest.raises(ValueError):
        main._write_log_file(output_dir, "log.txt", "replacement")

    assert victim.read_text() == "original"


def test_log_write_creates_new_file(tmp_path) -> None:
    """A normal log write creates the requested output."""
    output_dir = tmp_path / "output"

    log_path = main._write_log_file(output_dir, "log.txt", "contents")

    assert log_path.read_text() == "contents"


def test_remap_log_write_rejects_symlink_destination(tmp_path) -> None:
    """The remap CLI cannot redirect its predictable log through a symlink."""
    output_dir = tmp_path / "output"
    victim = tmp_path / "victim"
    output_dir.mkdir()
    victim.write_text("original")
    (output_dir / "log.txt").symlink_to(victim)

    with pytest.raises(ValueError):
        remap._write_log_file(output_dir, "log.txt", "replacement")

    assert victim.read_text() == "original"


def test_decompile_does_not_replace_adjacent_source(tmp_path, monkeypatch) -> None:
    """Decompilation leaves an existing adjacent source file untouched."""
    pyc_file = tmp_path / "victim.pyc"
    source_file = tmp_path / "victim.py"
    pyc_file.write_bytes(b"pyc")
    source_file.write_text("original")
    fake_decompiler = SimpleNamespace(decompile_file=lambda *args, **kwargs: print("replacement"))
    monkeypatch.setattr(bytecode.xdis.load, "load_module", lambda *args, **kwargs: ((3, 8),))
    monkeypatch.setattr(bytecode, "_decompiler_for_version", lambda version: fake_decompiler)

    result = bytecode.decompile_pyc((pyc_file, None, None))

    assert result == "no_action"
    assert source_file.read_text() == "original"


def test_decompile_ignores_symlinked_pyc(tmp_path, monkeypatch) -> None:
    """Direct decompilation cannot read a PYC reached through a symlink."""
    outside_pyc = tmp_path / "outside.pyc"
    linked_pyc = tmp_path / "linked.pyc"
    outside_pyc.write_bytes(b"pyc")
    linked_pyc.symlink_to(outside_pyc)
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("symlinked PYC was opened")

    monkeypatch.setattr(bytecode.xdis.load, "load_module", fail_if_called)

    assert bytecode.decompile_pyc((linked_pyc, None, None)) == "no_action"
    assert called is False


def test_corrected_pyc_does_not_follow_symlink(tmp_path) -> None:
    """Corrected bytecode cannot overwrite a symlink target."""
    pyc_file = tmp_path / "sample.pyc"
    victim = tmp_path / "victim"
    pyc_file.write_bytes(b"c" + b"\0" * 31)
    victim.write_bytes(b"original")
    pyc_file.with_suffix(".corrected.pyc").symlink_to(victim)

    Pyc(pyc_file, version_hint="3.8").unpack()

    assert victim.read_bytes() == b"original"


def test_py2exe_output_does_not_follow_symlink(tmp_path, monkeypatch) -> None:
    """Py2Exe bytecode output cannot overwrite a symlink target."""
    output_dir = tmp_path / "output"
    victim = tmp_path / "victim"
    output_dir.mkdir()
    victim.write_bytes(b"original")
    (output_dir / "victim.pyc").symlink_to(victim)
    artifact = PYTHONSCRIPT.__new__(PYTHONSCRIPT)
    artifact.resource_contents = b""
    artifact.marshalled_obj_start_idx = 0
    artifact.magic_num = next(iter(pydecipher.bytecode.magicint2version))
    artifact.output_dir = output_dir
    code_object = SimpleNamespace(co_filename="victim.py")
    monkeypatch.setattr("pydecipher.artifact_types.py2exe.load_code", lambda *args: [code_object])
    monkeypatch.setattr(
        "pydecipher.artifact_types.py2exe.xdis.load.write_bytecode_file",
        lambda path, *args: Path(path).write_bytes(b"replacement"),
    )

    artifact.disassemble_and_dump()

    assert victim.read_bytes() == b"original"


def test_cleanup_does_not_delete_through_symlink(tmp_path) -> None:
    """Cleanup cannot recursively delete a version directory outside output."""
    output_dir = tmp_path / "output"
    outside_dir = tmp_path / "outside"
    version_dir = outside_dir / "3.8"
    output_dir.mkdir()
    version_dir.mkdir(parents=True)
    evidence = version_dir / "evidence.txt"
    evidence.write_text("keep")
    (output_dir / "pythonscript_output").symlink_to(outside_dir, target_is_directory=True)

    PYTHONSCRIPT.cleanup(output_dir)

    assert evidence.read_text() == "keep"


def test_relocation_rejects_symlinked_destination_parent(tmp_path) -> None:
    """Relocation cannot escape through a symlinked output subdirectory."""
    relative_root = tmp_path / "input"
    source = relative_root / "nested" / "victim.py"
    output_dir = tmp_path / "output"
    outside_dir = tmp_path / "outside"
    source.parent.mkdir(parents=True)
    output_dir.mkdir()
    outside_dir.mkdir()
    source.write_text("replacement")
    victim = outside_dir / "victim.py"
    victim.write_text("original")
    (output_dir / "nested").symlink_to(outside_dir, target_is_directory=True)

    with pytest.raises(ValueError):
        main._relocate_decompiled_file(source, relative_root, output_dir)

    assert victim.read_text() == "original"
    assert source.exists()


def test_relocation_does_not_replace_existing_destination(tmp_path) -> None:
    """Relocation preserves both files when the destination is occupied."""
    relative_root = tmp_path / "input"
    source = relative_root / "victim.py"
    output_dir = tmp_path / "output"
    source.parent.mkdir()
    output_dir.mkdir()
    source.write_text("replacement")
    victim = output_dir / "victim.py"
    victim.write_text("original")

    with pytest.raises(FileExistsError):
        main._relocate_decompiled_file(source, relative_root, output_dir)

    assert victim.read_text() == "original"
    assert source.read_text() == "replacement"


def test_relocation_moves_file_to_contained_destination(tmp_path) -> None:
    """A normal relocation preserves the relative path and removes the source."""
    relative_root = tmp_path / "input"
    source = relative_root / "nested" / "source.py"
    output_dir = tmp_path / "output"
    source.parent.mkdir(parents=True)
    source.write_text("contents")

    output_path = main._relocate_decompiled_file(source, relative_root, output_dir)

    assert output_path.read_text() == "contents"
    assert not source.exists()


def test_relocation_rejects_symlinked_source(tmp_path) -> None:
    """Relocation cannot disclose a file reached through a source symlink."""
    relative_root = tmp_path / "input"
    output_dir = tmp_path / "output"
    outside_file = tmp_path / "outside.py"
    relative_root.mkdir()
    outside_file.write_text("secret")
    source = relative_root / "source.py"
    source.symlink_to(outside_file)

    with pytest.raises(ValueError):
        main._relocate_decompiled_file(source, relative_root, output_dir)

    assert not output_dir.exists()
    assert outside_file.read_text() == "secret"


def test_find_pyc_files_excludes_symlinks_and_preexisting_paths(tmp_path) -> None:
    """PYC discovery returns only current regular files from the selected tree."""
    root = tmp_path / "output"
    root.mkdir()
    fresh = root / "fresh.pyc"
    stale = root / "stale.pyc"
    outside = tmp_path / "outside.pyc"
    linked = root / "linked.pyc"
    fresh.write_bytes(b"fresh")
    stale.write_bytes(b"stale")
    outside.write_bytes(b"outside")
    linked.symlink_to(outside)

    discovered = main._find_pyc_files(root, excluded_paths={stale})

    assert discovered == [fresh]


def test_remapping_output_rejects_dangling_symlink(tmp_path) -> None:
    """Remapping output cannot create a target through a dangling symlink."""
    output_dir = tmp_path / "output"
    victim = tmp_path / "victim"
    output_dir.mkdir()
    (output_dir / "remapping.txt").symlink_to(victim)

    output_path = remap.write_remapping_file({}, "3.8", "test", "cmd", output_dir)

    assert output_path.name == "remapping-1.txt"
    assert not victim.exists()
