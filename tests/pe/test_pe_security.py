# -*- coding: utf-8 -*-
"""Security regression tests for Portable Executable resources."""

from types import SimpleNamespace

from pydecipher.artifact_types.pe import PortableExecutable


def _portable_executable_with_resource(output_dir, resource_name):
    leaf = SimpleNamespace(data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=0, Size=18)))
    middle = SimpleNamespace(directory=SimpleNamespace(entries=[leaf]))
    entry = SimpleNamespace(
        name=SimpleNamespace(string=resource_name.encode()),
        directory=SimpleNamespace(entries=[middle]),
    )
    pe = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[entry]),
        get_data=lambda rva, size: b"attacker-controlled",
    )
    artifact = PortableExecutable.__new__(PortableExecutable)
    artifact.pe = pe
    artifact.output_dir = output_dir
    artifact.kwargs = {}
    return artifact


def test_dump_resource_rejects_parent_traversal(tmp_path) -> None:
    """A PE resource name cannot escape its extraction directory."""
    output_dir = tmp_path / "output"
    (output_dir / "python" / "a.dll").mkdir(parents=True)
    resource_name = "python/a.dll/../../../escaped"
    artifact = _portable_executable_with_resource(output_dir, resource_name)

    assert artifact.dump_resource(resource_name) is None
    assert not (tmp_path / "escaped").exists()


def test_dump_resource_rejects_symlink_escape(tmp_path) -> None:
    """An existing symlink cannot redirect a PE resource write."""
    output_dir = tmp_path / "output"
    outside_dir = tmp_path / "outside"
    output_dir.mkdir()
    outside_dir.mkdir()
    (output_dir / "python.dll").symlink_to(outside_dir, target_is_directory=True)
    resource_name = "python.dll/escaped"
    artifact = _portable_executable_with_resource(output_dir, resource_name)

    assert artifact.dump_resource(resource_name) is None
    assert not (outside_dir / "escaped").exists()


def test_dump_resource_enforces_member_size_limit(tmp_path) -> None:
    """PE resources share the recursive extraction size budget."""
    output_dir = tmp_path / "output"
    resource_name = "python36.dll"
    artifact = _portable_executable_with_resource(output_dir, resource_name)
    artifact.kwargs = {"max_member_size": 4}

    assert artifact.dump_resource(resource_name) is None
    assert not (output_dir / resource_name).exists()
