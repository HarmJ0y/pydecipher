# -*- coding: utf-8 -*-
"""Regression tests for logging state persisting across analysis jobs (029)."""

import io
import logging

import pytest

import pydecipher
from pydecipher import main

SECRET = "pyz-encryption-key-from-prior-job"


@pytest.fixture
def console_streams():
    """Capture both console handlers and restore global logging state."""
    stdout_handler = pydecipher._stdout_console_handler
    stderr_handler = pydecipher._stderr_console_handler
    stdout, stderr = io.StringIO(), io.StringIO()
    original_stdout = stdout_handler.setStream(stdout)
    original_stderr = stderr_handler.setStream(stderr)
    original_handlers = list(pydecipher.logger.handlers)
    try:
        yield stdout, stderr
    finally:
        stdout_handler.setStream(original_stdout)
        stderr_handler.setStream(original_stderr)
        pydecipher.set_logging_options(verbose=False, quiet=False)
        for handler in list(pydecipher.logger.handlers):
            if handler not in original_handlers:
                pydecipher.logger.removeHandler(handler)
        for handler in original_handlers:
            if handler not in pydecipher.logger.handlers:
                pydecipher.logger.addHandler(handler)


def test_default_job_after_verbose_job_restores_levels(console_streams) -> None:
    """A non-verbose job does not inherit DEBUG handler levels."""
    pydecipher.set_logging_options(verbose=True, quiet=False)
    assert pydecipher._stdout_console_handler.level == logging.DEBUG

    pydecipher.set_logging_options(verbose=False, quiet=False)

    assert pydecipher.verbose_enabled is False
    assert pydecipher.get_logging_options()["verbose"] is False
    assert pydecipher._stdout_console_handler.level == logging.INFO
    assert pydecipher._stderr_console_handler.level == logging.WARNING


def test_default_job_after_verbose_job_does_not_emit_debug(console_streams) -> None:
    """DEBUG records such as recovered keys are not shown to a later job."""
    stdout, stderr = console_streams
    pydecipher.set_logging_options(verbose=True, quiet=False)
    pydecipher.logger.debug("first-job-debug")
    assert "first-job-debug" in stdout.getvalue()

    pydecipher.set_logging_options(verbose=False, quiet=False)
    pydecipher.logger.debug(f"[+] Verified ZlibArchive password is {SECRET}.")
    pydecipher.logger.info("second-job-info")

    assert SECRET not in stdout.getvalue()
    assert SECRET not in stderr.getvalue()
    assert "second-job-info" in stdout.getvalue()


def test_default_job_after_quiet_job_restores_console(console_streams) -> None:
    """Quiet mode does not silence a later job that did not request it."""
    stdout, _ = console_streams
    pydecipher.set_logging_options(verbose=False, quiet=True)
    pydecipher.logger.info("quiet-job-info")
    assert "quiet-job-info" not in stdout.getvalue()

    pydecipher.set_logging_options(verbose=False, quiet=False)
    pydecipher.logger.info("normal-job-info")

    assert pydecipher.quiet_enabled is False
    assert pydecipher._stdout_console_handler in pydecipher.logger.handlers
    assert pydecipher._stderr_console_handler in pydecipher.logger.handlers
    assert "normal-job-info" in stdout.getvalue()


def test_cli_default_run_after_verbose_run_does_not_emit_debug(console_streams, tmp_path) -> None:
    """Consecutive CLI runs in one process reset verbose state per run."""
    stdout, stderr = console_streams
    artifact = tmp_path / "not_an_artifact.bin"
    artifact.write_bytes(b"\x00" * 64)

    main.run([str(artifact), "--output", str(tmp_path / "out1"), "--verbose"])
    assert pydecipher.verbose_enabled is True

    main.run([str(artifact), "--output", str(tmp_path / "out2")])
    assert pydecipher.verbose_enabled is False
    pydecipher.logger.debug(f"[+] Verified ZlibArchive password is {SECRET}.")

    assert SECRET not in stdout.getvalue()
    assert SECRET not in stderr.getvalue()


def _attached_handlers():
    return list(pydecipher.logger.handlers)


@pytest.mark.parametrize("produces_output", [False, True])
def test_cli_run_detaches_in_memory_log_buffer(console_streams, tmp_path, monkeypatch, produces_output) -> None:
    """Each run's in-memory log buffer is removed once the run finishes."""
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"\x00" * 64)
    output_dir = tmp_path / "out"

    def fake_unpack(path, output_dir, **kwargs):
        if produces_output:
            output = tmp_path / "out"
            output.mkdir(exist_ok=True)
            (output / "member.bin").write_bytes(b"member")

    monkeypatch.setattr(main, "unpack", fake_unpack)
    pydecipher.set_logging_options(verbose=False, quiet=False)
    before = _attached_handlers()

    main.run([str(artifact), "--output", str(output_dir), "--verbose"])

    leaked = [
        handler
        for handler in _attached_handlers()
        if handler not in before and handler is not pydecipher._log_file_handler
    ]
    assert leaked == []
    if produces_output:
        assert pydecipher._log_file_handler is not None


def test_cli_run_detaches_in_memory_log_buffer_on_error(console_streams, tmp_path, monkeypatch) -> None:
    """A failing run does not leave its in-memory log buffer attached."""
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"\x00" * 64)

    def failing_unpack(path, output_dir, **kwargs):
        raise RuntimeError("unpack failed")

    monkeypatch.setattr(main, "unpack", failing_unpack)
    pydecipher.set_logging_options(verbose=False, quiet=False)
    before = _attached_handlers()

    with pytest.raises(RuntimeError):
        main.run([str(artifact), "--output", str(tmp_path / "out")])

    assert _attached_handlers() == before
