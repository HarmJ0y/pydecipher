# 019: PyInstaller Path-Shape Collisions Abort Extraction

## Summary

PyInstaller output writes do not catch filesystem errors caused by one entry
creating a file where a later entry requires a directory.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:390-393`
- `pydecipher/artifact_types/pyinstaller.py:683-685`

## Exploitation

A CArchive containing `node` followed by `node/child`, or a PYZ containing
equivalent suffixed paths, raises an uncaught `NotADirectoryError`.

## Impact

A pair of hostile member names aborts the whole analysis job.

## Remediation

Detect normalized path-shape conflicts before extraction and handle per-entry
filesystem failures without terminating the archive.
