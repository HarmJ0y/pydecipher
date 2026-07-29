# 009: Quadratic PyInstaller Parsing

## Summary

CArchive TOC parsing repeatedly copies the unparsed suffix, while encrypted PYZ
key discovery repeatedly slices strings and removes candidates from the front
of a list. Extraction limits apply only after these operations.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:240-295`
- `pydecipher/artifact_types/pyinstaller.py:553-561`
- `pydecipher/artifact_types/pyinstaller.py:623-637`

## Exploitation

Use a CArchive with many minimal TOC records or place a long printable string
inside `pyimod00_crypto_key.pyc` beside an encrypted PYZ.

## Impact

Small-to-moderate artifacts can cause disproportionate CPU and memory use.

## Remediation

Parse TOCs with an index or memoryview, cap records before materialization, use
iterators/deques for key candidates, and bound candidate count.
