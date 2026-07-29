# 026: CArchive TOC Order Suppresses Source Extraction

## Summary

CArchive source entries need a Python magic number learned from module entries,
but extraction processes entries in one pass and skips sources encountered
before the first module.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:298-381`

## Exploitation

Place a source entry before a module entry containing the required magic.
Reversing the same two entries extracts both; the hostile order silently drops
the source.

## Impact

Archive ordering can hide entrypoint source from analysis.

## Remediation

Perform a metadata/magic discovery pass before extracting source entries.
