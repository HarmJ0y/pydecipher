# 018: Archive Extraction Replaces Existing Files

## Summary

ZIP, CArchive, and PYZ extraction atomically rename output over existing
regular files without warning or collision policy.

## Affected Code

- `pydecipher/artifact_types/zip.py:154-166`
- `pydecipher/artifact_types/pyinstaller.py:390-393,683-685`
- `pydecipher/utils.py:223-255`

## Exploitation

Extract a member named `victim` into a reused output directory containing an
existing `victim`. The archive payload replaces the prior contents. This was
reproduced for ZIP and CArchive.

## Impact

Analyzing an untrusted archive can destroy existing project files or prior
analysis evidence.

## Remediation

Reject occupied destinations by default or create a fresh output root per run.
Provide overwrite behavior only as an explicit option.
