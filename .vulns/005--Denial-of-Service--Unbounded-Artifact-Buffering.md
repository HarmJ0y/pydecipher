# 005: Unbounded Artifact Buffering

## Summary

Artifact constructors read complete hostile files into memory before format
validation or extraction budgets apply. Some paths then duplicate the buffer
through `BytesIO`, decompression, or header repair.

## Affected Code

- `pydecipher/artifact_types/zip.py:80-83`
- `pydecipher/artifact_types/pyinstaller.py:135-138,487-490`
- `pydecipher/artifact_types/pe.py:90-93`
- `pydecipher/artifact_types/pyc.py:81-84,175-190`
- `pydecipher/artifact_types/py2exe.py:61-64`

## Exploitation

Submit a multi-gigabyte file with enough valid prefix or suffix metadata to
reach the relevant parser.

## Impact

The process can be terminated by memory exhaustion before configured
extraction limits provide protection.

## Remediation

Add a maximum input size, stream formats where possible, and avoid duplicating
whole-file buffers.
