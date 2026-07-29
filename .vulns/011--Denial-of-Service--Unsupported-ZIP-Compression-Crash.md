# 011: Unsupported ZIP Compression Crashes Extraction

## Summary

`archive.open()` can raise `NotImplementedError` or `RuntimeError` for hostile
compression metadata, but the member extraction handler does not catch those
exceptions.

## Affected Code

- `pydecipher/artifact_types/zip.py:154-167`

## Exploitation

Patch a valid ZIP's local and central compression method fields to an
unsupported value such as 99. Validation succeeds, then extraction raises an
uncaught `NotImplementedError`. This was reproduced locally.

## Impact

One malformed member aborts an analysis job or batch.

## Remediation

Catch unsupported-compression exceptions per member, log once, and continue
without aborting the archive.
