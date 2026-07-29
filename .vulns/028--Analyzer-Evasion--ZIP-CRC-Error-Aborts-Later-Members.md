# 028: ZIP CRC Error Aborts Later Members

## Summary

`BadZipFile` is caught around the entire member loop rather than around each
member read.

## Affected Code

- `pydecipher/artifact_types/zip.py:129-168`

## Exploitation

Corrupt the CRC of an early member and place valid payloads afterward. The CRC
failure exits the complete extraction loop, so later members are never written.

## Impact

A disposable corrupt member can hide all subsequent ZIP contents from
analysis.

## Remediation

Catch CRC and read errors per member and continue with later entries.
