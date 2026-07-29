# 027: Nested CArchive Names Share Output Directories

## Summary

Nested archive output names use only the portion of the filename before the
first dot.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:395-403`

## Exploitation

Entries `foo.one.pyz` and `foo.two.pyz` both recursively unpack into
`foo_output`.

## Impact

Distinct nested archives mix and overwrite results, allowing one member to
confuse or suppress evidence from another.

## Remediation

Derive output directories from the complete normalized filename plus a stable
unique identifier.
