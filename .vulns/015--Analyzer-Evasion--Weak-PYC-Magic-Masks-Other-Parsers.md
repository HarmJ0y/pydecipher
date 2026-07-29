# 015: Weak PYC Magic Masks Other Parsers

## Summary

The PYC detector accepts either marshal marker anywhere in the first 24 bytes.
Artifact dispatch stops at the first accepting parser, and PYC precedes
CArchive, PYZ, PYTHONSCRIPT, and ZIP in the current registry.

## Affected Code

- `pydecipher/artifact_types/pyc.py:124-135`
- `pydecipher/main.py:140-147`
- `pydecipher/artifact_types/__init__.py:13-17`

## Exploitation

Insert `b"c\x00\x00\x00\x00\x00\x00\x00"` into an otherwise valid archive's
first 24 bytes. A patched valid ZIP and a valid CArchive were both accepted by
their real parser and by `Pyc`, but dispatch selected `Pyc`.

## Impact

Malicious frozen applications can suppress correct archive extraction and
evade analysis.

## Remediation

Validate complete PYC headers and marshal structure, assign deterministic
parser priorities, and continue dispatch when a parser cannot actually unpack.
