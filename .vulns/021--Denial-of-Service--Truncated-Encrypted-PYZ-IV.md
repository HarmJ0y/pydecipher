# 021: Truncated Encrypted PYZ IV Crashes Extraction

## Summary

Encrypted PYZ members shorter than the AES IV size reach `AES.new()`.
`ValueError` from the invalid IV is not caught.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:618-642`
- `pydecipher/artifact_types/pyinstaller.py:669-679`

## Exploitation

Mark a PYZ as encrypted and provide a one-byte member. AES initialization
raises an uncaught `ValueError`.

## Impact

A malformed encrypted member terminates archive processing.

## Remediation

Reject encrypted members shorter than 16 bytes and catch cryptographic
parameter errors per member.
