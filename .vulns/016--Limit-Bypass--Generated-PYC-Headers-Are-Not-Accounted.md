# 016: Generated PYC Headers Bypass Extraction Limits

## Summary

PYZ extraction accounts only for decompressed member bytes, then writes a
generated PYC header in addition to those bytes.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:647-685`
- `pydecipher/utils.py:62-81`

## Exploitation

With one-byte member and total limits, ten empty PYZ members wrote 160 bytes of
headers while the shared budget remained at zero. This was reproduced locally.

## Impact

Actual disk output can exceed configured per-member and total extraction
limits.

## Remediation

Include generated headers and other transformations in payload validation and
commit the exact number of bytes written.
