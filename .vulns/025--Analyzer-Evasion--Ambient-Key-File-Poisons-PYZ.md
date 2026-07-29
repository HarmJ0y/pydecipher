# 025: Ambient Key File Poisons PYZ Extraction

## Summary

The presence of a sibling `pyimod00_crypto_key.pyc` marks the entire PYZ as
encrypted before a valid key is recovered.

## Affected Code

- `pydecipher/artifact_types/pyinstaller.py:521-566`
- `pydecipher/artifact_types/pyinstaller.py:669-675`

## Exploitation

Place a malformed, stale, or decoy key file beside an unencrypted PYZ. The
extractor attempts decryption and produces no output. Removing the decoy
restores extraction.

## Impact

An untrusted sibling file can suppress analysis of an otherwise valid archive.

## Remediation

Set encrypted mode only after a candidate key successfully decrypts and
decompresses a member; otherwise retry the original bytes as unencrypted data.
