# 023: WIN_CERTIFICATE Length and Alignment Are Misparsed

## Summary

The WIN_CERTIFICATE `dwLength` includes its eight-byte header, but the parser
extracts and advances by an additional eight bytes. It also ignores required
eight-byte record alignment.

## Affected Code

- `pydecipher/artifact_types/pe.py:217-224`

## Exploitation

Supply multiple valid aligned certificate records. The first record consumes
bytes from the next, and subsequent records are parsed at incorrect offsets.

## Impact

Authenticode evidence can be missed or misattributed, enabling analysis
evasion.

## Remediation

Validate `dwLength >= 8`, extract `dwLength - 8` payload bytes, and advance by
the record length rounded up to an eight-byte boundary.
