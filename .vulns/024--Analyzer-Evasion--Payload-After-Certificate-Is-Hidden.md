# 024: Payload After Certificate Table Is Hidden

## Summary

When a PE has a certificate table, overlay extraction ends at the certificate
start and ignores all bytes after it, including data following the declared
certificate table.

## Affected Code

- `pydecipher/artifact_types/pe.py:290-305`

## Exploitation

Append `OVERLAY + CERTIFICATE_TABLE + HIDDEN_PAYLOAD` and point the security
directory at the certificate. Only bytes before the certificate are returned
as overlay; the trailing payload is never recursively analyzed.

## Impact

Frozen Python archives or other payloads placed after Authenticode data evade
the extraction pipeline.

## Remediation

Exclude only the declared certificate-table range and preserve both pre-table
and post-table overlay regions for analysis.
