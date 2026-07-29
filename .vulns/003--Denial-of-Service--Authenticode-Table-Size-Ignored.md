# 003: Authenticode Table Size Is Ignored

## Summary

Certificate parsing slices from the security directory offset through the end
of the PE instead of honoring the directory's declared size. A zero-filled
overlay is processed as a long sequence of invalid certificate records.

## Affected Code

- `pydecipher/artifact_types/pe.py:217-235`

## Exploitation

Declare a small certificate table and append a large zero-filled overlay.
Zero-length records advance eight bytes at a time while repeatedly invoking
ASN.1 parsing and logging failures.

## Impact

Hostile PEs can cause excessive CPU use, allocation, and log volume.

## Remediation

Slice exactly `VirtualAddress:VirtualAddress+Size`, reject records shorter than
eight bytes or with invalid lengths, and cap certificate count.
