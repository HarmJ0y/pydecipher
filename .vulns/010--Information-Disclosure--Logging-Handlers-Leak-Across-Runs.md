# 010: Logging Handlers Leak Across Runs

## Summary

Each invocation adds stream and file handlers without removing or closing
previous handlers. In a long-lived process, later analysis logs continue to be
written to earlier output files.

## Affected Code

- `pydecipher/main.py:212-216`
- `pydecipher/__init__.py:152-162`

## Exploitation

Run two analyses with different log paths in one process, then emit a message
during the second run. The message appears in both files. This was reproduced
locally.

## Impact

Artifact paths, errors, and extracted metadata can cross tenant or job
boundaries.

## Remediation

Manage handlers per invocation with `try/finally`, remove and close obsolete
handlers, and avoid mutable process-global logging destinations.
