# 029: Verbose State Persists Across Jobs

## Summary

Enabling verbose mode raises handler levels and a global flag, but a later
`verbose=False` call does not restore normal levels.

## Affected Code

- `pydecipher/__init__.py:110-116`
- `pydecipher/__init__.py:130-162`
- `pydecipher/artifact_types/pyinstaller.py:635-636`

## Exploitation

Run one verbose analysis followed by a default analysis in the same process.
The second job still emits DEBUG records, including recovered PYZ encryption
keys. This was reproduced locally.

## Impact

Secrets and artifact metadata can be disclosed to logs or users that did not
request verbose output.

## Remediation

Make logging configuration per-run and explicitly restore handler levels and
global state for false options.
