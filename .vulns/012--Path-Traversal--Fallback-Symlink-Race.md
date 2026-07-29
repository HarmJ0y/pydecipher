# 012: Fallback Output Symlink Race

## Summary

On platforms without descriptor-relative `O_NOFOLLOW` operations, containment
is checked before creating a temporary file and replacing the destination.
An attacker can swap a checked parent directory for a symlink between those
operations.

## Affected Code

- `pydecipher/utils.py:248-257`

## Exploitation

Force the fallback path, then concurrently replace an output parent directory
with a symlink after validation but before `NamedTemporaryFile` or
`os.replace()`.

## Impact

Archive extraction can write outside the intended output root on affected
platforms.

## Remediation

Fail closed when secure descriptor-relative operations are unavailable, or
implement an equivalent platform-specific no-follow directory traversal.
