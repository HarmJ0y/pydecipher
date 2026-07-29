# 033: Raw Output Directory Creation Follows Symlinks

## Summary

ZIP setup, CLI output setup, and certificate extraction used recursive
`mkdir()` before secure file creation. A symlinked output parent could redirect
directory creation outside the intended root.

## Impact

Analysis could create attacker-chosen directory trees with the privileges of
the pydecipher process.

## Remediation

Create every output directory through descriptor-relative `O_NOFOLLOW`
traversal and fail closed where those primitives are unavailable.

