# 031: Stale and Symlinked PYC Discovery

## Summary

Recursive PYC discovery accepted preexisting files and file symlinks from
reused input or output trees. Those paths were passed to decompilation even
though the current extraction had not produced them.

## Impact

One analysis job could process another job's files or read bytecode outside the
selected tree through a symlink.

## Remediation

Snapshot preexisting output paths, process only newly created regular files,
and reject symlinks during discovery and direct decompilation.

