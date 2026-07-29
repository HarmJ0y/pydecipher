# 014: Relocation Follows Destination-Parent Symlinks

## Summary

After decompilation, source files are moved with `Path.rename()` into an output
path constructed without containment or no-follow checks.

## Affected Code

- `pydecipher/main.py:297-305`

## Exploitation

Place a symlink at an output subdirectory that points outside the output root.
Relocating a matching decompiled file follows the symlinked parent and replaces
an external destination file. This was reproduced locally.

## Impact

An attacker controlling the output directory can overwrite files outside it.

## Remediation

Relocate through securely opened directory descriptors, reject symlinked
parents, and use exclusive atomic creation rather than `rename()`.
