# 013: Cleanup Follows a Symlinked Parent

## Summary

The final Py2Exe cleanup searches recursively for `pythonscript_output`,
accepts a symlink to an external directory, and then calls `shutil.rmtree()` on
version-named children reached through that symlink.

## Affected Code

- `pydecipher/main.py:307-308`
- `pydecipher/artifact_types/py2exe.py:230-245`

## Exploitation

Create `output/pythonscript_output` as a symlink to an external directory
containing `3.8/valuable.txt`. Cleanup treats the external version directory as
an output artifact and deletes it recursively. This was reproduced locally.

## Impact

An attacker controlling the output tree can delete arbitrary version-named
directories writable by the pydecipher process.

## Remediation

Do not recursively discover cleanup roots. Track directories created by the
current run and operate through descriptor-relative, no-follow paths.
