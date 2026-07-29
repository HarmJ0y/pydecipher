# 006: Decompiler Overwrites Adjacent Source

## Summary

Decompiled output is derived by removing the final `c` from the input PYC path.
The existing-file guard is commented out, so an adjacent source file is
truncated even when decompilation later reports an error.

## Affected Code

- `pydecipher/bytecode.py:301-305`
- `pydecipher/bytecode.py:328-335`
- `pydecipher/bytecode.py:362-370`
- `pydecipher/main.py:289-305`

## Exploitation

Place `victim.pyc` beside a valuable `victim.py` and analyze the PYC. The
decompiler replaces the existing source and may then move it into the selected
output directory.

## Impact

Analyzing untrusted bytecode can destroy user source files.

## Remediation

Write directly into a dedicated output tree using exclusive atomic creation,
and never overwrite an existing source path by default.
