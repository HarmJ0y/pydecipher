# 007: Corrected PYC Output Follows Symlinks

## Summary

Header repair copies a corrected PYC to a predictable adjacent filename using
`shutil.copyfile()`. A symlink at that destination is followed.

## Affected Code

- `pydecipher/artifact_types/pyc.py:239-266`

## Exploitation

Create `sample.corrected.pyc` as a symlink to a victim file, then analyze a
headerless `sample.pyc` with a version hint. The victim is overwritten with
corrected bytecode. This was reproduced locally.

## Impact

An attacker controlling the analysis directory can overwrite arbitrary files
writable by the pydecipher process.

## Remediation

Use `open_output_file()` for corrected files and reject existing destinations
instead of following or replacing them.
