# 008: Py2Exe Output Follows Symlinks

## Summary

PYTHONSCRIPT extraction writes code objects through
`xdis.load.write_bytecode_file()`, bypassing pydecipher's race-resistant output
helper.

## Affected Code

- `pydecipher/artifact_types/py2exe.py:214-228`

## Exploitation

Use a code object whose `co_filename` becomes `victim.pyc` and pre-create that
output path as a symlink. Extraction follows the symlink and truncates the
target.

## Impact

An attacker controlling the output directory can overwrite files writable by
the analysis process.

## Remediation

Serialize bytecode to a securely opened temporary file and atomically commit
it using `open_output_file()`.
