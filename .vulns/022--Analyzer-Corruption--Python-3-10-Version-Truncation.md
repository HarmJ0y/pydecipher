# 022: Python 3.10+ Version Truncation Corrupts Analysis

## Summary

Several bytecode paths convert a version by taking three characters and using
`float`. Versions such as `3.10` become `3.1`.

## Affected Code

- `pydecipher/bytecode.py:134-153`
- `pydecipher/bytecode.py:421-437`
- `pydecipher/artifact_types/pyc.py:183-190`

## Exploitation

Repair or remap Python 3.10+ bytecode. Header generation emits an eight-byte
legacy header instead of the required modern header, and opcode arguments can
be interpreted as opcodes.

## Impact

Hostile modern bytecode can produce corrupted repaired files and poisoned
opcode mappings, undermining analysis results.

## Remediation

Use parsed version tuples for all comparisons and add regression coverage for
Python 3.10 through current supported versions.
