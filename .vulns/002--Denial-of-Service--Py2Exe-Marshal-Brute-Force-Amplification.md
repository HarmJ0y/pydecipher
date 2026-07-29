# 002: Py2Exe Marshal Brute-Force Amplification

## Summary

When a PYTHONSCRIPT resource has no reliable version, pydecipher unmarshals the
same attacker-controlled payload once for every xdis magic number. Expensive
marshal structures amplify a small input into prolonged CPU consumption.

## Affected Code

- `pydecipher/artifact_types/py2exe.py:190-207`
- `pydecipher/artifact_types/py2exe.py:260-265`

## Exploitation

Provide a valid PYTHONSCRIPT header followed by a large marshal tuple and no
usable version clues. The parser retries the payload across approximately 256
magic numbers.

## Impact

A small artifact can occupy an analysis worker for minutes or longer.

## Remediation

Bound marshal object counts and depth, cap version attempts, and require an
explicit version hint after a small number of failed probes.
