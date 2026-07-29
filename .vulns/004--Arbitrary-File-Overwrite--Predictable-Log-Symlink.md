# 004: Predictable Log Symlink Overwrite

## Summary

The CLI creates a timestamp-derived log filename using ordinary truncating
`open("w")`. In an attacker-writable output directory, a pre-created symlink
redirects the write to another writable file.

## Affected Code

- `pydecipher/main.py:261-267`
- `pydecipher/utils.py:445-458`

## Exploitation

Predict the second-resolution filename, create it as a symlink to a victim
file, then cause pydecipher to produce output. The victim is truncated and
replaced with log data. This was reproduced locally.

## Impact

Running pydecipher with greater privileges can overwrite arbitrary files
writable by that process.

## Remediation

Create logs through a no-follow, descriptor-relative exclusive open, or use
`open_output_file()` with collision-resistant names.
