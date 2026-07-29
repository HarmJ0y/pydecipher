# 017: Remapping Output Follows Dangling Symlinks

## Summary

Remapping output uses `Path.exists()` for collision detection and then
`open("w")`. A dangling symlink reports as nonexistent but is followed by the
write.

## Affected Code

- `pydecipher/remap.py:174-188`

## Exploitation

Create `remapping.txt` as a symlink to a nonexistent path outside the output
directory. `write_remapping_file()` follows it and creates the external target.
This was reproduced locally.

## Impact

An attacker controlling the output directory can create files elsewhere with
the privileges of pydecipher. A race can similarly redirect overwrites.

## Remediation

Use no-follow, exclusive atomic output creation and treat symlinks as occupied
destinations.
