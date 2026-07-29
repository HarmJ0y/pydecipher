# 030: Log Reopen Symlink Race

## Summary

The CLI safely created a log and then reopened its pathname with
`logging.FileHandler`. An attacker controlling the output directory could
replace the pathname with a symlink between those operations and redirect
later log appends.

## Impact

Analysis logs could be appended to an arbitrary writable file.

## Remediation

Reopen the log through no-follow directory descriptors and verify the created
file identity before attaching the logging handler.

