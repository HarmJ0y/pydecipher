# 020: ZIP Processing Includes Stale Output Files

## Summary

After extraction, ZIP handling recursively processes every file already
present in the output directory rather than only files extracted in the
current run.

## Affected Code

- `pydecipher/artifact_types/zip.py:169-181`

## Exploitation

Reuse an output directory containing a stale archive or a file symlink to an
external target, then extract a benign ZIP. The stale or external file is
passed back into artifact dispatch. This was reproduced locally.

## Impact

One job can process another job's files, follow preexisting file symlinks, and
trigger extraction or decompilation side effects outside its intended input.

## Remediation

Track successfully extracted paths and recurse only into that exact set.
