# 032: Standard Bytecode Generator Follows Output Symlinks

## Summary

`StandardBytecodeGenerator` copied PYC files with `shutil.copyfile()` into a
bind-mounted destination. Existing leaf or parent symlinks could redirect or
replace files outside the intended output subtree.

## Impact

Running the container against an attacker-controlled destination could
overwrite files writable by the container process.

## Remediation

Create destination parents through no-follow directory descriptors and create
each output file exclusively.

