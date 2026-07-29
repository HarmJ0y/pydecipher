# 001: Exponential Code-Object Traversal

## Summary

`diff_opcode()` recursively visits nested code objects, but its deduplication
compares code objects against a list containing serialized bytecode. Shared
references are therefore never deduplicated, allowing a small malicious PYC to
cause exponential CPU and memory consumption.

## Affected Code

- `pydecipher/bytecode.py:409-416`

## Exploitation

Construct nested code objects where each parent references the same child many
times, marshal the graph into two PYC inputs, and pass them to `diff_opcode()`.
Each repeated reference is traversed as a distinct subtree.

## Impact

An attacker-controlled bytecode pair can hang or exhaust an analysis worker.

## Remediation

Track visited code objects by identity or a stable digest, and enforce maximum
node and recursion limits while walking constants.
