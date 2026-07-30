# Post-Patch File-Based Re-Audit

## Threat Boundary

The primary boundary is a fresh malware-analysis job processing an arbitrary
PE/PyInstaller input and writing to a new output tree. The re-audit also covers
the broader CLI surfaces and a same-user process able to modify a shared output
directory concurrently. No archive member is assumed trustworthy.

## Re-Audit Findings and Coverage

All re-audit findings are now remediated and their acceptance tests run as
ordinary regressions.

| Finding | Reachable input and impact | Sad-path acceptance test | Happy-path control |
| --- | --- | --- | --- |
| 001 | Shared code-object DAGs cause exponential work during opcode remapping. | `test_code_object_traversal_processes_each_object_once` | Existing opcode diff tests |
| 002 | A versionless Py2Exe resource triggers hundreds of marshal probes. | `test_py2exe_version_probes_are_bounded` | Py2Exe tests with a supplied magic |
| 009 | PYZ TOCs materialize beyond `max_members`; CArchive's module pre-scan copies every overlapping payload. | `test_pyz_toc_respects_member_limit_during_parsing`, `test_carchive_magic_prescan_does_not_copy_every_member_payload` | Existing bounded CArchive and PYZ parsing tests |
| 010 | A long-lived process keeps the previous job's log handler open and appends later-job metadata. | `test_new_logging_job_detaches_previous_file` | Existing secure log creation/reopen tests |
| 015 | A recognized magic plus a marker, without marshal validation, still lets PYC mask a valid CArchive. | `test_pyc_detector_rejects_non_pyc_with_recognized_header` | Existing genuine/headerless PYC tests |
| 016 | CArchive source reconstruction still writes an uncharged generated PYC header. | `test_carchive_budget_accounts_for_generated_header` | Existing PYZ exact-output accounting test |
| 034 | CArchive ignores `length_of_package` when interpreting offsets and selects the first magic instead of the final cookie. | `test_carchive_uses_cookie_package_start`, `test_carchive_selects_final_valid_cookie` | Ordinary CArchive extraction tests |
| 035 | A valid key-sidecar PYC containing non-string constants raises `TypeError` during key discovery. | `test_pyz_key_discovery_ignores_non_string_constants` | Ordinary and absent-key discovery tests |
| 036 | A malformed encrypted entry consumes all candidate keys, suppressing later valid encrypted modules. | `test_corrupt_pyz_member_does_not_discard_key_for_later_members` | Valid encrypted-member extraction behavior |
| 037 | Invalid UTF-8 in one CArchive TOC name aborts all later records. | `test_carchive_skips_malformed_name_and_parses_later_entry` | Existing multi-record TOC tests |
| 038 | A password-protected ZIP member raises `RuntimeError` and aborts later unencrypted members. | `test_encrypted_zip_member_is_skipped_and_later_member_extracts` | Existing unsupported-compression and CRC isolation tests |
| 039 | A same-user writer can replace the visible temporary pathname before hard-link publication, causing a symlink to become the final output. | `test_atomic_output_rejects_replaced_temporary_name` | `test_open_output_file_writes_nested_member_atomically` |
| 040 | One deeply nested member name creates an unbounded descriptor/directory chain inside the output root. | `test_member_path_depth_is_bounded` | Existing nested-member extraction tests |
| 041 | Py2Exe-produced PYC files are not charged to the recursive extraction budget. | `test_py2exe_output_is_charged_to_extraction_budget` | Existing Py2Exe output test |
| 042 | Invalid UTF-8 in a plausible Py2Exe archive-name field escapes constructor rejection and aborts dispatch. | `test_py2exe_rejects_invalid_archive_name_encoding` | Existing valid Py2Exe header tests |
| 043 | A malformed but matching PE resource tree raises before other resources can be processed. | `test_malformed_pe_resource_is_skipped` | Existing valid PE resource tests |
| 044 | Non-UTF-8 PE VERSIONINFO strings abort extraction before overlay/resource handling. | `test_invalid_pe_version_strings_are_ignored` | Existing version-info integration behavior |

## Filesystem Conclusions

The post-patch archive write paths reject parent traversal, absolute/drive
paths, existing destinations, stable symlinks, and symlinked output parents.
Cleanup no longer deletes extraction output, so no malicious-binary-only
arbitrary-delete flow remains. Finding 039 requires concurrent write access to
the output tree; the other findings are reachable through file contents alone.

The acceptance tests now fail normally on any regression.
