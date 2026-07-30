# File-Based Vulnerability Audit

## Scope

Reviewed archive/resource extraction, corrected and decompiled bytecode
outputs, recursive file discovery, relocation and deletion, log/remapping
outputs, temporary files, nested output naming, certificate/overlay writes,
and the standard-bytecode collection utility.

## Finding and Test Matrix

| Finding | Sad-path regression | Happy-path coverage |
| --- | --- | --- |
| Archive path traversal and symlink escape | `test_zip_extraction_rejects_*`, `test_*archive_skips_traversal_entries`, `test_dump_resource_rejects_*` | ZIP, PE, and PyInstaller integration tests |
| Existing archive output replacement | `test_*does_not_replace_existing_file` | archive integration tests |
| Predictable log symlink overwrite | `test_log_write_rejects_symlink_destination`, `test_remap_log_write_rejects_symlink_destination` | `test_log_write_creates_new_file` |
| Log reopen replacement race | `test_open_existing_file_rejects_replaced_*` | `test_open_existing_file_appends_to_expected_inode` |
| Adjacent source overwrite | `test_decompile_does_not_replace_adjacent_source` | bytecode integration tests |
| Corrected PYC symlink overwrite | `test_corrected_pyc_does_not_follow_symlink` | PYC integration paths |
| Py2Exe output symlink overwrite | `test_py2exe_output_does_not_follow_symlink` | Py2Exe integration tests |
| Insecure fallback writes/directories | `test_*fails_closed_without_secure_dir_fd` | `test_open_output_file_writes_nested_member_atomically`, `test_make_output_directory_creates_nested_directory` |
| Cleanup arbitrary deletion | `test_cleanup_does_not_delete_through_symlink` | cleanup is now intentionally non-destructive |
| Relocation overwrite, escape, and source symlink | `test_relocation_rejects_*`, `test_relocation_does_not_replace_existing_destination` | `test_relocation_moves_file_to_contained_destination` |
| Remapping dangling-symlink creation | `test_remapping_output_rejects_dangling_symlink` | remap integration tests |
| PyInstaller path-shape collision | `test_carchive_path_shape_collision_does_not_abort_later_entries` | PyInstaller integration tests |
| ZIP stale-output recursion | `test_zip_recurses_only_into_files_extracted_by_current_run` | same test verifies the current member is processed |
| Stale/symlinked PYC discovery | `test_find_pyc_files_excludes_symlinks_and_preexisting_paths`, `test_decompile_ignores_symlinked_pyc` | bytecode integration tests |
| Nested archive output collision | `test_nested_carchives_use_distinct_output_directories` | PyInstaller integration tests preserve established names |
| Ambient key/version symlink reads | `test_zlibarchive_rejects_symlinked_key_file` | encrypted archive discovery remains supported for regular sidecars |
| PE certificate/overlay unsafe output | `test_certificate_directory_does_not_follow_symlink`, `test_overlay_does_not_replace_existing_file` | PE integration/resource tests |
| Raw output `mkdir()` symlink traversal | `test_zip_does_not_create_output_through_symlinked_parent` | normal extraction/integration tests |
| Standard-bytecode generator overwrite | `test_bytecode_producer_does_not_follow_destination_symlink` | `test_bytecode_producer_copies_to_new_destination` |

## Post-Patch Re-Audit

The original pending findings were patched in isolated commits. A fresh audit
found residual parser, budget, ordering, and atomic-publication issues. See
`POST-PATCH-REAUDIT.md` for the current threat boundary and the happy/sad test
matrix. Its strict acceptance tests describe the desired future remediation.

## Residual Risk

Secure output creation now fails closed on platforms lacking descriptor-relative
`O_NOFOLLOW` support. Some third-party decompilation APIs still require
pathnames, so a hostile local process with concurrent rename access to an
analysis tree can race reads after discovery; preexisting and leaf symlinks are
rejected, but complete descriptor-only input handling would require upstream
API changes or copying every input to a private staging directory.
