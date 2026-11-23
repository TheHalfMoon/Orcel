# Orcel for ChatGPT — Release Notes (submission draft)

Orcel connects ChatGPT to one computer that its owner paired through a Orcel relay. The plugin exposes the remote `core` tool profile only:

- workspace reads: `fs_stat`, `fs_list`, `fs_read`, `fs_read_range`, `fs_search`, `fs_find`, `workspace_get`, `system_status`;
- Git, off until it runs confined (calls are refused with a clear message, nothing is asked and nothing runs): `git_status`, `git_diff`, `git_log`, `git_branch_create`, `git_stage`, `git_unstage`, `git_commit`, `git_fetch_preview`, `git_fetch`, `git_push_preview`, `git_push`;
- approved changes: `fs_write_preview`, `fs_write`, `fs_mkdir`, `fs_move`, `fs_edit`, `fs_remove`;
- registered program runs: `process_spawn`.

Every call requires OAuth 2.1 with the tool's exact scope, an active remote-session lease that the owner started on the computer, and workspace trust. Every change asks for approval on the computer; removal requires Windows Hello presence. Desktop observation, clipboard, and device-side web fetch tools are local-only and are never offered to ChatGPT. There is no shell, no unrestricted file system, and no remote approval.
