# F4 slice 4 runbook: the client journey with your approval

**Status: READY TO RUN.** This is SG-000127 slice 4 (#446). Every step is prepared except the one only you can do: answering Orcel's local approval prompt. **About 15 minutes.** It costs nothing and publishes nothing.

An agent must never answer this prompt: that would be manufacturing consent. So this tool approves nothing and never talks to orceld or the client. It only prepares a scratch folder and checks the evidence afterwards.

## What it proves

One supported client, at the exact version you record, drives a report task through an installed orceld over local stdio:

| Path | Who decides | Expected result |
|---|---|---|
| Approved report | **You: Yes** | Report created; the independent checker verifies it |
| Denied report | **You: No** | `APPROVAL_DENIED`; nothing written |
| Existing destination | orceld, before any Orcel prompt | Refused; your file untouched |
| Changed source | orceld, before any Orcel prompt | `TARGET_STALE`; nothing written |
| `orceld` dies mid-task | You end the process; orceld and the client recover | The same session reads what the task did from a new `orceld`; nothing is committed or re-sent |
| Task history | Read-only | The Windows app and the journal both show each task's steps |

It proves that client version only, not every client.

## Before you start

- Windows, with the Claude Code CLI installed (`claude --version`). Codex works the same way through `examples/mcp-clients/codex-config.toml`.
- Rust and Node.js on PATH. `cargo` runs the kit; Node.js is an Orcel prerequisite.
- An unsigned release candidate of the commit you are testing, from its CI run:

```bash
gh run download <CI run id> --repo TheHalfMoon/Orcel --name orcel-release-candidate-<commit sha> --dir orcel-rc
```

The artifact holds `orcel-<version>-windows-x64.zip` with its manifest, SBOM and checksums. **Extract the zip** into `orcel-rc/release`: `orcel.exe` needs `manifest.json` beside it.

Unsigned means Windows may warn. This is a development build, **not a release**.

## Steps

### 1. Install and prepare

From a checkout of the same commit:

```bash
orcel-rc/release/orcel.exe install --node "$(where node | head -1)"
```

```bash
cargo run -p orcel-lifecycle --example f4_journey -- prepare C:/orcel-f4-journey
```

```bash
orcel workspace add default "C:/orcel-f4-journey"
```

Install puts `orcel` on PATH; open a new terminal if it isn't found.

**The scratch folder must be the only workspace.** Orcel uses the first configured workspace as the default, and an existing id is refused. So before `workspace add`, run `orcel workspace list`, write down what's there, and `orcel workspace remove <id>` each one. You restore them in step 6. Removing a workspace from configuration never touches its files.

Then check that everything is in place. It reads the configuration, and approves nothing and starts no client:

```bash
cargo run -p orcel-lifecycle --example f4_journey -- ready C:/orcel-f4-journey
```

Every check should say `PASS`.

### 2. Start the client and record what it is

```bash
cd C:/orcel-f4-journey && claude --version && orcel version
```

```bash
cd C:/orcel-f4-journey && claude
```

The scratch folder's `.mcp.json` launches `orcel mcp stdio`. Accept the project's MCP server when asked.

### 3. Paste these prompts, one at a time

"No Orcel prompt" below means no Orcel message box. Claude Code may still ask its own permission to use a tool; allowing that approves nothing in Orcel.

**A. List the tools.** No Orcel prompt.

> List the Orcel tools you have. Say whether any of them is a shell, and whether any can start a process.

Expected: **no shell tool.** `process_spawn` is listed: it runs one registered executable (argv only, no shell) and needs a trusted workspace. This is the client's view of the SG-000096 shell being unarmed.

**B. Approved.** A Windows message box titled **Orcel approval SOFT** appears, naming the action, target, size and digest. No is the default button. **Read it, then click Yes.**

> Using Orcel's report tools: call report_start with title "Q3 revenue", sources ["data/q3.csv"] and folder "reports". Write a one-paragraph report with the total revenue in dollars. Call report_preview with name "q3.md", then report_commit with the same content and the sha256 the preview returned. Show me each tool result.

Expected: `state: verified`, with the checker's result.

**C. Denied.** The message box appears again. **Click No.**

> Start a new report task the same way, for a report named "q3-denied.md", preview it, and commit it. Show me the result. If it is refused, do not try again.

Expected: `APPROVAL_DENIED`. `reports/q3-denied.md` does not exist.

**D. Existing destination.** No Orcel prompt.

> Start a new report task the same way, and try to preview a report named "taken.md". Show me the result. Do not choose another name.

Expected: refused, because the destination exists. `reports/taken.md` is unchanged.

**E. Changed source.** First ask for the preview:

> Start a new report task the same way, for a report named "q3-stale.md", and preview it. Do not commit yet.

In a second terminal, **in your checkout of the commit**, not the scratch folder, change the source:

```bash
cargo run -p orcel-lifecycle --example f4_journey -- change-source C:/orcel-f4-journey
```

Then back in the client. No Orcel prompt:

> Now commit that report. Show me the result. If it is refused, do not try again.

Expected: `TARGET_STALE`.

**F. `orceld` dies mid-task.** No Orcel prompt in this step. The source changed in E, which doesn't matter here:

> Start a new report task the same way, for a report named "q3-recovered.md", and preview it. Do not commit. Show me the task_id.

In the second terminal, end only `orceld`, as a crash would. Keep the client running. This ends every `orceld` you have running, so close any other client that uses Orcel first. Use **PowerShell or Command Prompt** for this one: Git Bash rewrites the `/F` and `/IM` flags.

```powershell
taskkill /F /IM orceld.exe
```

Then back in the client:

> Call task_resume_summary with that task_id and show me the whole result. If the first call is refused because orceld stopped, call it once more. Do not commit anything.

Expected: the same `task_id`, with `observe` and `preview` among its completed steps and nothing unknown. The first call may be refused, and that request is never re-sent for you, so asking once more is right. `reports/q3-recovered.md` does not exist.

Then one more task, which shows the new `orceld` works, and gives it a task of its own:

> Start a new report task the same way, with the title "After the restart", and show me the result. Do not preview or commit it.

**G. The task history.** With the client still open, in a regular Windows PowerShell at the repository root, build and open the Windows app:

```bash
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\apps\orcel-desktop-preview\build.ps1 -OutputDirectory C:\orcel-f4-app
```

```bash
C:\orcel-f4-app\Orcel.Desktop.exe
```

Type `tasks` and press Enter. Expected, with shell and process sessions labelled unavailable:

- "After the restart", with its title, is `sources read`.
- It says "showing 5 of 6". The app lists the newest five, so **the report from B is the one left out**. It's in the history below.
- The tasks from before you ended `orceld` have **no title, which is expected**: titles are never written to the journal.
- **The tasks from D and F both show `failed`, which is expected**, with the step `run orceld_run_ended`, because their `orceld` is gone and they can't continue. D's report was refused as intended, and F's was never committed.
- The tasks from C and E keep `approval denied` and `stale`.

Note whether that's what you saw: the kit doesn't read the app. From the checkout, this prints the history from the journal, all six tasks including B's `verified`:

```bash
cargo run -p orcel-lifecycle --example f4_journey -- history C:/orcel-f4-journey
```

It shows what was written, so D and F appear as `observed` and `proposed` with no `run` step. The `failed` state in the app is `orceld` restoring them after the restart. The two views differ for that reason only.

### 4. Save the transcript

In Claude Code, run `/export` and save to `C:/orcel-f4-journey-transcript.txt`, outside the workspace. Copying the terminal's text into that file also works.

### 5. Check the evidence

From your checkout:

```bash
cargo run -p orcel-lifecycle --example f4_journey -- evidence C:/orcel-f4-journey --client "Claude Code <version>" --transcript C:/orcel-f4-journey-transcript.txt
```

It reads orceld's own journal (`%LOCALAPPDATA%\Orcel\report-tasks.jsonl`), which records steps and outcomes but never file contents, and the workspace. It prints `PASS` or `FAIL` for each path and writes:

- `evidence/summary.json`: the client, tasks, states and checks;
- `evidence/history.json`: each task's steps and outcomes, without file text;
- `evidence/transcript.redacted.txt`: the transcript through Orcel's log redactor.

Attach them to #446. **Read the redacted transcript before attaching it**: the redactor catches credentials, not everything you might not want public, and #446 is a public issue in a public repository.

### 6. Afterwards

```bash
orcel workspace remove default
```

Add back the workspaces you removed in step 1, in their original order. `orcel uninstall` removes the release if you installed it only for this.

## What this leaves open

- **Prompt A and the Windows app in G** are read by a person: the kit doesn't parse either.
- **Rehearsed without you, up to the prompt:** on a real `orceld` and MCP edge in WSL, with a test client and no approval, in this order, the kit passes recovery and the existing destination, and fails approved, denied and stale as it should. The Windows run of F and G, and any real client, are first shown by you.
- **Recovery:** the kit requires a task cut off after its preview, a second `orceld` in the journal and the transcript naming `task_resume_summary` with that task. It looks for the summary's own fields in the transcript, so a client that hides tool results fails this check. It can't tell that you ended `orceld` by hand rather than the client restarting.
- **The installed-release journey through uninstall** and **stop and takeover** are other acceptance items, not this one.
- **Signing stays an open gate.** This is engineering evidence on an unsigned build.
