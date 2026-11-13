# F4 slice 4 runbook: the client journey with your approval

**Status: READY TO RUN.** This is SG-000127 slice 4 (#446). Every step is prepared except the one only you can do: answering Orcel's local approval prompt. **About 15 minutes at the prompt, plus about 20 for CI to build the release candidate and kit first.** It costs nothing, and the only things it makes available are that build and its kit, for 3 days.

An agent must never answer this prompt: that would be manufacturing consent. So this tool approves nothing and never talks to the client. It prepares a scratch folder, asks `orcel doctor` for `orceld`'s status once in `ready`, which requests no approval, and checks the evidence afterwards.

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
- **At the keyboard, on your own unlocked desktop**, not over SSH or as a service. Orcel doesn't check this: elsewhere the message box shows nowhere, and the client just waits until it gives up.
- **Git Bash** for the commands here, unless a step says otherwise. Some won't work in PowerShell or Command Prompt.
- Node.js on PATH, an Orcel prerequisite, and the GitHub CLI (`gh`).
- An unsigned release candidate of the commit you are testing, and the kit built with it. CI builds both on every run and keeps them only when asked, for 3 days, so ask for them when you're ready to run this. They can be downloaded by others during those days, for as long as the repository is public. Start a run on `main`:

```bash
gh workflow run CI --repo TheHalfMoon/Orcel --ref main
```

```bash
gh run list --repo TheHalfMoon/Orcel --workflow CI --event workflow_dispatch --limit 1 --json databaseId,headSha,status,conclusion
```

That gives the run id and commit SHA for the next commands. Right after starting a run it can still show the previous one, so check that its `status` isn't `completed`, or ask again after a few seconds.

Wait for one job, not the whole run. **Release qualification** takes about 15 minutes, and a whole run from 30 minutes to over 3 hours, depending on the runners. The artifacts are there once that job has passed, even if the run is later marked failed, for example by a cancelled macOS job:

```bash
gh run view <CI run id> --repo TheHalfMoon/Orcel --json jobs --jq '.jobs[] | select(.name | startswith("Release qualification")) | .status + " " + .conclusion'
```

```bash
gh run download <CI run id> --repo TheHalfMoon/Orcel --name orcel-release-candidate-<commit sha> --dir orcel-rc
```

```bash
gh run download <CI run id> --repo TheHalfMoon/Orcel --name orcel-f4-kit-<commit sha> --dir orcel-kit
```

If a download finds nothing while the run is still going, wait for the run to finish. The first artifact holds `orcel-<version>-windows-x64.zip` with its manifest, SBOM and checksums. **Extract the zip** into `orcel-rc/release`: `orcel.exe` needs `manifest.json` beside it. The second is `f4_journey.exe`, the kit. Run the kit's commands below from the folder holding `orcel-rc` and `orcel-kit`.

Unsigned means Windows may warn, and Defender may hold these files. This is a development build, **not a release**.

With a Rust toolchain (MSVC Build Tools included), you can instead check out the commit and replace `orcel-kit/f4_journey.exe` below with `cargo run -p orcel-lifecycle --example f4_journey --`, about 5 minutes to compile. That kit compares the release candidate with your checkout, so run it from there and give the full path to `orcel-rc`.

## Steps

### 1. Install and prepare

```bash
orcel-rc/release/orcel.exe install --node "$(where node | head -1)"
```

If install says earlier Orcel state is waiting on a decision, run `orcel-rc/release/orcel.exe state status`, then `state migrate` or `state keep-separate`. Neither deletes it. Then install again.

Install puts `orcel` on PATH; open a new terminal if it isn't found, and go back to the folder holding `orcel-rc` and `orcel-kit`. **If Orcel is already installed under `%USERPROFILE%\.orcel`** at another version, install refuses. Use `orcel update --source orcel-rc/release` instead, and `orcel rollback` in step 6. An install from before the move, under `AppData\Local\Orcel`, can't update across: install this one, and remove that one with its own `orcel uninstall`. At the same version, install replaces what's there, and you can't roll back to the build it replaces.

**The scratch folder must be the only workspace.** Orcel uses the first configured workspace as the default, and an existing id is refused. So first run `orcel workspace list`, write down what's there, and `orcel workspace remove <id>` each one. You restore them in step 6. Removing a workspace from configuration never touches its files.

```bash
orcel-kit/f4_journey.exe prepare C:/orcel-f4-journey
```

```bash
orcel workspace add default "C:/orcel-f4-journey"
```

Then check that everything is in place. It reads the configuration and asks `orcel doctor` whether `orceld` answers. It approves nothing and starts no client:

```bash
orcel-kit/f4_journey.exe ready C:/orcel-f4-journey --release-candidate orcel-rc
```

Every check should say `PASS`. It also checks that the release candidate was built from the same commit as the kit, using its provenance file, and that its zip is the file that provenance hashed. `orcel-rc` is the folder you downloaded the artifact to, and not the extracted `release` folder.

**If orceld won't start.** Orcel keeps its state in `%USERPROFILE%\.orcel`, private to you. `orceld` refuses that folder if anyone else could delete from it, or rename it or a folder above it, and `ready` and `orcel doctor` name what they found. That check must not be weakened. Windows gives a profile's root only to you, SYSTEM and Administrators, so this should only happen if something has changed the permissions on your profile folder. Find out what did and decide from there. You don't need another Windows account.

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

**B. Approved.** A Windows message box titled **Orcel approval SOFT** appears, naming the action, target, size and digest. If you don't see it, check the taskbar. No is the default button. **Read it, then click Yes within 5 minutes.** Orcel treats a later Yes as denied, and the client reports `APPROVAL_DENIED`. If that happens, ask it to commit again, and answer the new box. That retried report still counts as approved, not as the denied path of C.

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

In a second terminal, in the folder holding `orcel-kit`, not the scratch folder, change the source:

```bash
orcel-kit/f4_journey.exe change-source C:/orcel-f4-journey
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

**G. The task history.** With the client still open, in another terminal, open the Windows app from the install:

```bash
orcel app
```

Type `tasks` and press Enter. Expected, with shell and process sessions labelled unavailable:

- "After the restart", with its title, is `sources read`.
- It says "showing 5 of 6". The app lists the newest five, so **the report from B is the one left out**. It's in the history below. The journal outlives an uninstall, so after an earlier attempt on this PC the app shows more tasks than this, and older ones. A retry needs a new scratch folder (`prepare` refuses one that isn't empty), and the kit reads only that folder's tasks.
- The tasks from before you ended `orceld` have **no title, which is expected**: titles are never written to the journal.
- **The tasks from D and F both show `failed`, which is expected**, with the step `run orceld_run_ended`, because their `orceld` is gone and they can't continue. D's report was refused as intended, and F's was never committed.
- The tasks from C and E keep `approval denied` and `stale`.

Note whether that's what you saw: the kit doesn't read the app. This prints the history from the journal, all six tasks including B's `verified`:

```bash
orcel-kit/f4_journey.exe history C:/orcel-f4-journey
```

It shows what was written, so D and F appear as `observed` and `proposed` with no `run` step. The `failed` state in the app is `orceld` restoring them after the restart. The two views differ for that reason only.

### 4. Save the transcript

In Claude Code, run `/export` and save to `orcel-f4-journey-transcript.txt` in your user folder (`%USERPROFILE%`), outside the workspace. Copying the terminal's text into that file also works. Check that the tool results and the whole `rpt-` task ids are there: the kit looks for them.

### 5. Check the evidence

```bash
orcel-kit/f4_journey.exe evidence C:/orcel-f4-journey --client "Claude Code <version>" --transcript "$USERPROFILE/orcel-f4-journey-transcript.txt"
```

It reads orceld's own journal (`%USERPROFILE%\.orcel\report-tasks.jsonl`), which records steps and outcomes but never file contents, and the workspace. It prints `PASS` or `FAIL` for each path and writes:

- `evidence/summary.json`: the client, tasks, states and checks;
- `evidence/history.json`: each task's steps and outcomes, without file text;
- `evidence/transcript.redacted.txt`: the transcript through Orcel's log redactor.

Attach `summary.json` and `history.json` to #446, which is a public issue in a public repository. SG-000127 also asks for the redacted transcript. **Keep that on your PC, and read it before deciding where it goes**: the redactor catches credentials, not everything you might not want public, such as home paths or other text from your session. Say on #446 that it exists and that you read it, without its path. The kit can't judge prompt A or a client's wording, so a closeout resting on this run names who read the transcript.

### 6. Afterwards

Close the Windows app, and leave the client with `/exit`. An open app or client holds files in the install, which could stop `orcel uninstall` removing them.

```bash
orcel workspace remove default
```

Add back the workspaces you removed in step 1, in their original order. `orcel uninstall` removes the release if you installed it only for this, or `orcel rollback` returns you to the version you updated from.

## What this leaves open

- **Prompt A and the Windows app in G** are read by a person: the kit doesn't parse either.
- **First shown by your run:** the kit's upload and download on a manual run, `ready` against an installed release, the Yes through that release, whether the box takes focus, how long the client waits on a tool call, whether `/export` keeps tool results and whole task ids, and how Defender treats the unsigned files.
- **Rehearsed without you, up to the prompt:** on a real `orceld` and MCP edge in WSL, with a test client and no approval, in this order, the kit passes recovery and the existing destination, and fails approved, denied and stale as it should. The Windows run of F and G, and any real client, are first shown by you.
- **Recovery:** the kit requires a task cut off after its preview, a second `orceld` in the journal and the transcript naming `task_resume_summary` with that task. It looks for the summary's own fields in the transcript, so a client that hides tool results fails this check. It can't tell that you ended `orceld` by hand rather than the client restarting.
- **The installed-release journey through uninstall** and **stop and takeover** are other acceptance items, not this one.
- **Signing stays an open gate.** This is engineering evidence on an unsigned build.
