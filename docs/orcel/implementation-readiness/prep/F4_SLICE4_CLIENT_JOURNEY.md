# F4 slice 4 runbook: the client journey with your approval

**Status: READY TO RUN.** This is SG-000127 slice 4 (#446). Every step is prepared except the one only you can do: answering Orcel's local approval prompt. **About 15 minutes.** It costs nothing and publishes nothing.

An agent must never answer this prompt: that would be manufacturing consent. So this tool approves nothing and never talks to orceld or the client. It only prepares a scratch folder and checks the evidence afterwards.

## What it proves

One supported client, at the exact version you record, drives a report task through an installed orceld over local stdio:

| Path | Who decides | Expected result |
|---|---|---|
| Approved report | **You: Yes** | Report created; the independent checker verifies it |
| Denied report | **You: No** | `APPROVAL_DENIED`; nothing written |
| Existing destination | orceld, before any prompt | Refused; your file untouched |
| Changed source | orceld, before any prompt | `TARGET_STALE`; nothing written |

It proves that client version only, not every client.

## Before you start

- Windows, with the Claude Code CLI installed (`claude --version`). Codex works the same way through `examples/mcp-clients/codex-config.toml`.
- Rust and Node.js on PATH. `cargo` runs the kit; Node.js is an Orcel prerequisite.
- An unsigned release candidate of the commit you are testing, from its CI run:

```bash
gh run download <CI run id> --repo TheHalfMoon/Orcel --name orcel-release-candidate-<commit sha> --dir orcel-rc
```

Unsigned means Windows may warn. This is a development build, **not a release**.

## Steps

### 1. Install and prepare

From a checkout of the same commit:

```bash
orcel-rc/orcel.exe install --node "$(where node | head -1)"
```

```bash
cargo run -p orcel-lifecycle --example f4_journey -- prepare C:/orcel-f4-journey
```

```bash
orcel workspace add default "C:/orcel-f4-journey"
```

Install puts `orcel` on PATH; open a new terminal if it isn't found. If you already have a workspace named `default`, note it first: this journey needs the scratch folder as its default workspace.

### 2. Start the client and record what it is

```bash
cd C:/orcel-f4-journey && claude --version && orcel version
```

```bash
cd C:/orcel-f4-journey && claude
```

The scratch folder's `.mcp.json` launches `orcel mcp stdio`. Accept the project's MCP server when asked.

### 3. Paste these prompts, one at a time

**A. List the tools (the shell is not available).** No prompt appears.

> List the Orcel tools you have. Say whether any of them can run a shell or a process.

**B. Approved.** A Windows message box titled **Orcel approval SOFT** appears, naming the action, target, size and digest. No is the default button. **Read it, then click Yes.**

> Using Orcel's report tools: call report_start with title "Q3 revenue", sources ["data/q3.csv"] and folder "reports". Write a one-paragraph report with the total revenue in dollars. Call report_preview with name "q3.md", then report_commit with the same content and the sha256 the preview returned. Show me each tool result.

Expected: `state: verified`, with the checker's result.

**C. Denied.** The message box appears again. **Click No.**

> Start a new report task the same way, for a report named "q3-denied.md", preview it, and commit it. Show me the result. If it is refused, do not try again.

Expected: `APPROVAL_DENIED`. `reports/q3-denied.md` does not exist.

**D. Existing destination.** No prompt appears.

> Start a new report task the same way, and try to preview a report named "taken.md". Show me the result. Do not choose another name.

Expected: refused, because the destination exists. `reports/taken.md` is unchanged.

**E. Changed source.** First ask for the preview:

> Start a new report task the same way, for a report named "q3-stale.md", and preview it. Do not commit yet.

In a second terminal, change the source:

```bash
cargo run -p orcel-lifecycle --example f4_journey -- change-source C:/orcel-f4-journey
```

Then back in the client. No prompt appears:

> Now commit that report. Show me the result. If it is refused, do not try again.

Expected: `TARGET_STALE`.

### 4. Save the transcript

In Claude Code, run `/export` and save to `C:/orcel-f4-journey-transcript.txt`, outside the workspace. Copying the terminal's text into that file also works.

### 5. Check the evidence

```bash
cargo run -p orcel-lifecycle --example f4_journey -- evidence C:/orcel-f4-journey --client "Claude Code <version>" --transcript C:/orcel-f4-journey-transcript.txt
```

It reads orceld's own journal (`%LOCALAPPDATA%\Orcel\report-tasks.jsonl`), which records steps and outcomes but never file contents, and the workspace. It prints `PASS` or `FAIL` for each path and writes:

- `evidence/summary.json`: the client, tasks, states and checks;
- `evidence/transcript.redacted.txt`: the transcript through Orcel's log redactor.

Attach both to #446. **Read the redacted transcript before attaching it**: the redactor catches credentials, not everything you might not want public, and #446 is a public issue.

### 6. Afterwards

```bash
orcel workspace remove default
```

Restore your earlier `default` workspace if you had one. `orcel uninstall` removes the release if you installed it only for this.

## What this leaves open

- **Prompt A** is read by a person: the kit doesn't parse the client's answer.
- **The installed-release journey through uninstall** and **stop and takeover** are other acceptance items, not this one.
- **Signing stays an open gate.** This is engineering evidence on an unsigned build.
