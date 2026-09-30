---
title: "CLI Telemetry"
description: "Learn what kaf CLI telemetry collects and how to control it."
---

# CLI telemetry

kaf collects usage data from its CLI to help improve its commands and development experience. You can turn telemetry off at any time.

## What kaf collects

kaf sends the following information to Vercel:

- The kaf version, operating system, CPU architecture, and whether stdin is a terminal.
- The command you ran, its outcome, and setup or onboarding steps when applicable, including connection-ready and first-response timing. When setup or onboarding fails, kaf sends a bounded category describing the failed step. It does not send the underlying error.
- For `kaf dev`, whether you connected to a local or remote agent and whether the UI was interactive or headless.
- Random identifiers for the CLI session, installation, and project, plus whether the installation and project identifiers are ephemeral or persistent.

The project identifier lets kaf group usage from the same project without sending its name or location. kaf derives it from the Git remote when available, otherwise `REPOSITORY_URL` or the working directory, and transforms that value before sending it.

## What kaf does not collect

kaf does not collect command arguments, prompts, agent files, URLs, request headers, error messages, environment variables, file paths, or file contents.

## View telemetry data

Set `KAF_TELEMETRY_DEBUG=1` to print the telemetry batch to stderr instead of sending it:

```bash
KAF_TELEMETRY_DEBUG=1 kaf info
```

## Turn telemetry off

Disable telemetry for this machine:

```bash
kaf telemetry disable
```

Check its status or turn it back on:

```bash
kaf telemetry status
kaf telemetry enable
```

To disable telemetry for one command without changing the saved setting, set `KAF_TELEMETRY_DISABLED=1`:

```bash
KAF_TELEMETRY_DISABLED=1 kaf dev
```

On an interactive terminal, kaf displays this information once before it collects telemetry. kaf saves your preference in your platform user configuration directory. In CI and Docker environments, kaf uses fresh in-memory identifiers for each invocation instead of saving them.

Vercel handles CLI telemetry under the [Vercel Privacy Notice](https://vercel.com/legal/privacy-notice).
