---
title: "CLI Telemetry"
description: "Learn what orcel CLI telemetry collects and how to control it."
---

# CLI telemetry

orcel collects usage data from its CLI to help improve its commands and development experience. You can turn telemetry off at any time.

## What orcel collects

orcel sends the following information to Vercel:

- The orcel version, operating system, CPU architecture, and whether stdin is a terminal.
- The command you ran, its outcome, and setup or onboarding steps when applicable, including connection-ready and first-response timing. When setup or onboarding fails, orcel sends a bounded category describing the failed step. It does not send the underlying error.
- For `orcel dev`, whether you connected to a local or remote agent and whether the UI was interactive or headless.
- Random identifiers for the CLI session, installation, and project, plus whether the installation and project identifiers are ephemeral or persistent.

The project identifier lets orcel group usage from the same project without sending its name or location. orcel derives it from the Git remote when available, otherwise `REPOSITORY_URL` or the working directory, and transforms that value before sending it.

## What orcel does not collect

orcel does not collect command arguments, prompts, agent files, URLs, request headers, error messages, environment variables, file paths, or file contents.

## View telemetry data

Set `ORCEL_TELEMETRY_DEBUG=1` to print the telemetry batch to stderr instead of sending it:

```bash
ORCEL_TELEMETRY_DEBUG=1 orcel info
```

## Turn telemetry off

Disable telemetry for this machine:

```bash
orcel telemetry disable
```

Check its status or turn it back on:

```bash
orcel telemetry status
orcel telemetry enable
```

To disable telemetry for one command without changing the saved setting, set `ORCEL_TELEMETRY_DISABLED=1`:

```bash
ORCEL_TELEMETRY_DISABLED=1 orcel dev
```

On an interactive terminal, orcel displays this information once before it collects telemetry. orcel saves your preference in your platform user configuration directory. In CI and Docker environments, orcel uses fresh in-memory identifiers for each invocation instead of saving them.

Vercel handles CLI telemetry under the [Vercel Privacy Notice](https://vercel.com/legal/privacy-notice).
