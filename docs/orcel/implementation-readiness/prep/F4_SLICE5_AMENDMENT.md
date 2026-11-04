# F4 slice 5: proposed amendment for stop without paid signing

**Status: PROPOSAL, NOT ACTIVE.** Nothing here takes effect until the founder decides on #446. The rule in `protocol/ORCEL_APP_API_1.md` stands: "The first method that changes state or carries authority must add a first-party code requirement before it ships." This builds on the design in `prep/F4_TASK_STOP.md`, whose kernel part is #607.

## The decision

May one authority-reducing method, `task.stop`, ship on the existing app API with peer identity only, without a code-signing identity?

| Option | Unlocks | Cost | Reversible |
|---|---|---|---|
| **1. Sign first**, then check the publisher | Stop, with the caller narrowed to signed apps | A Windows code-signing certificate (paid); macOS needs FD-05 | Yes |
| **2. Amend the rule for this one method (recommended)** | Stop on development and unsigned builds; F4's stop and takeover acceptance items | **None** | Yes: remove the method, or add the publisher check once signing exists |
| **3. No stop in F4** | Nothing; the closeout records stop and takeover as open | None | Yes |

**Why option 2.** The rule exists because a state-changing method could carry authority. This one can only remove it. The worst a same-user caller can do with stop is what it can already do by killing orceld: prevent progress on the user's own task.

## Security assessment

| Question | Finding |
|---|---|
| Can stop gain authority? | No. It only moves a task to a final state. It never approves, writes, retries, resumes or deletes (spec invariant). Tests assert nothing is written after a stop (#607). |
| Who can call it? | The same user only. The endpoint is the existing owner-only named pipe (DACL) or Unix socket (peer credentials), unchanged. It is not on MCP, stdio dispatch, the relay or the cloud. |
| What can a malicious same-user process do? | Stop the user's in-flight report tasks: denial of progress. It can already kill orceld or edit the user's files, so this adds no capability. **Residual, for the founder to accept under this option.** |
| What does signing add? | It narrows the caller to signed apps, on Windows and macOS. On Linux, same-user ptrace makes binary identity unprovable anyway (S-27). It doesn't change what stop can do. |
| Stop racing an approval | Closed by the conditional transitions (#607): an approval granted after a stop writes nothing, and stays spent. |
| A second writer | Stop would be the first. Requests otherwise run one at a time, and the app API only reads. That is exactly what #607 prepares for. |
| Precedent | The amendment admits one named method. It must not be read as permission for any other state-changing method: each later one still needs the first-party requirement. |
| A UI that lies | The app shows the state from `task.updated` and never its own optimistic state. |

**Not qualified yet:** the surface itself (no method exists), the Windows app's Stop control and its UI Automation test, and the open prompt's behaviour below.

## Open question inside this decision

A stop during an open approval prompt refuses the commit, but the Windows message box stays on screen until answered. Answering it then does nothing. The spec's "invalidates any pending approval" is met by the refusal. Closing the dialog itself would be platform-specific UI work. **Recommended: leave the dialog; document it.**

## Takeover

`prep/F4_TASK_STOP.md` section 8 treats takeover as a separate, larger design: handing a task's context to another actor. The **spec's** acceptance item is much narrower:

> Takeover: after stop, the app shows control returned to the user's own session with no agent input pending, and no input authority was added.

That is a label in the app after a stop, adding no authority and no approval semantics. **Recommended: implement the spec's narrow meaning with stop**, and keep any fuller hand-over out of F4.

## Proposed text (applied only on approval)

Added to `protocol/ORCEL_APP_API_1.md`, under Code identity:

> **Exception, founder decision of <date> (#446).** `task.stop` may ship with the peer identity above and no first-party code requirement, because it can only reduce authority: it moves one task of the current orceld run to a final state and never approves, writes, retries or resumes anything. This exception covers that method only. Any other method that changes state or carries authority still needs the first-party code requirement. When signing exists, `task.stop` adds the publisher check.

Added to the methods table: `task.stop`, params `{task_id}`, result `{task_id, state}`; `stopped` added to the closed states. Refused: unknown, foreign or earlier-run tasks (`TARGET_STALE`) and committing tasks.

## What ships if approved

1. Remove `#[cfg(test)]` from `TaskRegistry::stop`; add `task.stop` to the app API, with the workspace taken from the task. Absent from MCP, with the exact-membership tests extended, and refused on the stdio dispatch path.
2. A Stop control and the "control returned to you" label in `apps/orcel-desktop-preview`, showing the kernel's state only, with a UI Automation test against a real install.
3. A native test for the acceptance item: stop during a pending approval, the approval then unusable, and a restart leaves no pending approval.
4. Fresh-context security judge on the exact head (the spec requires one for slice 5).
