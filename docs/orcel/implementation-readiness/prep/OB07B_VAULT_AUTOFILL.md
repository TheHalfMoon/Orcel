# OB-07b: saved-login autofill through the browser vault

**Status: decided and implemented on `browser/ob07b-vault-autofill` (SG-000135 work packet OB-07, second half; acceptance FA-I in part). Not merged. Unit and source-scan tests only. No live sign-in, no founder-present run.**

The first half of OB-07 (PR #810) hands every sign-in page to the person ([`OB07_CHALLENGE_HANDOFF.md`](OB07_CHALLENGE_HANDOFF.md), section 6: "a sign-in page is handed to the person"). This packet had to decide whether Orcel can instead let the browser's own password manager fill a saved login for a persistent Orcel-managed profile, without Orcel ever handling the secret.

## 1. Decision

**No safe mechanism exists today, so Orcel does not trigger saved-login autofill.** A sign-in page stays a `needs_you` page of kind `sign_in`. The person signs in, either by typing the password or by choosing the browser's own saved password in a Visible session's window. OB-06 holds the session while the person types. On a persistent Orcel-managed profile (OB-04), the sign-in and any password the person saved there carry over to later sessions on that profile. Orcel adds no credential store, tool or preference.

Fail closed: until a later packet finds and qualifies a mechanism that meets every rule in section 2, no `browser_full` tool fills, triggers, reads or stores a login.

## 2. The rules a mechanism had to meet

From SG-000135 (rule change on SG-000122, the excluded donor features `credentials`, `payment_cards` and `evaluate_in_page`) and the founder documents:

- The agent, orceld, the MCP server, logs and receipts never see, read, transmit or type a password or other credential.
- No page script. No OS input, focus or clipboard. No cross-origin frame.
- No credential store in Orcel. Passwords live only in the browser's own vault, which the person controls.
- A spoofed origin must fail. The browser's own vault binds each saved login to its origin, and Orcel must not weaken that.

## 3. What the engine offers, checked

Engine: Edge 157 (Chromium 157 family), driven by Playwright over `--remote-debugging-pipe`. The protocol surface was read from the Playwright protocol types the worker builds against (`playwright-core/types/protocol.d.ts`).

| Candidate | What it does | Verdict |
|---|---|---|
| CDP `Autofill.trigger` | Fills a form from a credit card or an address that the **caller** passes in (`card` or `address`, mutually exclusive). It has no password or saved-login variant. `Autofill.setAddresses`, `enable` and `disable` are address-only too. | Unusable: the caller would have to hold the data, which is the opposite of the rule. Payment cards stay excluded. |
| CDP `WebAuthn` | Installs a virtual authenticator. | Excluded by SG-000135 (a passkey bypass). |
| Any other CDP domain | No domain reads, lists, triggers or accepts a password-manager entry. | Nothing to use. |
| The browser's suggestion popup | When a person focuses a username or password field, the browser shows its own saved-login list. It is browser UI, not a page node, so no snapshot node or page click reaches it. Choosing an entry by keys (ArrowDown, then Enter, sent as page key events) depends on undocumented browser behaviour, and headless (Shadow) has no popup. If no popup is open, the same Enter submits the form with whatever is in it, which is a high-impact action that cannot be predicted. Edge may also ask for the Windows device password or Windows Hello before it fills ("Ask for device password before autofilling"), and that prompt is the person's alone. | Rejected: unreliable, a hidden submit, and a presence check Orcel may not answer. |
| Fill on page load | For a single saved login on an origin, Chromium can fill the form itself when the page loads. It holds the password back from the page until a user gesture, and Orcel cannot ask for it or see whether it happened without reading the field's value. A later agent click is a gesture that releases the value to the page. Submitting the form is a high-impact action, and the `sign_in` detector holds the page anyway (a visible password field), so the agent could never press submit. | Not a mechanism: not triggerable, not observable without reading the secret, and it would need a submit that the gate refuses. |
| Page script (`evaluate_in_page`) | Could call the Credential Management API or read the field. | Excluded. |
| Reading the profile's `Login Data` | Would be Orcel reading the secret. | Forbidden. |

So the only path through the browser's vault that keeps the secret out of Orcel is the one the person drives: in a Visible window, the person focuses the field and picks the browser's suggestion. That is what the `sign_in` guidance now says.

## 4. What changed

- **`needs_you` guidance per kind** (`crates/orceld/src/browser_broker.rs`, `needs_you_guidance`). A `sign_in` page now has its own guidance:
  - Visible: the person signs in in this session's window, by typing or by choosing the browser's own saved password. Orcel never fills, reads or types a password. Once the page no longer needs the person (about three seconds after the sign-in form is gone), the agent observes it again before acting.
  - Shadow: a Shadow session has no window for the person and Orcel never fills a password. Close the session. The person signs in once in a Visible session on a persistent Orcel-managed profile, where the browser's own saved password can fill it when the person chooses. Then run the task again on that profile.
  - Other kinds keep their guidance unchanged. The handoff values (`visible_window`, `rerun_in_visible`), the `reason`, the failure code (`HUMAN_VERIFICATION_REQUIRED`) and the shape are unchanged, so no contract, schema or agent guidance changes.
- **Source scan** (`crates/orceld/tests/ob07b_vault_scan.rs`). It covers the browser host crate, the session-state crate, the browser provider, every orceld source, the worker and the MCP server (tests and fixtures excluded, comments allowed). It fails if any of them calls the CDP `Autofill` or `WebAuthn` domains, names the profile's `Login Data`, `Web Data` or `Cookies` stores or the `os_crypt` key, touches the password-manager preferences, reads or writes cookies in bulk (`Storage.getCookies`, `Network.getCookies`, Playwright `cookies()`, `addCookies`, `storageState`), or names a `browser_autofill`, `browser_login`, `browser_password`, `browser_credential` or `browser_sign_in` tool. A later packet that finds a safe mechanism must change this test and this document together.
- The same test pins the worker's secret-field selectors (password type, `current-password`, `new-password`, `one-time-code`), so fill and type stay refused on credential fields.

## 5. Why not the alternatives in the brief

- **A `browser_autofill_login` tool.** It would need a mechanism from section 3, and none qualifies. Adding a tool that always answers `needs_you` would only duplicate the detector. Under SG-000079 it would also change the tool surface tables, the README and TOOL_CONTRACT for no gain.
- **Holding the sign-in back in Shadow until a saved login fills on load.** Not observable without reading the field (section 3).
- **An Orcel credential broker.** The founder's Shadow spec mentions a "dedicated encrypted password/credential broker". This packet does not build one. The brief forbids inventing a credential store in Orcel, and the browser's own vault already exists in each persistent profile. A broker would be a separate grain with its own security judge.

## 6. Limits

- **FA-I is met in part.** "A real challenge is handed to the person" and "no secret appears in prompts, logs or receipts" hold for sign-in pages, as in OB-07. "Saved-login autofill succeeds through the browser vault" holds only when the person chooses the saved login in a Visible window. Orcel never starts it. "A spoofed origin fails" is the browser vault's own origin binding, not an Orcel check, and it is not tested here.
- **Shadow cannot sign in.** A Shadow session that meets a sign-in page ends there. The person signs in once in a Visible session on the same persistent profile. Cookies then carry the sign-in into later Shadow runs, until the site expires them.
- **Ephemeral profiles keep nothing.** A sign-in in an ephemeral session is lost when the session ends.
- **The detector's known false negatives stay** (OB07_CHALLENGE_HANDOFF.md, section 2). For example, a password field with no form and no button is not flagged. Fill and type stay refused on it either way.
- **A person's saved passwords live in the profile folder,** encrypted by the engine under the person's Windows account. Orcel's tools never expose profile files. A local process running as the same Windows account is outside what Orcel can stop.
- **Edge's device-password prompt** before autofill, where Edge shows it, is answered by the person. Orcel never answers a Windows security prompt.

## 7. Not done

- No live test of a person choosing a saved login. A scripted test cannot be the person, and an agent must never enter a password, not even a dummy one. The founder-present run should cover: save a dummy login on a throwaway local fixture in a Visible session on a throwaway persistent profile, close the session, open a new Visible session on that profile, and check that the person can pick the saved login, that the page resumes after the form is gone, and that no receipt, log or reply holds the dummy password.
- No spoofed-origin test (it tests the browser's vault, not Orcel).
- No Orcel credential broker, and no address autofill. CDP's address autofill takes the data from the caller, and Orcel has no address store.
- The `browser_takeover` tool for an explicit person takeover of a Visible page stays open (OB07_CHALLENGE_HANDOFF.md, section 3).
- Security judge: this packet touches authority and credentials, so it needs a fresh-context security review before merge.
