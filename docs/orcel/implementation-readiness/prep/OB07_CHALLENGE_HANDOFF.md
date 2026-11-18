# OB-07 challenge handoff ("Needs you")

**Status: PROVISIONAL (SG-000135 work packet OB-07, acceptance A9 in part).** Scripted runs only. The founder-present run and a real-site challenge have not run.

SG-000135 invariant 7: no CAPTCHA, MFA, passkey, WebAuthn or presence bypass or spoofing. The session waits in `AWAIT_HUMAN_VERIFICATION` until the person completes the check. Orcel has no code that solves, skips, fills, clicks or answers a challenge. It does not port BrowserOS `solve_captcha` or any provider, token or virtual-authenticator code.

## 1. What happens

```
agent action on a browser_full session
  -> orceld: read-only challenge check of the active page (LiveBrowser::check_challenge)
       -> host DetectChallenge {status}
            -> worker challenge {url, status}: CDP DOMSnapshot.captureSnapshot (a read; no page script)
               -> classifyChallenge -> closed kind + closed signal names
       <- host checks the vocabulary (challenge::check_report)
  -> found: takeover gate challenge(page, kind, Detected) -> AWAIT_HUMAN_VERIFICATION
  -> takeover gate refuses the action: HUMAN_VERIFICATION_REQUIRED (before any approval prompt)
```

- **Detection points.** The check runs before every page action of a `browser_full` session, and after every action that may open a document or tab (open, click, fill, select and tabs). It also runs on every `browser_task_status` read. While a page waits, the check runs at most once per second (`CHALLENGE_RECHECK`).
- **Refusal.** While a page waits, every agent read and write on it is refused with the new contract code `HUMAN_VERIFICATION_REQUIRED`. That covers snapshot, screenshot, extract, verify, open, click, fill, select and closing its tab. The refusal comes from the takeover gate before any approval prompt. The message starts with `needs_you:` and carries no page text. Other tabs of the session, and other sessions, go on.
- **Status.** `browser_task_status` returns `needs_you`, a list of waiting pages. Each entry has `page_id`, `kind` (`captcha`, `mfa`, `sign_in`, `passkey`, or `other` when the detector could not answer), `signals`, a fixed `reason` and `clearing` (the detector no longer sees the check). It also has `handoff` and `guidance` for the session's mode. The status also returns `page_state`, the active page's gate state (`RUNNING`, `AWAIT_HUMAN_VERIFICATION`, `REOBSERVE` and so on). Every successful page reply carries the same `needs_you` list.
- **Auto-resume.** Only the detector can end the wait. When a check sees no challenge on a waiting page, it calls `challenge_cleared` once per disappearance; the gate waits 3000 ms, then moves the page to `REOBSERVE`. Agent writes are then refused `TARGET_STALE` (`reobserve_required`) until the agent takes a new snapshot. After that, the next write must be planned on that snapshot (REPLAN). The agent has no call that clears a challenge. If the check is seen again during the quiet period, the page is held again on the next check (at the latest before the agent's next action runs).
- **Nothing is auto-submitted.** Orcel never presses, submits or re-sends anything after a challenge. The detector only reads. The person, or the page's own script, does whatever the page needs. The agent then observes the result and plans anew.
- **Fail closed.** If the detector cannot answer for a page that has a committed document (a capture timeout, a document that moved during the capture, or a refused frame), the page is held as `other` with the signal `detector_unavailable`. It is checked again on later reads.

## 2. The detector (apps/orcel-browser-worker/src/challenge.ts)

Input: the engine's own DOM and layout serialisation (`DOMSnapshot.captureSnapshot` with the `display` and `visibility` styles), for the main document and every frame document the snapshot holds. Also the HTTP status orceld recorded for the committed navigation, used only while the tab still shows that URL. Output: a closed kind and closed signal names. Never page text, a field value, a name, a site key or a URL. Bounded to 60 000 nodes, 32 documents and 32 768 characters of rendered text. A larger snapshot is classified as far as it was read and marked `truncated`.

| Kind | Signals | Rule |
|---|---|---|
| `captcha` | `captcha_frame` | A rendered, visible iframe whose `src` host is a CAPTCHA vendor (reCAPTCHA on google.com `/recaptcha/` or recaptcha.net, hCaptcha, Cloudflare challenges, GeeTest, AWS WAF, Arkose/FunCaptcha), not inside the invisible reCAPTCHA badge |
| | `captcha_widget` | A rendered, visible widget container: class `g-recaptcha` (not `data-size=invisible`), `h-captcha`, `cf-turnstile`, `awswaf-captcha`, `data-pkey`, or a class or id containing `geetest_`, `awswaf`, `funcaptcha` or `px-captcha` |
| | `challenge_interstitial` | Cloudflare interstitial ids (`challenge-form`, `challenge-stage`, `challenge-running`, `cf-challenge-running`, ...) or a title starting "Just a moment" |
| | `challenge_text` | Rendered bot-check wording ("I'm not a robot", "verify you are human", "checking your browser", "press and hold", "unusual traffic", ...) |
| `mfa` | `otp_autocomplete`, `otp_field`, `otp_split` | A visible text field with `autocomplete=one-time-code`; one whose name, id, placeholder, `aria-label`, title or label says code, OTP, 2FA, verification, authenticator or similar; or 4 to 8 single-character fields under one parent |
| `sign_in` | `password_field`, `http_auth` | A visible password field; or HTTP 401 or 407 |
| `passkey` | `webauthn_autocomplete`, `passkey_prompt` | A field with the `webauthn` autocomplete token; or a visible button, link, heading, label or dialog naming a passkey, security key, Windows Hello, Touch ID or Face ID |
| (none) | `http_blocked` | HTTP 403, 429 or 503. Reported alongside a challenge, never one by itself |

A credential or code field counts only when a person could submit it: it is in a form, or its document has a button. Precedence when several kinds match: captcha, mfa, sign_in, passkey.

### Known false negatives (the agent keeps acting; secret fields stay refused to fill)

- A widget inside a cross-process frame whose parent document shows no vendor frame address or marker, and challenges drawn on a canvas.
- Bot-check, code and passkey wording in languages other than English.
- A credential or code field with no form and no button anywhere in its document (for example a page that submits from a plain `div`). The OB-03 masking fixture is such a page, and stays unflagged on purpose.
- A WebAuthn ceremony started from script with no visible cue. `navigator.credentials` is not observable read-only: the CDP WebAuthn domain installs a virtual authenticator, which SG-000135 excludes.
- Invisible or score-only CAPTCHAs (reCAPTCHA v3, an invisible v2 widget). They ask nothing of a person until they challenge, and the challenge frame is then caught.
- A challenge past the 60 000-node read bound.

Known false positives (the page waits for the person): pages about passkeys or security keys, a login form that is visible on a page the agent only meant to read, and any page that shows a one-time-code field. These are accepted by design.

## 3. Handoff in Shadow mode: decision

**Chosen:** no mid-session mode switch. A challenge in a Shadow session ends the mission at that page. The status says `handoff: rerun_in_visible`, and the guidance is to close the session. The person then completes the check in a Visible session, ideally on the same persistent Orcel-managed profile (OB-04), so a sign-in's cookies carry over. Then the task runs again. A challenge in a Visible session says `handoff: visible_window`: the person completes it in that session's window, and the session resumes on its own.

**Why not a `browser_takeover` tool that turns the Shadow page into a Visible window:**

- A Shadow engine is launched headless with the Shadow argv. A window needs a new, headed engine lifetime (OB-04's separately reviewed Visible argv). That means a new host launch on the same profile, which ends the headless one. The challenge page's live state, such as a half-solved widget, a code already sent or a form already typed, would be lost. The person would get a reloaded page, not the one the agent left.
- It would add a tool to the `browser_full` profile. Under the SG-000079 rule, that changes `ToolSurfaceProfile`, `SURFACE_PROFILES`, `LOCAL_TOOL_SURFACE_PROFILES`, `profile_gate.rs`, `exposure.rs`, the README and TOOL_CONTRACT together. It would also need its own SOFT approval and a focus residual (the engine brings a new window to the front; OB04_MODES_PROFILES.md section 2a).
- Only one live session may hold a persistent profile, so a rerun in Visible on the same profile gets the same sign-in result without moving a live engine between modes.

The `browser_takeover` tool named in the SG-000135 tool list stays open for a later packet (with OB-08 or the Orcel Browser app shell), as an explicit takeover of a Visible session's page.

## 4. Gate changes

- The takeover gate (`crates/orceld/src/takeover_gate.rs`) is now on for every `browser_full` broker session (`LiveBrowser::enable_takeover_gate`, called before the session opens a page), whatever the build's `browser-takeover-gate` switch. `browser_structured` keeps the switch (off).
- `Reason::AwaitingHumanVerification` maps to `FailureCode::HumanVerificationRequired` (HTTP 409, wire `HUMAN_VERIFICATION_REQUIRED`). Every other gate refusal keeps `TARGET_STALE`.
- The orcel-agent guidance for the code (`apps/orcel-agent/orcel_agent/failures.py`) says to stay off the page and to read status until it no longer needs the person, then observe again. It never says to retry, approve or work around the check.
- The B1 state machine (`crates/orcel-browser-session`) is unchanged. The detector is its "engine's detector": `challenge(Detected)` and `challenge_cleared`. The live browser reports a disappearance once, so a status poll cannot keep pushing the quiet period back.

## 5. Tests

- Worker: `src/challenge.test.ts` classifies fixture HTML for each challenge type and the negatives: the OB-01 and OB-03 mission pages, hidden login forms, prose about robots and discount codes, and three single-character fields. It also checks that no page text crosses, the bound, and malformed snapshots. `src/challenge-html.fixture.ts` turns fixture markup into the snapshot shape the engine produces. `src/worker.test.ts` and `src/protocol.test.ts` cover the new frames.
- Host: `challenge.rs` covers the closed vocabulary and its match with the worker's list. `worker_host.rs` covers the request and reply forms.
- orceld: `takeover_gate.rs` tests that a detected challenge refuses reads and writes with `HUMAN_VERIFICATION_REQUIRED`, that time alone never clears it, the quiet period after the detector's clear, the REOBSERVE before a write, and that other pages are unaffected. They also test enabling the gate for a session. `browser_broker.rs` tests the `needs_you` shape.
- Contracts: the new code's wire spelling, its declared position and HTTP 409. The JSON schemas were regenerated.
- MCP: the refusal code crosses unchanged, `browser_task_status` returns orceld's `needs_you` unchanged, and no tool of the profile can clear, solve or take over a challenge.
- E2E: `scripts/browser-full-e2e.mjs`, OB-07 mission (`--only ob07` runs it alone). See OB01_E2E.md.

## 6. Gaps

- **Saved-login autofill through the browser vault** (the rest of OB-07 in SG-000135) is not in this change. A sign-in page is handed to the person. Nothing types a password.
- **No human-input adapter yet.** The quiet period runs from the detector's clear, not from the person's last keystroke. Rechecks run only when the agent acts or reads status, not continuously.
- **No real challenge** (a real CAPTCHA, code or passkey site) and no founder-present run.
- **Background tabs** are checked when they become active, not while in the background.
- **The detector's own failure holds the page** (`detector_unavailable`). A page whose snapshot always times out stays held until the session closes.
