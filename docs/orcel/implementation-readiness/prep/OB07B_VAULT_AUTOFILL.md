# OB-07b: saved-login autofill through the browser vault

**Status: decided and implemented on `browser/ob07b-vault-autofill` (SG-000135 work packet OB-07, second half; acceptance FA-I in part). Not merged. The independent security review of 80e6ffe9 confirmed the decision and failed the head on seven findings; section 8 lists each and its fix. The re-review of 67307e87 confirmed them and failed one more item (page URLs in replies); section 9 has its fix. Unit and source-scan tests only. No live sign-in, no founder-present run.**

The first half of OB-07 (PR #810, merge 27b86f0d) hands every sign-in page to the person ([`OB07_CHALLENGE_HANDOFF.md`](OB07_CHALLENGE_HANDOFF.md), section 6: "a sign-in page is handed to the person"). This packet had to decide whether Orcel can instead let the browser's own password manager fill a saved login for a persistent Orcel-managed profile, without Orcel ever handling the secret.

## 1. Decision

**No safe mechanism exists today, so Orcel does not trigger saved-login autofill.** A sign-in page stays a `needs_you` page of kind `sign_in`. The person signs in, either by typing the password or by choosing the browser's own saved password in a Visible session's window. OB-06 holds the session while the person types. On a persistent Orcel-managed profile (OB-04), the sign-in and any password the person saved there carry over to later sessions on that profile. Orcel adds no credential store, tool or preference.

**Where the person's sign-in can go through.** The session's route rules still apply to the person's own requests:

- Only the session's admitted origin. A sign-in that passes through another site (single sign-on: a redirect to an identity provider and back, or a form that posts to another origin) is refused, like any top-level navigation off the origin. Single sign-on across sites does not work in an agent session.
- No sign-in post once a Full Access lease was used. After a lease is used in a lifetime, every page request but a GET or HEAD is refused for the rest of that lifetime (`guard_get_only`, `crates/orcel-browser-host/src/worker_navigation.rs`), and that includes the person's sign-in post.

So the person signs in in a new Visible session that is opened on the sign-in page itself (`browser_open` to that page, so its origin is the admitted one), on a persistent profile, before any lease is used. The `needs_you` guidance says this. Fail closed: Orcel does not widen the origin or lift the GET-only rule for a sign-in.

**The future mechanism** is the OB-10 Orcel Browser (the BrowserOS build). Its own password manager can fill a saved login in the browser process, by the browser's own rules, with no CDP and no secret crossing to Orcel. That needs its own decision and security judge.

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
  - Visible: the person signs in in this session's window, by typing or by choosing the browser's own saved password. Orcel never fills, reads or types a password. Only a sign-in on the page's own admitted origin can go through. A sign-in that passes through another site is refused, and so is a sign-in post once a Full Access lease was used in the session. In those cases, close the session and sign in in a new Visible session, with no lease used, opened on the sign-in page itself. Once the page no longer needs the person (about three seconds after the sign-in form is gone), the agent observes it again before acting.
  - Shadow: a Shadow session has no window for the person and Orcel never fills a password. Close the session. The person signs in once in a new Visible session on a persistent Orcel-managed profile, opened on the sign-in page itself with no Full Access lease used, where the browser's own saved password can fill it when the person chooses. Then run the task again on that profile.
  - Other kinds keep their guidance unchanged. The handoff values (`visible_window`, `rerun_in_visible`), the `reason`, the failure code (`HUMAN_VERIFICATION_REQUIRED`) and the shape are unchanged, so no contract, schema or agent guidance changes.
- **Source scan** (`crates/orceld/tests/ob07b_vault_scan.rs`). It covers the browser host crate, the session-state crate, the browser provider, every orceld source, Orcel's own native-host sources (`apps/orcel-native-host/src`; its vendored `third_party` donor code is a separate desktop-automation surface and is not scanned), the worker and the MCP server. Comments are allowed; TypeScript tests and fixtures and inline Rust test modules are left out. It fails on:
  - the CDP `Autofill` or `WebAuthn` domains;
  - the profile's `Login Data`, `Web Data` or `Cookies` stores, or the `os_crypt` key;
  - the password-manager preferences;
  - an HTTP authentication answer (`httpCredentials`, `setHTTPCredentials`, `continueWithAuth`, `ProvideCredentials`, `handleAuthRequests`);
  - free typing (`Input.insertText`, `keyboard.type`, `pressSequentially`);
  - traffic recording (`recordHar`, `tracing.start`);
  - bulk cookie access (`Storage.getCookies`, `Network.getCookies`, Playwright `cookies()`, `addCookies`, `storageState`);
  - a request body read (`postData`) anywhere but the gated path in `routing.ts`;
  - a `browser_autofill`, `browser_login`, `browser_password`, `browser_credential` or `browser_sign_in` tool.

  Only `#[cfg(test)]` on an inline module (`mod name {`) is cut, up to the module's closing brace at its own indentation. A `#[cfg(test)]` on a function or statement cuts nothing. Every Rust file must keep at least a fifth of its lines, and nine key files must show a named production item near their end, so a cut that stops early fails. A unit test pins the cutting rule. A later packet that finds a safe mechanism must change this test and this document together.
- **Request bodies stay in the worker** (`apps/orcel-browser-worker/src/worker.ts`, `withheldBody`). The worker sends a request's body to the host only while an approved form execution runs, and only for its top-level document: that is the one request the host checks a body for (`Submission::check`). Every other body, such as the person's sign-in post, crosses as `null` with size 0, so no field value reaches orceld. `worker.test.ts` tests it with a dummy post, and the scan pins the call.
- **Sign-in detection and secret fields** (`challenge.ts`, `secret-memory.ts`, `verify.ts`, `actions/form.ts`, `screenshot.ts`):
  - A field with the `current-password` or `new-password` autocomplete token counts as a password field, whatever its type.
  - A page's password fields are remembered by the engine's backend node id and by name and id, bounded to 256 each. A field that was a password field still counts as one after a "show password" toggle turns it into a text field. The detector keeps the page held, `isSecretField` refuses to read or fill it, and the screenshot mask covers it.
  - `isSecretField` also reads `aria-label` and `placeholder` (password, passcode, passphrase, one-time code, PIN, security code).
  - The fill locator's own exclusion (`NOT_SECRET`) adds PIN names and ids. A PIN name or id is matched only as a whole word part, never "shipping" or "spinner". It also adds password words in `aria-label` and `placeholder`.
  - The mask adds `aria-label` and `placeholder` hints.
  - Fill checks the field again after focusing it, right before the text goes in, and refuses if it is no longer the one non-secret field.
  - Behavioural tests in `form.test.ts` and `secret-memory.test.ts` check each case.

## 5. Why not the alternatives in the brief

- **A `browser_autofill_login` tool.** It would need a mechanism from section 3, and none qualifies. Adding a tool that always answers `needs_you` would only duplicate the detector. Under SG-000079 it would also change the tool surface tables, the README and TOOL_CONTRACT for no gain.
- **Holding the sign-in back in Shadow until a saved login fills on load.** Not observable without reading the field (section 3).
- **An Orcel credential broker.** The founder's Shadow spec mentions a "dedicated encrypted password/credential broker". This packet does not build one. The brief forbids inventing a credential store in Orcel, and the browser's own vault already exists in each persistent profile. A broker would be a separate grain with its own security judge.

## 6. Limits

- **FA-I is met in part.** "A real challenge is handed to the person" and "no secret appears in prompts, logs or receipts" hold for sign-in pages, as in OB-07. "Saved-login autofill succeeds through the browser vault" holds only when the person chooses the saved login in a Visible window. Orcel never starts it. "A spoofed origin fails" is the browser vault's own origin binding, not an Orcel check, and it is not tested here.
- **Shadow cannot sign in.** A Shadow session that meets a sign-in page ends there. The person signs in once in a Visible session on the same persistent profile. Cookies then carry the sign-in into later Shadow runs, until the site expires them.
- **Ephemeral profiles keep nothing.** A sign-in in an ephemeral session is lost when the session ends.
- **No single sign-on across sites, and no sign-in after a lease was used** (section 1).
- **A GET sign-in form** puts its fields in the URL's query. The host and orceld see that URL to apply the route rules, as for any navigation, and receipts keep only a digest of it. The agent never sees the values (section 9). The URL's path is shown as it is: a site that puts a secret in the path itself (for example `/reset/<token>`) is not redacted.
- **`<label for>` text is not read by the secret-field check.** `isSecretField` reads the field's own type, `autocomplete`, name, id, `aria-label` and `placeholder`, and the page's toggle memory. A plain text field whose only hint is a separate `<label>` saying "Password" is not refused by that check. The detector still holds a page with a real password field, and the toggle memory covers a field that was one.
- **Node swap residual.** A fill acts on the element its locator resolves at that moment, and the locator itself excludes every secret field. A page that swaps the element for an innocuous one between the check and the fill, then copies the typed text elsewhere by its own script, is outside what a read-only check can see. The agent only ever fills values it was approved to type, never a credential.
- **The toggle memory** covers fields the detector has seen as password fields on that page. It runs before every action and on status reads. A field that is never seen as a password field before it is shown in clear, and has no secret-looking name, label or placeholder, is not covered.
- **The detector's known false negatives stay** (OB07_CHALLENGE_HANDOFF.md, section 2). For example, a password field with no form and no button is not flagged. Fill and type stay refused on it either way.
- **A person's saved passwords live in the profile folder,** encrypted by the engine under the person's Windows account. Orcel's tools never expose profile files. A local process running as the same Windows account is outside what Orcel can stop.
- **Edge's device-password prompt** before autofill, where Edge shows it, is answered by the person. Orcel never answers a Windows security prompt.

## 7. Not done

- No live test of a person choosing a saved login. A scripted test cannot be the person, and an agent must never enter a password, not even a dummy one. The founder-present run should cover: save a dummy login on a throwaway local fixture in a Visible session on a throwaway persistent profile, close the session, open a new Visible session on that profile, and check that the person can pick the saved login, that the page resumes after the form is gone, and that no receipt, log or reply holds the dummy password.
- No spoofed-origin test (it tests the browser's vault, not Orcel).
- No Orcel credential broker, and no address autofill. CDP's address autofill takes the data from the caller, and Orcel has no address store.
- The `browser_takeover` tool for an explicit person takeover of a Visible page stays open (OB07_CHALLENGE_HANDOFF.md, section 3).
- Security judge: this packet touches authority and credentials, so it needs a fresh-context security review before merge.

## 8. After the security review of 80e6ffe9

The independent review confirmed the decision and failed the head. Each finding and its fix:

1. **High: the scan cut each file at its first `#[cfg(test)]`,** which in several files sits on one item early in the file, so most production code went unscanned. Fixed: only an inline test module is cut (section 4), every file must keep a fifth of its lines, and nine key files must show a production item near their end. The OB-04 scan (`ob04_shadow_scan.rs`) reads whole files and never cut anything, so it was not affected.
2. **Medium: the person's sign-in post reached orceld.** The worker described every URL-encoded POST body of up to 16 KiB to the host, and the host lives in orceld. Fixed: bodies leave the worker only for an approved execution's document (section 4).
3. **Medium: the guidance overstated where a sign-in works.** The route rules refuse cross-origin sign-in and any sign-in post after a lease was used. Fixed: the guidance and section 1 say so, and say how to sign in.
4. **Low-medium: sign-in detection knew only `type=password`.** Fixed: password autocomplete tokens, the show-password toggle memory, and `aria-label`/`placeholder` hints for the secret-field check and the mask (section 4).
5. **Low: missing tokens and a substring-only selector check.** Fixed: the HTTP-auth, typing, recording and `postData` tokens; `Cookies` with path separators; the native host's own sources; PIN in `NOT_SECRET`. The selector substring test is replaced by behavioural fill tests.
6. **Low: fill checked the field only before focus.** Fixed: it checks again after focus.
7. **Info.** The #810 merge (27b86f0d) and the OB-10 future mechanism are recorded.

## 9. After the re-review of 67307e87: page URLs the agent reads

The re-review confirmed all seven fixes and failed the head on one item: agent-facing replies returned the full committed URL, query and fragment included. After a person's GET sign-in, the agent's next reply could carry `?password=...` to the MCP client (and later, through OB-09, off the machine). Only the tab list stripped the query.

**Fix: one sanitizer** (`crates/orceld/src/agent_url.rs`) for every page URL in an agent-facing reply. That covers the live `browser_structured` shapes (open, click, form action, verify) and `browser_full` (open, click, fill and select, verify, extract, a new tab's navigation). The tab list keeps the stricter `bare` form from the same module (no query or fragment at all). `needs_you`, snapshots and errors carry no URL. Receipts digest the reply as sent, so they digest the sanitized URL. `LiveBrowser::agent_url` applies the rules:

- Userinfo (`user:password@`) is always dropped.
- The scheme, host and path are kept. A URL that is not http or https shows only its scheme (`about:blank` stays).
- A query or fragment parameter keeps its name. Its value becomes `[redacted]` when the name looks secret: it contains, case-insensitively and after `%XX` decoding, pass, pw, secret, token, otp, code, key, auth, session, sid, sig, signature, credential, cred, saml, assertion, ticket, jwt, bearer, access, refresh or nonce, or it has `pin` as a whole word. A token-like name (a run of 16 or more token characters, or longer than 64) is redacted too.
- A bare query item (no `=`) is kept only when it is short, not token-like and not secret-looking.
- A fragment with `=` is read as parameters (the OAuth implicit flow's `#access_token=...`). Any other fragment is a plain anchor. It is kept only when it is at most 64 characters, has no run of 16 or more token characters and is not secret-looking; otherwise it becomes `[redacted]`.
- **After a sign-in page:** once the detector saw a `sign_in` page in the session, every query and fragment value and every bare query item is redacted for the rest of the session, whatever the names. Any later URL may carry what the person typed. The flag is per session and never cleared, the cheapest form that fails closed. Plain anchor fragments keep the rule above. `browser_structured` has no detector (its gate is off), so only the name rules apply there.

The agent keeps the path and the parameter names, enough to know where it is. Tests: `agent_url.rs` checks each rule, including the strict mode and the tab form. `live_browser.rs` checks the session's switch to strict after a sign-in. The vault scan requires every reply field named `url` (or ending in `url`) in `live_dispatch.rs` and `browser_broker.rs` to be built by `agent_url` or `agent_url::bare`, at least 11 of them. It also now cuts `#[cfg(all(test, ...))]` modules as test code, and it checks that the native host keeps cua-driver-core on `orcel-minimal` with default features off.

## 10. Follow-ups after the merge (branch `browser/agent-url-followups`)

The reviewer's low residuals on #820 (merge 7ad1ac77):

1. **`url_is` is no oracle.** Before a `url_is` check reaches the host, orceld compares both URLs as the agent may read them, in the session's mode (`LiveBrowser::url_checks_without_oracle`). If they match, the host is asked about orceld's committed URL, which passes unless the page moved on. If not, the host is asked about the sanitized expected URL, which cannot equal the committed one. A right and a wrong guess of a redacted value (a password in a GET sign-in's query) give the same answer. The redacted form the agent was shown matches, in strict mode too.
2. **Sanitizer.**
   - `;` separates parameters as well as `&`, and each separator is kept as it was.
   - A name is `%XX`-decoded up to three times before it is matched, so `%2570ass` matches. A fourth level is not unwrapped (bounded).
   - A parsed download's `source_url` (WI-05 document parse) now goes through the sanitizer too. A download link may carry a signed token.
3. **A sign-in the detector never saw.** Strict mode starts only when the detector has seen a `sign_in` page in the session. The detector runs before each agent action and on status reads. A person could load a GET sign-in form and submit it between two of them. The resulting URL then gets only the name rules, which still redact any secret-looking name (a password field named `password`, `pw`, `pass`, `pin` and so on).

   I considered turning strict mode on whenever a navigation comes from a form submission on a page that had a password field. The worker's toggle memory does know which pages had a password field. But the worker cannot tell a person's form submission from any other navigation without page script, and the route question carries no such flag. That would mean a protocol change for a residual the name rules mostly cover, so it is recorded, not built.
4. **Scan breadth.** The vault scan now checks every orceld source, not only the two reply builders. It looks at:
   - every URL-like key: `url`, `href`, `location`, `link`, `redirect`, or any key ending in `_<one of them>`;
   - written as a JSON key (also with the value on the next line) or a map `insert`;
   - every URL-like field of a type that derives `Serialize`.

   Each must be built by `agent_url` or `agent_url::bare`, or be on an explicit allowlist with its reason. The allowlist holds the journal input a `browser_full` action maps onto, the observation's page-authored `latest_dated_link`, and web search results. A unit test pins the detection on each form.
