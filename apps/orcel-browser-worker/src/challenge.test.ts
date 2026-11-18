// SG-000135 OB-07: the challenge detector on fixture HTML, one case per
// challenge type and the negatives that must stay quiet.

import assert from "node:assert/strict";
import { test } from "node:test";
import { CHALLENGE_SIGNALS, classifyChallenge, MAX_CHALLENGE_NODES, type ChallengeReport } from "./challenge.js";
import { snapshotOf } from "./challenge-html.fixture.js";

const page = (body: string, title = "Fixture") => `<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`;
const classify = (html: string, status = 200, ...frames: string[]): ChallengeReport => classifyChallenge(snapshotOf(html, ...frames), status);

test("reCAPTCHA, hCaptcha and Turnstile widgets are CAPTCHAs", () => {
  for (const widget of [
    '<div class="g-recaptcha" data-sitekey="6Lc-fixture"></div>',
    '<div class="h-captcha" data-sitekey="10000000-ffff"></div>',
    '<div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>',
    '<div id="captcha-geetest_holder" class="geetest_panel"></div>',
    '<div data-pkey="ARKOSE-KEY" id="enforcement"></div>',
    '<awswaf-captcha></awswaf-captcha>'
  ]) {
    const report = classify(page(`<form>${widget}<button>Continue</button></form>`));
    assert.equal(report.kind, "captcha", widget);
    assert.ok(report.signals.includes("captcha_widget"), widget);
  }
});

test("a vendor CAPTCHA frame is a CAPTCHA, but an invisible reCAPTCHA badge is not", () => {
  for (const src of [
    "https://www.google.com/recaptcha/api2/anchor?k=fixture",
    "https://www.recaptcha.net/recaptcha/api2/anchor?k=fixture",
    "https://newassets.hcaptcha.com/captcha/v1/abc/static/hcaptcha.html",
    "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/h/b/turnstile/if/ov2/av0"
  ]) {
    const report = classify(page(`<p>Before you continue</p><iframe src="${src}" title="widget"></iframe>`));
    assert.equal(report.kind, "captcha", src);
    assert.deepEqual(report.signals, ["captcha_frame"], src);
  }
  const badge = classify(page('<form><input name="q"><button>Go</button></form><div class="grecaptcha-badge"><iframe src="https://www.google.com/recaptcha/api2/anchor?size=invisible"></iframe></div>'));
  assert.equal(badge.kind, "none");
  const invisible = classify(page('<form><div class="g-recaptcha" data-size="invisible" data-sitekey="k"></div><button>Send</button></form>'));
  assert.equal(invisible.kind, "none");
  // google.com frames that are not reCAPTCHA (a map) are not challenges.
  assert.equal(classify(page('<iframe src="https://www.google.com/maps/embed?pb=1"></iframe>')).kind, "none");
  // A frame that is hidden (the reCAPTCHA challenge popup before it opens).
  assert.equal(classify(page('<div style="visibility:hidden"><iframe src="https://www.google.com/recaptcha/api2/bframe"></iframe></div>')).kind, "none");
});

test("a widget inside a same-process frame document is found", () => {
  const report = classify(page('<iframe src="/inner"></iframe>'), 200, page('<div class="h-captcha" data-sitekey="k"></div><button>Go</button>'));
  assert.equal(report.kind, "captcha");
});

test("the Cloudflare interstitial and bot-check wording are CAPTCHAs, with the blocked status noted", () => {
  const interstitial = classify(page('<div id="challenge-stage"></div><p>Checking if the site connection is secure</p>', "Just a moment..."), 403);
  assert.equal(interstitial.kind, "captcha");
  assert.deepEqual(interstitial.signals, ["challenge_interstitial", "challenge_text", "http_blocked"]);
  const robot = classify(page("<h1>Please verify you are a human</h1><p>Press &amp; hold the button</p>"), 429);
  assert.equal(robot.kind, "captcha");
  assert.deepEqual(robot.signals, ["challenge_text", "http_blocked"]);
  // A blocked status alone asks nothing of a person.
  const blocked = classify(page("<h1>Forbidden</h1>"), 403);
  assert.equal(blocked.kind, "none");
  assert.deepEqual(blocked.signals, ["http_blocked"]);
});

test("one-time-code fields are MFA: autocomplete, an OTP label with a numeric field, and split digits", () => {
  const autocomplete = classify(page('<form><input autocomplete="one-time-code" inputmode="numeric" name="c"><button>Verify</button></form>'));
  assert.equal(autocomplete.kind, "mfa");
  assert.ok(autocomplete.signals.includes("otp_autocomplete"));
  const labelled = classify(page('<form><label>Enter the verification code <input inputmode="numeric" name="token"></label><button>Continue</button></form>'));
  assert.equal(labelled.kind, "mfa");
  assert.deepEqual(labelled.signals, ["otp_field"]);
  const labelFor = classify(page('<form><label for="x">Authenticator code</label><input id="x" type="tel"><button>Next</button></form>'));
  assert.deepEqual(labelFor.signals, ["otp_field"]);
  const named = classify(page('<form><input name="otp" type="text"><button>Go</button></form>'));
  assert.equal(named.kind, "mfa");
  const split = classify(page(`<form><div>${'<input maxlength="1" inputmode="numeric">'.repeat(6)}</div><button>Verify</button></form>`));
  assert.equal(split.kind, "mfa");
  assert.deepEqual(split.signals, ["otp_split"]);
});

test("a password field with a way to submit is a sign-in wall, and so is HTTP 401", () => {
  const login = classify(page('<form action="/login" method="post"><label>Email <input type="email" name="email"></label><label>Password <input type="password" name="pw"></label><button>Sign in</button></form>'));
  assert.equal(login.kind, "sign_in");
  assert.deepEqual(login.signals, ["password_field"]);
  // Formless (an app page) with a button still counts.
  assert.equal(classify(page('<div><input type="password"></div><div role="button">Log in</div>')).kind, "sign_in");
  const unauthorized = classify(page("<h1>Authorization required</h1>"), 401);
  assert.equal(unauthorized.kind, "sign_in");
  assert.deepEqual(unauthorized.signals, ["http_auth"]);
  assert.equal(classify(page("<p>proxy</p>"), 407).kind, "sign_in");
});

test("a passkey or WebAuthn prompt is a passkey challenge; with a password field it is a sign-in", () => {
  const prompt = classify(page("<h2>Use your passkey</h2><button>Continue with a security key</button>"));
  assert.equal(prompt.kind, "passkey");
  assert.deepEqual(prompt.signals, ["passkey_prompt"]);
  const autofill = classify(page('<input name="user" autocomplete="username webauthn">'));
  assert.equal(autofill.kind, "passkey");
  assert.deepEqual(autofill.signals, ["webauthn_autocomplete"]);
  const both = classify(page('<form><input autocomplete="username webauthn"><input type="password"><button>Sign in</button><a href="/pk">Sign in with a passkey</a></form>'));
  assert.equal(both.kind, "sign_in");
  assert.deepEqual(both.signals, ["password_field", "webauthn_autocomplete", "passkey_prompt"]);
});

test("ordinary pages, hidden fields and lone secret fields stay quiet", () => {
  const quiet = [
    // The OB-01 mission form and its second page.
    page('<h1>Orcel Browser mission</h1><label>Full name <input type="text" name="full_name"></label><label>City <select name="city"><option>Lisbon</option></select></label><p><a href="/ob01-done">Continue to the second page</a></p>'),
    page('<h1>Second page</h1><p id="result">OB-01 mission second page reached</p>'),
    // The OB-03 masking page: secret fields with no form and no button.
    page('<input type="text" name="nickname"><input type="password" name="pw"><input type="text" autocomplete="one-time-code" name="code"><input autocomplete="cc-number"><p>OB-03 second tab reached</p>'),
    // A login form that is not shown (a closed menu), by attribute or style.
    page('<nav><form hidden><input type="password"><button>Sign in</button></form><form style="display:none"><input autocomplete="one-time-code"><button>Go</button></form></nav><p>Welcome</p>'),
    page('<form style="visibility:hidden"><input type="password"><button>Sign in</button></form>'),
    // A hidden input never counts.
    page('<form><input type="hidden" name="otp" value="x"><input name="q"><button>Search</button></form>'),
    // Wording about robots or codes in ordinary prose.
    page('<article><h1>Robots in the factory</h1><p>Our discount code is SPRING.</p></article><form><input name="coupon" placeholder="Discount code"><button>Apply</button></form>'),
    // Three single-character fields are not a code.
    page('<form><input maxlength="1"><input maxlength="1"><input maxlength="1"><button>Go</button></form>')
  ];
  for (const html of quiet) {
    const report = classify(html);
    assert.equal(report.kind, "none", `${html} -> ${JSON.stringify(report)}`);
    assert.deepEqual(report.signals, [], html);
  }
});

test("the report is a closed kind and closed signals, never page text", () => {
  const secret = "hunter2-SECRET-VALUE";
  const report = classify(page(`<form><label>Password <input type="password" value="${secret}"></label><div class="h-captcha" data-sitekey="${secret}"></div><button>${secret}</button></form>`, secret));
  const text = JSON.stringify(report);
  assert.ok(!text.includes(secret), text);
  assert.ok(!text.includes("Password"), text);
  for (const signal of report.signals) assert.ok((CHALLENGE_SIGNALS as readonly string[]).includes(signal));
  assert.deepEqual(Object.keys(report).sort(), ["kind", "signals", "truncated"]);
});

test("the detector is bounded: an oversized snapshot is read up to the node budget and marked", () => {
  const filler = "<p>x</p>".repeat(Math.ceil(MAX_CHALLENGE_NODES / 2) + 10);
  const report = classify(page(`${filler}<div class="h-captcha"></div>`));
  assert.equal(report.truncated, true);
  // What came past the budget was not read: a known false negative.
  assert.equal(report.kind, "none");
  const early = classify(page(`<div class="h-captcha"></div><button>Go</button>${filler}`));
  assert.equal(early.truncated, true);
  assert.equal(early.kind, "captcha");
});

test("a malformed snapshot classifies as nothing rather than throwing", () => {
  assert.deepEqual(classifyChallenge({ documents: [], strings: [] }, 0), { kind: "none", signals: [], truncated: false });
  const odd = { documents: [{ nodes: { nodeType: [1, 3], nodeName: [99], parentIndex: [-1, 0], attributes: [[5, 6, 7]] } }], strings: [] };
  assert.equal(classifyChallenge(odd, 0).kind, "none");
});
