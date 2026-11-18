// SG-000135 OB-07: the read-only challenge detector ("Needs you").
//
// It classifies the active tab's committed document as a page only a person
// can get past: a CAPTCHA or bot check, a one-time code or other second
// factor, a sign-in wall, or a passkey or WebAuthn prompt. It never solves,
// skips, fills, clicks or answers any of them, and it never runs script in
// the page: the input is the engine's own DOM and layout serialisation
// (CDP `DOMSnapshot.captureSnapshot`, a read) plus the HTTP status the
// host recorded for the committed document. The output is a closed kind and
// a closed list of signal names: never page text, a field value, a name or a
// URL, so nothing a person types on a challenge page can reach the host, the
// agent or a log through it.
//
// It is conservative: a page that looks like a challenge is handed to the
// person (a false positive costs a "Needs you"; a false negative lets the
// agent keep acting, where the existing refusals of secret fields still
// hold). Known false negatives (OB07_CHALLENGE_HANDOFF.md):
// - widgets inside cross-process frames whose parent shows no vendor frame
//   address or marker, and challenges drawn on a canvas;
// - bot-check, one-time-code and passkey wording in languages other than
//   English;
// - a credential or code field with no form and no button anywhere in its
//   document (a formless page that submits from a plain element);
// - a WebAuthn ceremony the page starts from script with no visible cue
//   (navigator.credentials is not observable read-only: the CDP WebAuthn
//   domain installs a virtual authenticator, which Orcel never uses);
// - an invisible or score-only CAPTCHA (reCAPTCHA v3, an invisible v2
//   widget), which asks nothing of a person until it challenges.
//
// Donor data (docs/orcel/browseros_provenance.json): the vendor frame hosts
// and widget markers are ported as data from BrowserOS
// packages/browseros-agent/crates/neo-sdk/neo-captcha/src/detect.rs (blob
// c6883f3fdd54580d2fa18616b9b4696b48e38978 at
// bd725831273884c4b1aee8425975afa122f720f2; AGPL-3.0-or-later upstream,
// notice docs/orcel/notices/browseros-AGPL-3.0.txt; owner-asserted
// authorization docs/orcel/grants/2026-11-17-founder-attestation.md). The
// donor detects by running script in the page and goes on to solve; Orcel
// keeps only the host list and the marker names, reads them from the
// engine's DOM snapshot, and has no solving, token, provider or callback
// code at all.

/// The page was between documents (a navigation in flight, or the document
/// changed during the capture): nothing was classified; ask again later.
import { rememberSecretField, wasSecretField, type SecretMemory } from "./secret-memory.js";

export class ChallengeBusy extends Error {
  constructor() {
    super("busy");
  }
}

/// Why a check gave no report: `busy` (ask again later) or `failed`.
export type ChallengeFailure = "busy" | "failed";

/// The kinds a page can be classified as.
export type ChallengeKind = "none" | "captcha" | "mfa" | "sign_in" | "passkey";

/// Every signal the detector can report: a closed vocabulary.
export const CHALLENGE_SIGNALS = [
  "captcha_frame",
  "captcha_widget",
  "challenge_interstitial",
  "challenge_text",
  "otp_autocomplete",
  "otp_field",
  "otp_split",
  "password_field",
  "http_auth",
  "http_blocked",
  "webauthn_autocomplete",
  "passkey_prompt"
] as const;
export type ChallengeSignal = (typeof CHALLENGE_SIGNALS)[number];

export interface ChallengeReport {
  kind: ChallengeKind;
  /// The signals seen, in vocabulary order, each once.
  signals: ChallengeSignal[];
  /// The snapshot was larger than the detector reads; what it read was
  /// classified.
  truncated: boolean;
}

/// The computed styles the capture asks for, in this order.
export const CHALLENGE_STYLES = ["display", "visibility"] as const;
/// The most snapshot nodes read, across every document.
export const MAX_CHALLENGE_NODES = 60_000;
/// The most documents read (the main document and its frames).
export const MAX_CHALLENGE_DOCUMENTS = 32;
/// The most rendered text read for bot-check wording, per snapshot.
export const MAX_CUE_TEXT_CHARS = 32_768;
/// The most text kept for one label, button, link or heading.
const MAX_OWNED_TEXT_CHARS = 256;
/// How far up the tree a text node or field looks for its owner or form.
const MAX_CLIMB = 48;

/// The engine snapshot's parts this module reads.
export interface ChallengeSnapshot {
  documents: Array<{
    documentURL?: number;
    title?: number;
    nodes: {
      parentIndex?: number[];
      nodeType?: number[];
      nodeName?: number[];
      nodeValue?: number[];
      attributes?: number[][];
      /// The engine's stable id per node (kept across snapshots of the same
      /// document), used only to remember password fields (OB-07b).
      backendNodeId?: number[];
    };
    layout?: {
      nodeIndex?: number[];
      styles?: number[][];
    };
  }>;
  strings: string[];
}

// Ported as data from the donor (see the header): the hosts whose frames
// carry a CAPTCHA widget. google.com counts only for its /recaptcha/ paths.
const VENDOR_HOST = /(^|\.)(recaptcha\.net|hcaptcha\.com|challenges\.cloudflare\.com|geetest\.com|geevisit\.com|awswaf\.com|arkoselabs\.com|arkoselabs\.cn|funcaptcha\.com)$/;
const GOOGLE_HOST = /(^|\.)google\.com$/;
// Ported as data from the donor: widget containers by class token.
const WIDGET_CLASSES = new Set(["g-recaptcha", "h-captcha", "cf-turnstile"]);
// Ported as data from the donor: widget markers by class or id fragment.
const WIDGET_FRAGMENTS = ["geetest_", "awswaf", "funcaptcha", "px-captcha"];
// Cloudflare's interstitial ("Just a moment...") by element id.
const INTERSTITIAL_IDS = new Set(["challenge-form", "challenge-stage", "challenge-running", "cf-challenge-running", "challenge-body-text", "cf-please-wait"]);

const BOT_CHECK_TEXT =
  /\b(i'?m not a robot|are you a robot|are you human|verify (?:that )?you are (?:a )?human|confirm (?:that )?you are (?:a )?human|prove (?:that )?you(?:'re| are) (?:a )?human|human verification|checking (?:if the site connection is secure|your browser)|press (?:and|&) hold|complete the security check|unusual traffic|solve (?:the|this) (?:puzzle|challenge))\b/i;
const OTP_HINT =
  /(\botp\b|\btotp\b|\b2fa\b|\bmfa\b|one[-_\s]?time|verification[-_\s]?code|security[-_\s]?code|auth(?:entication|enticator)?[-_\s]?code|two[-_\s]?factor|2[-_\s]?step|passcode|sms[-_\s]?code|enter (?:the |your )?code|confirmation[-_\s]?code)/i;
const PASSKEY_CUE =
  /\b(passkeys?|security keys?|windows hello|touch id|face id|use your (?:phone|device|fingerprint|face|screen lock)|sign in with (?:your )?(?:phone|device)|webauthn)\b/i;

/// Elements whose own text is read as one label, button, link or heading.
const OWNER_TAGS = new Set(["label", "button", "a", "h1", "h2", "h3", "legend", "summary"]);
const OWNER_ROLES = new Set(["button", "link", "heading", "dialog", "alertdialog"]);
/// Input types that take typed text (a code field may be any of them).
const TEXT_TYPES = new Set(["", "text", "tel", "number", "password", "email", "search"]);
/// `autocomplete` tokens that mark a password field whatever its type.
const PASSWORD_TOKENS = new Set(["current-password", "new-password"]);
/// Controls that can submit or continue.
const BUTTON_TYPES = new Set(["submit", "button", "image"]);

interface Element {
  tag: string;
  attrs: Map<string, string>;
  parent: number;
  /// The engine's backend node id, when the snapshot carries one.
  backend?: number;
}

/// One document, as the detector reads it.
class Doc {
  readonly elements = new Map<number, Element>();
  readonly parents: number[] = [];
  readonly rendered = new Set<number>();
  readonly hidden = new Set<number>();
  readonly owned = new Map<number, string>();
  readonly forms = new Set<number>();
  buttons = 0;

  /// Whether `node` is rendered and not hidden by visibility.
  shown(node: number): boolean {
    return this.rendered.has(node) && !this.hidden.has(node);
  }

  /// The nearest ancestor (or `node` itself) that `test` accepts, within
  /// the climb bound.
  climb(node: number, test: (index: number, element: Element) => boolean): number | null {
    let at = node;
    for (let step = 0; step < MAX_CLIMB && at >= 0; step++) {
      const element = this.elements.get(at);
      if (element && test(at, element)) return at;
      at = this.parents[at] ?? -1;
    }
    return null;
  }

  /// Whether `node` sits in a form (by ancestry or its `form` attribute).
  inForm(node: number): boolean {
    const element = this.elements.get(node);
    if (element?.attrs.has("form")) return true;
    return this.climb(node, (_, candidate) => candidate.tag === "form") !== null;
  }

  /// Whether a person could submit or continue from `node`: it is in a
  /// form, or its document has a button.
  submittable(node: number): boolean {
    return this.buttons > 0 || this.inForm(node);
  }
}

function lower(value: string | undefined): string {
  return (value ?? "").toLowerCase();
}

function tokens(value: string | undefined): string[] {
  return lower(value).split(/\s+/).filter((token) => token.length > 0);
}

function isOwner(element: Element): boolean {
  return OWNER_TAGS.has(element.tag) || OWNER_ROLES.has(lower(element.attrs.get("role")));
}

function vendorFrame(src: string | undefined): boolean {
  if (!src) return false;
  let url: URL;
  try {
    url = new URL(src);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return false;
  const host = url.hostname.toLowerCase();
  if (VENDOR_HOST.test(host)) return true;
  return GOOGLE_HOST.test(host) && url.pathname.startsWith("/recaptcha/");
}

/// Read one snapshot document into the detector's model, within the shared
/// node budget. Returns the document and the nodes it used.
function readDocument(
  snapshot: ChallengeSnapshot,
  index: number,
  budget: number,
  cue: { text: string }
): { doc: Doc; used: number; truncated: boolean } {
  const doc = new Doc();
  const raw = snapshot.documents[index];
  const strings = snapshot.strings ?? [];
  const text = (at: number | undefined): string => (at !== undefined && at >= 0 ? (strings[at] ?? "") : "");
  const nodes = raw?.nodes ?? {};
  const types = nodes.nodeType ?? [];
  const count = Math.min(types.length, budget);
  const parentIndex = nodes.parentIndex ?? [];
  const names = nodes.nodeName ?? [];
  const values = nodes.nodeValue ?? [];
  const attributes = nodes.attributes ?? [];
  const backends = nodes.backendNodeId ?? [];
  for (let i = 0; i < count; i++) {
    doc.parents.push(parentIndex[i] ?? -1);
    if (types[i] !== 1) continue;
    const attrs = new Map<string, string>();
    const flat = attributes[i] ?? [];
    for (let a = 0; a + 1 < flat.length; a += 2) {
      const name = text(flat[a]).toLowerCase();
      if (name && !attrs.has(name)) attrs.set(name, text(flat[a + 1]));
    }
    const backend = backends[i];
    doc.elements.set(i, {
      tag: text(names[i]).toLowerCase(),
      attrs,
      parent: parentIndex[i] ?? -1,
      ...(typeof backend === "number" && Number.isSafeInteger(backend) && backend > 0 ? { backend } : {})
    });
  }
  const layoutNodes = raw?.layout?.nodeIndex ?? [];
  const styles = raw?.layout?.styles ?? [];
  const visibilityAt = CHALLENGE_STYLES.indexOf("visibility");
  for (let k = 0; k < layoutNodes.length; k++) {
    const node = layoutNodes[k];
    if (node === undefined || node < 0 || node >= count) continue;
    doc.rendered.add(node);
    const visibility = lower(text(styles[k]?.[visibilityAt]));
    if (visibility === "hidden" || visibility === "collapse") doc.hidden.add(node);
  }
  for (const [node, element] of doc.elements) {
    if (element.tag === "form") doc.forms.add(node);
    if (!doc.shown(node)) continue;
    const type = lower(element.attrs.get("type"));
    if (element.tag === "button" || lower(element.attrs.get("role")) === "button" || (element.tag === "input" && BUTTON_TYPES.has(type))) {
      doc.buttons += 1;
    }
  }
  // Rendered text goes to its nearest label, button, link or heading, and
  // (bounded) to the page's bot-check wording.
  for (let i = 0; i < count; i++) {
    if (types[i] !== 3 || !doc.rendered.has(i) || doc.hidden.has(i)) continue;
    const value = text(values[i]).replace(/\s+/g, " ");
    if (value.trim().length === 0) continue;
    if (cue.text.length < MAX_CUE_TEXT_CHARS) cue.text += ` ${value.slice(0, MAX_CUE_TEXT_CHARS - cue.text.length)}`;
    const owner = doc.climb(parentIndex[i] ?? -1, (_, element) => isOwner(element));
    if (owner !== null) {
      const kept = doc.owned.get(owner) ?? "";
      if (kept.length < MAX_OWNED_TEXT_CHARS) doc.owned.set(owner, `${kept} ${value}`.slice(0, MAX_OWNED_TEXT_CHARS));
    }
  }
  return { doc, used: count, truncated: types.length > count };
}

/// What one field's label, name, id, placeholder and accessible label say.
function fieldHint(doc: Doc, node: number, element: Element, labels: Map<string, string>): string {
  const parts = [
    element.attrs.get("name"),
    element.attrs.get("id"),
    element.attrs.get("placeholder"),
    element.attrs.get("aria-label"),
    element.attrs.get("title"),
    labels.get(element.attrs.get("id") ?? "\u0000")
  ];
  const label = doc.climb(node, (_, candidate) => candidate.tag === "label");
  if (label !== null) parts.push(doc.owned.get(label));
  return parts.filter((part) => part !== undefined && part.length > 0).join(" ");
}

/// Classify one engine snapshot. `status` is the committed document's HTTP
/// status when the host knows it is this document's (0 otherwise).
/// `memory` (SG-000135 OB-07b) is the page's record of fields that were
/// password fields: each password field seen is added, and a field that was
/// one still counts as one after a "show password" toggle made it a text
/// field (`secret-memory.ts`).
export function classifyChallenge(snapshot: ChallengeSnapshot, status: number, memory?: SecretMemory): ChallengeReport {
  const seen = new Set<ChallengeSignal>();
  const cue = { text: "" };
  let budget = MAX_CHALLENGE_NODES;
  let truncated = (snapshot.documents?.length ?? 0) > MAX_CHALLENGE_DOCUMENTS;
  const strings = snapshot.strings ?? [];
  const documents = (snapshot.documents ?? []).slice(0, MAX_CHALLENGE_DOCUMENTS);
  for (let d = 0; d < documents.length && budget > 0; d++) {
    const { doc, used, truncated: cut } = readDocument(snapshot, d, budget, cue);
    budget -= used;
    truncated ||= cut;
    // label[for] text, by the id it names.
    const labels = new Map<string, string>();
    for (const [node, element] of doc.elements) {
      const target = element.tag === "label" ? element.attrs.get("for") : undefined;
      const owned = doc.owned.get(node);
      if (target && owned && !labels.has(target)) labels.set(target, owned);
    }
    // Single-character fields per parent (a split one-time code).
    const singles = new Map<number, number>();
    for (const [node, element] of doc.elements) {
      const shown = doc.shown(node);
      const type = lower(element.attrs.get("type"));
      const classes = tokens(element.attrs.get("class"));
      const id = lower(element.attrs.get("id"));
      // CAPTCHA widgets and frames (an invisible reCAPTCHA asks nothing).
      if (shown && element.tag === "iframe" && vendorFrame(element.attrs.get("src"))) {
        const badge = doc.climb(node, (_, candidate) => tokens(candidate.attrs.get("class")).includes("grecaptcha-badge"));
        if (badge === null) seen.add("captcha_frame");
      }
      if (shown && lower(element.attrs.get("data-size")) !== "invisible") {
        const marked =
          classes.some((token) => WIDGET_CLASSES.has(token)) ||
          element.tag === "awswaf-captcha" ||
          element.attrs.has("data-pkey") ||
          WIDGET_FRAGMENTS.some((fragment) => id.includes(fragment) || classes.some((token) => token.includes(fragment)));
        if (marked) seen.add("captcha_widget");
      }
      if (INTERSTITIAL_IDS.has(id) || classes.includes("cf-browser-verification")) seen.add("challenge_interstitial");
      const autocomplete = tokens(element.attrs.get("autocomplete"));
      // OB-07b: a password field (by type or by a password autocomplete
      // token) is remembered, shown or not; a field remembered as one is
      // still one after a page toggled it to plain text.
      const passwordLike = element.tag === "input" && TEXT_TYPES.has(type) && (type === "password" || autocomplete.some((token) => PASSWORD_TOKENS.has(token)));
      if (memory && passwordLike) rememberSecretField(memory, element.backend, element.attrs.get("name"), element.attrs.get("id"));
      const password = passwordLike || (memory !== undefined && element.tag === "input" && TEXT_TYPES.has(type) && wasSecretField(memory, element.backend));
      // Fields: only shown, typed-text inputs count.
      if (!shown || element.tag !== "input" || !TEXT_TYPES.has(type)) continue;
      if (autocomplete.includes("webauthn")) seen.add("webauthn_autocomplete");
      if (!doc.submittable(node)) continue;
      if (password) seen.add("password_field");
      if (autocomplete.includes("one-time-code")) seen.add("otp_autocomplete");
      if (!password && OTP_HINT.test(fieldHint(doc, node, element, labels))) seen.add("otp_field");
      if (element.attrs.get("maxlength") === "1") singles.set(element.parent, (singles.get(element.parent) ?? 0) + 1);
    }
    for (const count of singles.values()) if (count >= 4 && count <= 8) seen.add("otp_split");
    // Passkey prompts: a button, link, heading or label that names one.
    for (const [node, element] of doc.elements) {
      if (!doc.shown(node) || !isOwner(element)) continue;
      const said = `${doc.owned.get(node) ?? ""} ${element.attrs.get("aria-label") ?? ""}`;
      if (PASSKEY_CUE.test(said)) seen.add("passkey_prompt");
    }
    if (d === 0) {
      const title = documents[0]?.title;
      const titled = title !== undefined && title >= 0 ? (strings[title] ?? "") : "";
      if (/^\s*just a moment\b/i.test(titled)) seen.add("challenge_interstitial");
    }
  }
  if (BOT_CHECK_TEXT.test(cue.text)) seen.add("challenge_text");
  if (status === 401 || status === 407) seen.add("http_auth");
  if (status === 403 || status === 429 || status === 503) seen.add("http_blocked");
  const signals = CHALLENGE_SIGNALS.filter((signal) => seen.has(signal));
  return { kind: kindOf(seen), signals, truncated };
}

/// The kind the signals add up to. A blocked status alone is not a
/// challenge (nothing on such a page asks a person for anything).
function kindOf(seen: Set<ChallengeSignal>): ChallengeKind {
  const any = (...signals: ChallengeSignal[]) => signals.some((signal) => seen.has(signal));
  if (any("captcha_frame", "captcha_widget", "challenge_interstitial", "challenge_text")) return "captcha";
  if (any("otp_autocomplete", "otp_field", "otp_split")) return "mfa";
  if (any("password_field", "http_auth")) return "sign_in";
  if (any("webauthn_autocomplete", "passkey_prompt")) return "passkey";
  return "none";
}
