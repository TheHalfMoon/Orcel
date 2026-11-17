//! SG-000135 OB-08: the positive routine classification of a browser
//! action's target, for Full Access leases.
//!
//! Under a browser lease orceld dispatches an action without a per-action
//! prompt only when its target is positively classified [`Impact::Routine`].
//! Anything this module cannot read, and anything that names a submit,
//! send, buy, pay, publish, delete or other consequential effect, is not
//! routine, so it asks as before (fail closed). The classification is a
//! heuristic over page-supplied text: a page can name a "Buy" control
//! "Next", so it narrows what a lease covers and never widens it, and
//! routine is never inferred from the absence of a known word alone: a
//! name or URL must also be readable (printable ASCII, bounded) to be
//! classified at all.
//!
//! The browser host classifies links (their accessible names never leave
//! it); orceld classifies form fields from the facts their prompt already
//! shows, and navigation URLs, with the same functions. It lives here, in
//! the crate both depend on, so there is one classifier. orceld also
//! refuses (never classifies) a field whose name the host's secret rule
//! flags, before any of this runs.

/// The classification of one target. On the host's wire it is one of
/// `routine`, `high_impact` or `unknown`; anything else fails to parse, and
/// the reply with it is refused (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    /// Positively classified routine.
    Routine,
    /// Names a consequential effect: never covered by a routine lease.
    HighImpact,
    /// Not classifiable: never covered by a routine lease.
    Unknown,
}

impl Impact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Routine => "routine",
            Self::HighImpact => "high_impact",
            Self::Unknown => "unknown",
        }
    }

    /// The classification named exactly `text`; anything else is unknown.
    pub fn parse(text: &str) -> Self {
        match text {
            "routine" => Self::Routine,
            "high_impact" => Self::HighImpact,
            _ => Self::Unknown,
        }
    }
}

/// The longest name or URL this module classifies.
const MAX_CLASSIFIED_BYTES: usize = 2048;

/// Whole words that name a consequential effect (lowercase ASCII).
const HIGH_IMPACT_WORDS: &[&str] = &[
    "accept",
    "agree",
    "allow",
    "apply",
    "approve",
    "authorize",
    "authorise",
    "bid",
    "book",
    "buy",
    "cancel",
    "cart",
    "checkout",
    "close",
    "comment",
    "confirm",
    "connect",
    "deactivate",
    "decline",
    "delete",
    "deposit",
    "destroy",
    "disable",
    "discard",
    "donate",
    "download",
    "enable",
    "erase",
    "finish",
    "follow",
    "grant",
    "install",
    "invite",
    "join",
    "like",
    "login",
    "logout",
    "message",
    "order",
    "pay",
    "payment",
    "place",
    "post",
    "publish",
    "purchase",
    "register",
    "reject",
    "remove",
    "rent",
    "reply",
    "report",
    "reserve",
    "reset",
    "revoke",
    "save",
    "sell",
    "send",
    "share",
    "signin",
    "signout",
    "signup",
    "submit",
    "subscribe",
    "trade",
    "transfer",
    "unfollow",
    "unsubscribe",
    "update",
    "upload",
    "vote",
    "withdraw",
];

/// Two-word phrases that name a consequential effect.
const HIGH_IMPACT_PAIRS: &[(&str, &str)] = &[
    ("log", "in"),
    ("log", "out"),
    ("sign", "in"),
    ("sign", "out"),
    ("sign", "up"),
    ("check", "out"),
    ("add", "to"),
];

/// Run-together forms a URL or a name may carry ("addToCart",
/// "/account/logout").
const HIGH_IMPACT_FRAGMENTS: &[&str] = &[
    "addtocart",
    "checkout",
    "delete",
    "login",
    "logout",
    "payment",
    "purchase",
    "remove",
    "signin",
    "signout",
    "signup",
    "submit",
    "unsubscribe",
    "transfer",
];

/// Field names that ask for payment, account or identity data: never a
/// routine fill, even when not secret.
const SENSITIVE_FIELD_WORDS: &[&str] = &[
    "account",
    "amount",
    "bank",
    "beneficiary",
    "bic",
    "billing",
    "card",
    "credit",
    "cvc",
    "cvv",
    "debit",
    "expiration",
    "expiry",
    "iban",
    "licence",
    "license",
    "passport",
    "payee",
    "payment",
    "recipient",
    "routing",
    "ssn",
    "swift",
    "tax",
];

/// Field-name words that suggest a secret (the host's own, fuller rule
/// refuses such fields outright; these keep this module fail closed on its
/// own).
const SECRET_FIELD_WORDS: &[&str] = &[
    "code",
    "otp",
    "passcode",
    "passphrase",
    "password",
    "pin",
    "secret",
    "token",
];

/// The roles a routine fill or select may target.
const ROUTINE_FIELD_ROLES: &[&str] = &["textbox", "searchbox", "combobox", "listbox"];

/// Whether `text` is something this module reads at all: non-empty after
/// trimming, bounded, printable ASCII only.
fn readable(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_CLASSIFIED_BYTES
        && text.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Whether the words name a consequential effect.
fn names_effect(words: &[String]) -> bool {
    let has_word = words
        .iter()
        .any(|word| HIGH_IMPACT_WORDS.contains(&word.as_str()));
    let has_pair = words.windows(2).any(|pair| {
        HIGH_IMPACT_PAIRS
            .iter()
            .any(|(a, b)| pair[0] == *a && pair[1] == *b)
    });
    let joined: String = words.concat();
    let has_fragment = HIGH_IMPACT_FRAGMENTS
        .iter()
        .any(|fragment| joined.contains(fragment));
    has_word || has_pair || has_fragment
}

/// A navigation's destination: routine when it is a readable `https://`
/// URL whose path and query name no consequential effect. The origin is
/// the lease's business, not this module's.
pub fn classify_destination(url: &str) -> Impact {
    let Some(rest) = url.strip_prefix("https://") else {
        return Impact::Unknown;
    };
    if !readable(url) {
        return Impact::Unknown;
    }
    let tail = match rest.find(['/', '?', '#']) {
        Some(at) => &rest[at..],
        None => "",
    };
    // The fragment never reaches the server.
    let tail = tail.split('#').next().unwrap_or("");
    if names_effect(&words(tail)) {
        Impact::HighImpact
    } else {
        Impact::Routine
    }
}

/// A link activation: routine when the link's accessible name is readable
/// and names no consequential effect, and its destination is routine.
pub fn classify_link(name: &str, destination: &str) -> Impact {
    if !readable(name) {
        return Impact::Unknown;
    }
    if names_effect(&words(name)) {
        return Impact::HighImpact;
    }
    classify_destination(destination)
}

/// A fill or select target: routine when its role is a text field or a
/// list, and its name is readable, not secret-looking and names neither a
/// consequential effect nor payment, account or identity data.
pub fn classify_field(role: &str, name: &str) -> Impact {
    if !ROUTINE_FIELD_ROLES.contains(&role) || !readable(name) {
        return Impact::Unknown;
    }
    let words = words(name);
    if words
        .iter()
        .any(|word| SECRET_FIELD_WORDS.contains(&word.as_str()) || word.starts_with("passw"))
        || names_effect(&words)
        || words
            .iter()
            .any(|word| SENSITIVE_FIELD_WORDS.contains(&word.as_str()))
    {
        return Impact::HighImpact;
    }
    Impact::Routine
}

/// Prefixes of well-known credential formats (API keys, tokens, keys).
const SECRET_VALUE_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "akia",
    "asia",
    "aiza",
    "ya29.",
    "eyj",
    "-----begin",
];

/// The Luhn check of a card-number-like digit string.
fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (index, digit) in digits.iter().rev().enumerate() {
        let mut value = u32::from(*digit);
        if index % 2 == 1 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    sum % 10 == 0
}

/// OB-08 review: whether a value an agent would type under a Full Access
/// lease looks like a secret, by the secret-field detector's words (a
/// password, PIN, token, one-time code, security code) and the shapes of
/// secrets themselves: a card number (13 to 19 digits passing Luhn), a
/// PIN or one-time code (4 to 8 digits alone), a known credential prefix,
/// or one long unbroken token mixing letters and digits. A value it flags
/// is never typed without the person seeing it.
pub fn value_looks_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let words = words(trimmed);
    let secret_word = words.iter().any(|word| {
        SECRET_FIELD_WORDS.contains(&word.as_str())
            || word.starts_with("passw")
            || matches!(word.as_str(), "cvc" | "cvv" | "csc" | "otp")
    });
    let digits: Vec<u8> = trimmed
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect();
    let only_digits_and_separators = trimmed
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b' ' || b == b'-');
    let card = only_digits_and_separators && (13..=19).contains(&digits.len()) && luhn(&digits);
    let pin = trimmed.bytes().all(|b| b.is_ascii_digit()) && (4..=8).contains(&trimmed.len());
    let lower = trimmed.to_ascii_lowercase();
    let prefixed = SECRET_VALUE_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix));
    let token = trimmed.len() >= 20
        && !trimmed.contains(char::is_whitespace)
        && trimmed.bytes().any(|b| b.is_ascii_digit())
        && trimmed.bytes().any(|b| b.is_ascii_alphabetic());
    secret_word || card || pin || prefixed || token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_looking_values_are_flagged_and_ordinary_ones_are_not() {
        for value in [
            "4111 1111 1111 1111",
            "4111-1111-1111-1111",
            "123456",
            "0042",
            "sk-abc123",
            "AKIAIOSFODNN7EXAMPLE",
            "eyJhbGciOiJIUzI1NiJ9.e30.x",
            "my password is hunter2",
            "a1b2c3d4e5f6g7h8i9j0k1",
        ] {
            assert!(value_looks_secret(value), "{value}");
        }
        // Assembled at run time, so no secret-shaped literal is in the
        // source (the release-blocker sweep refuses those).
        for value in [
            format!("{}{}", "gh", "p_0123456789abcdefABCDEF"),
            format!("{}BEGIN {}KEY{}", "-".repeat(5), "PRIVATE ", "-".repeat(5)),
        ] {
            assert!(value_looks_secret(&value), "{value}");
        }
        for value in [
            "",
            "Ada Lovelace",
            "Round 3",
            "Porto",
            "4111 1111 1111 1112",
            "12",
            "123456789",
            "Meet at 10:30 on 2026-11-17",
        ] {
            assert!(!value_looks_secret(value), "{value}");
        }
    }

    #[test]
    fn submit_send_buy_publish_and_delete_links_are_high_impact() {
        for name in [
            "Submit",
            "Submit order",
            "Send message",
            "Buy now",
            "Place order",
            "Publish",
            "Delete",
            "Delete account",
            "Remove item",
            "Pay",
            "Check out",
            "Checkout",
            "Add to cart",
            "addToCart",
            "Sign in",
            "Log out",
            "Unsubscribe",
            "Confirm transfer",
            "SAVE",
        ] {
            assert_eq!(
                classify_link(name, "https://fixture.test/next"),
                Impact::HighImpact,
                "{name}"
            );
        }
    }

    #[test]
    fn unreadable_or_empty_names_are_unknown_never_routine() {
        for name in [
            "",
            "   ",
            "Kaufen \u{2192}",
            "\u{8cfc}\u{5165}",
            "Next\u{200b}",
            "tab\there",
        ] {
            assert_eq!(
                classify_link(name, "https://fixture.test/next"),
                Impact::Unknown,
                "{name:?}"
            );
        }
        assert_eq!(
            classify_link(
                &"a".repeat(MAX_CLASSIFIED_BYTES + 1),
                "https://fixture.test/"
            ),
            Impact::Unknown
        );
    }

    #[test]
    fn ordinary_links_to_ordinary_pages_are_routine() {
        for (name, destination) in [
            (
                "Continue to the second page",
                "https://fixture.test/ob01-done",
            ),
            ("Next", "https://fixture.test/page/2"),
            ("Read more", "https://fixture.test/articles?id=7"),
        ] {
            assert_eq!(classify_link(name, destination), Impact::Routine, "{name}");
        }
        // The destination is classified too.
        for destination in [
            "https://fixture.test/account/logout",
            "https://fixture.test/cart/add?item=1",
            "https://fixture.test/items/7/delete",
            "https://fixture.test/x?action=submit",
            "http://fixture.test/next",
            "https://fixture.test/\u{e9}",
        ] {
            assert_ne!(
                classify_link("Next", destination),
                Impact::Routine,
                "{destination}"
            );
        }
        // A fragment is not sent; it does not make a page consequential.
        assert_eq!(
            classify_destination("https://fixture.test/page#delete"),
            Impact::Routine
        );
    }

    #[test]
    fn fields_are_routine_only_when_ordinary_and_named() {
        for (role, name) in [
            ("textbox", "Full name"),
            ("searchbox", "Search"),
            ("combobox", "City"),
            ("listbox", "Colour"),
        ] {
            assert_eq!(classify_field(role, name), Impact::Routine, "{name}");
        }
        for (role, name) in [
            ("textbox", "Password"),
            ("textbox", "Card number"),
            ("textbox", "Credit card"),
            ("textbox", "IBAN"),
            ("textbox", "Amount"),
            ("textbox", "Recipient"),
            ("textbox", "One time code"),
            ("combobox", "Expiry month"),
        ] {
            assert_eq!(classify_field(role, name), Impact::HighImpact, "{name}");
        }
        for (role, name) in [
            ("button", "Full name"),
            ("checkbox", "Remember me"),
            ("textbox", ""),
            ("textbox", "Nom\u{e9}"),
        ] {
            assert_eq!(classify_field(role, name), Impact::Unknown, "{role} {name}");
        }
    }

    #[test]
    fn only_the_three_words_parse() {
        for impact in [Impact::Routine, Impact::HighImpact, Impact::Unknown] {
            assert_eq!(Impact::parse(impact.as_str()), impact);
        }
        for text in ["", "Routine", "routine ", "low", "safe"] {
            assert_eq!(Impact::parse(text), Impact::Unknown, "{text:?}");
        }
    }
}
