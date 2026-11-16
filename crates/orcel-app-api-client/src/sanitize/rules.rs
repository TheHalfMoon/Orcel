//! The value rules of the sanitiser (SG-000119 packet, "The sanitiser"):
//! text, identifier, epoch, path, file-name and hash. Each is a pure
//! function of the value alone. None of them touches the file system: a path
//! is judged as text, never joined to a root, opened or resolved.

/// The character every replaced character becomes.
pub const REPLACEMENT: char = '\u{FFFD}';

/// Unicode general category Cf (format characters), Unicode 16.0
/// (`DerivedGeneralCategory.txt`). Inclusive ranges, sorted.
const FORMAT_CHARACTERS: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` is a Unicode format character (general category Cf), which
/// includes the bidi controls U+200E, U+200F, U+202A to U+202E, U+2066 to
/// U+2069 and U+061C, and the zero-width characters.
pub fn is_format(c: char) -> bool {
    let c = u32::from(c);
    FORMAT_CHARACTERS
        .binary_search_by(|&(low, high)| {
            if high < c {
                std::cmp::Ordering::Less
            } else if low > c {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether the text rule replaces `c`: C0 and C1 controls (and DEL), every
/// format character, and U+2028 and U+2029.
pub fn is_replaced(c: char) -> bool {
    c.is_control() || is_format(c) || c == '\u{2028}' || c == '\u{2029}'
}

/// The text rule: every replaced character becomes U+FFFD, then the text is
/// cut to at most `max_chars` characters.
pub fn text(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .map(|c| if is_replaced(c) { REPLACEMENT } else { c })
        .take(max_chars)
        .collect()
}

/// `value` when it is 1 to `max` bytes, every byte accepted by `allowed`.
/// Only ASCII is ever allowed, so bytes and characters agree.
pub fn charset(value: &str, max: usize, allowed: impl Fn(u8) -> bool) -> Option<String> {
    (!value.is_empty() && value.len() <= max && value.bytes().all(allowed))
        .then(|| value.to_owned())
}

/// `[A-Za-z0-9_-]`, the identifier characters.
pub fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// The identifier rule for `task_id`, `workspace_id` and `run_id`: 1 to 128
/// characters of `[A-Za-z0-9_-]`.
pub fn identifier(value: &str) -> Option<String> {
    charset(value, 128, identifier_byte)
}

/// The identifier rule for `step_id`: `s` followed by 1 to 4 digits.
pub fn step_id(value: &str) -> Option<String> {
    let digits = value.strip_prefix('s')?;
    (!digits.is_empty() && digits.len() <= 4 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| value.to_owned())
}

/// orceld's epoch, `format!("{:x}-{:x}", pid, nanos)` (`new_epoch` in
/// `crates/orceld/src/app_api.rs`): 1 to 8 lowercase hex digits, a hyphen,
/// and 1 to 32 lowercase hex digits.
pub fn epoch(value: &str) -> Option<String> {
    let (pid, nanos) = value.split_once('-')?;
    let hex = |part: &str, max: usize| {
        !part.is_empty()
            && part.len() <= max
            && part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    (hex(pid, 8) && hex(nanos, 32)).then(|| value.to_owned())
}

/// The hash rule for `sha256` fields: exactly 64 lowercase hex characters.
pub fn sha256(value: &str) -> Option<String> {
    (value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| value.to_owned())
}

/// Characters that look like a path separator or a dot: division and
/// fraction slashes, fullwidth and small solidus and reverse solidus, the set
/// minus, fullwidth and small full stops, the one-dot leader, the ideographic
/// and halfwidth ideographic full stops.
const LOOKALIKES: &[char] = &[
    '\u{2215}', '\u{2044}', '\u{29F8}', '\u{29F9}', '\u{FF0F}', '\u{FF3C}', '\u{FE68}', '\u{2216}',
    '\u{FF0E}', '\u{2024}', '\u{FE52}', '\u{3002}', '\u{FF61}',
];

/// Whether `segment` names a Windows device (`CON`, `PRN`, `AUX`, `NUL`,
/// `CONIN$`, `CONOUT$`, `CLOCK$`, `COM1`-`COM9`, `LPT1`-`LPT9`, and `COM` or
/// `LPT` with a superscript one, two or three), with or without an
/// extension, in any case.
fn is_device_name(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    match stem.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$" => true,
        _ => match stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
        {
            Some(digit) => matches!(
                digit,
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{B9}"
                    | "\u{B2}"
                    | "\u{B3}"
            ),
            None => false,
        },
    }
}

/// The path rule for `folder`, `sources[].path`, `proposal.destination`,
/// `report.destination` and `check.destination`. A path is kept only if it
/// is workspace-relative: not empty, at most 1024 bytes, no leading `/` or
/// `\` (which also refuses UNC and `\\?\` prefixes), no `:` anywhere (a
/// drive letter or an alternate data stream), no segment (split at `/` and
/// `\`) that is empty once trailing dots and spaces are trimmed (`.`, `..`,
/// `...`, `. `), no Windows device name segment, no character that looks like
/// a separator or a dot, and no character the text rule would replace (NUL
/// included). It is never resolved.
pub fn workspace_path(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 1024 {
        return None;
    }
    if value.starts_with(['/', '\\']) || value.contains(':') {
        return None;
    }
    if value
        .chars()
        .any(|c| c == '\0' || is_replaced(c) || LOOKALIKES.contains(&c))
    {
        return None;
    }
    let bad_segment = |segment: &str| {
        !segment.is_empty()
            && (segment.trim_end_matches(['.', ' ']).is_empty() || is_device_name(segment))
    };
    if value.split(['/', '\\']).any(bad_segment) {
        return None;
    }
    Some(value.to_owned())
}

/// The file-name rule for `proposal.name` and `report.name`: the path rule,
/// no `/` or `\`, at most 255 bytes.
pub fn file_name(value: &str) -> Option<String> {
    if value.len() > 255 || value.contains(['/', '\\']) {
        return None;
    }
    workspace_path(value)
}
