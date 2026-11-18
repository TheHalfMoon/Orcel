//! SG-000135 OB-03: page screenshots and tabs of one worker lifetime.
//!
//! A screenshot is a bounded PNG of the lifetime's active tab, taken by the
//! worker with every secret field masked (`apps/orcel-browser-worker/src/
//! screenshot.ts`); it never names a window, a target or another page, and
//! this crate's desktop window capture (SG-000080, `capture.rs`) is never
//! used for it. A PNG is larger than one frame, so it crosses each pipe in
//! base64 pieces, each the encoding of its own slice of bytes; the receiver
//! checks every piece against the first, decodes it strictly, and checks
//! the whole: the byte count, the PNG signature, an IHDR whose size is the
//! reported one, and the bounds below.
//!
//! The bounds mirror the worker's (`screenshot.ts`, `tabs.ts`).

/// The largest PNG one screenshot may be, in bytes.
pub const MAX_SCREENSHOT_BYTES: usize = 2 * 1024 * 1024;
/// The largest screenshot, in CSS pixels at scale 1.
pub const MAX_SCREENSHOT_WIDTH: u32 = 2048;
pub const MAX_SCREENSHOT_HEIGHT: u32 = 4096;
/// One piece's base64 text, a multiple of 4.
pub const MAX_SCREENSHOT_PIECE_CHARS: usize = 48 * 1024;
/// The most pieces one screenshot is sent in.
pub const MAX_SCREENSHOT_PIECES: u32 = 64;
/// The most tabs one lifetime holds.
pub const MAX_TABS: usize = 8;
/// The largest tab id a worker may report (ids are never reused).
pub const MAX_TAB_ID: u32 = 1_000_000;

/// A checked screenshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageScreenshot {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// A full-page capture was cut at the height or width bound.
    pub truncated: bool,
}

/// One tab as the worker reports it: its id and its page's URL (an https
/// or `about:blank` URL, or empty when the worker would not report it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerTab {
    pub tab: u32,
    pub url: String,
}

/// The lifetime's tabs after a tab request; `active` is 0 when none is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabsState {
    pub active: u32,
    pub tabs: Vec<WorkerTab>,
}

impl TabsState {
    /// Check a worker's report: at most `MAX_TABS` distinct ids in order,
    /// each within range, every URL bounded and https, `about:blank` or
    /// empty, and the active id one of them (or 0 with no tab at all
    /// active).
    pub fn checked(active: u32, tabs: Vec<WorkerTab>) -> Result<Self, &'static str> {
        if tabs.len() > MAX_TABS {
            return Err("more tabs than the cap");
        }
        let mut last = 0u32;
        for tab in &tabs {
            if tab.tab == 0 || tab.tab > MAX_TAB_ID || tab.tab <= last {
                return Err("tab ids are not distinct, ordered and in range");
            }
            last = tab.tab;
            let url = tab.url.as_str();
            if url.len() > crate::navigation::MAX_URL_BYTES
                || url.chars().any(char::is_control)
                || !(url.is_empty() || url == "about:blank" || url.starts_with("https://"))
            {
                return Err("a tab URL is not a bounded https or blank URL");
            }
        }
        if active != 0 && !tabs.iter().any(|tab| tab.tab == active) {
            return Err("the active tab is not one of the tabs");
        }
        Ok(Self { active, tabs })
    }

    /// The active tab's URL, if a tab is active.
    pub fn active_url(&self) -> Option<&str> {
        self.tabs
            .iter()
            .find(|tab| tab.tab == self.active)
            .map(|tab| tab.url.as_str())
    }
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (index, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn sextet(byte: u8) -> Option<u32> {
    ALPHABET
        .iter()
        .position(|&c| c == byte)
        .and_then(|index| u32::try_from(index).ok())
}

/// Strict standard base64: a multiple of 4 characters from the alphabet,
/// padding only at the end, and zero padding bits; anything else is None.
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.len() / 4;
    for (index, quad) in bytes.chunks(4).enumerate() {
        let last = index + 1 == quads;
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (position, &c) in quad.iter().enumerate() {
            let value = if position >= 4 - pad { 0 } else { sextet(c)? };
            n = (n << 6) | value;
        }
        let decoded = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        if pad == 2 && n & 0xFFFF != 0 || pad == 1 && n & 0xFF != 0 {
            return None;
        }
        out.extend_from_slice(&decoded[..3 - pad]);
    }
    Some(out)
}

/// A PNG's width and height from its leading IHDR chunk.
pub fn png_dimensions(png: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if png.len() < 24 || png[..8] != SIGNATURE || png[8..12] != [0, 0, 0, 13] {
        return None;
    }
    if &png[12..16] != b"IHDR" {
        return None;
    }
    let read = |at: usize| u32::from_be_bytes([png[at], png[at + 1], png[at + 2], png[at + 3]]);
    Some((read(16), read(20)))
}

/// What every piece of one screenshot repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PieceHeader {
    pub total: u32,
    pub width: u32,
    pub height: u32,
    pub bytes: u64,
    pub truncated: bool,
}

/// Assembles the pieces of one screenshot, in order, checking each.
#[derive(Debug)]
pub struct ScreenshotAssembly {
    header: PieceHeader,
    png: Vec<u8>,
    next: u32,
}

impl ScreenshotAssembly {
    /// Start with piece 0 and the header it carries.
    pub fn start(header: PieceHeader, piece: u32, data: &str) -> Result<Self, &'static str> {
        if header.total == 0 || header.total > MAX_SCREENSHOT_PIECES {
            return Err("piece count out of range");
        }
        if header.width == 0
            || header.height == 0
            || header.width > MAX_SCREENSHOT_WIDTH
            || header.height > MAX_SCREENSHOT_HEIGHT
        {
            return Err("screenshot size out of bounds");
        }
        if header.bytes == 0 || header.bytes > MAX_SCREENSHOT_BYTES as u64 {
            return Err("screenshot byte count out of bounds");
        }
        let mut assembly = Self {
            header,
            png: Vec::new(),
            next: 0,
        };
        assembly.push(header, piece, data)?;
        Ok(assembly)
    }

    /// The next piece to ask for, or None when every piece arrived.
    pub fn next(&self) -> Option<u32> {
        (self.next < self.header.total).then_some(self.next)
    }

    /// Add the next piece: same header, the expected index, bounded and
    /// strictly decodable text, and never past the reported byte count.
    pub fn push(
        &mut self,
        header: PieceHeader,
        piece: u32,
        data: &str,
    ) -> Result<(), &'static str> {
        if header != self.header {
            return Err("a piece disagrees with the first");
        }
        if piece != self.next {
            return Err("pieces out of order");
        }
        if data.is_empty() || data.len() > MAX_SCREENSHOT_PIECE_CHARS {
            return Err("piece text out of bounds");
        }
        let bytes = decode_base64(data).ok_or("piece is not strict base64")?;
        if (self.png.len() + bytes.len()) as u64 > header.bytes {
            return Err("pieces exceed the byte count");
        }
        self.png.extend_from_slice(&bytes);
        self.next += 1;
        Ok(())
    }

    /// The whole PNG, once every piece arrived and it is what was reported.
    pub fn finish(self) -> Result<PageScreenshot, &'static str> {
        if self.next != self.header.total || self.png.len() as u64 != self.header.bytes {
            return Err("the screenshot is incomplete");
        }
        match png_dimensions(&self.png) {
            Some((width, height)) if width == self.header.width && height == self.header.height => {
                Ok(PageScreenshot {
                    png: self.png,
                    width,
                    height,
                    truncated: self.header.truncated,
                })
            }
            _ => Err("not a PNG of the reported size"),
        }
    }
}

/// Split a checked PNG into base64 pieces of at most
/// `MAX_SCREENSHOT_PIECE_CHARS`, each the encoding of its own bytes.
pub fn base64_pieces(png: &[u8]) -> Vec<String> {
    png.chunks(MAX_SCREENSHOT_PIECE_CHARS / 4 * 3)
        .map(encode_base64)
        .collect()
}

#[cfg(test)]
pub(crate) fn test_png(width: u32, height: u32, padding: usize) -> Vec<u8> {
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];
    png.extend_from_slice(b"IHDR");
    png.extend_from_slice(&width.to_be_bytes());
    png.extend_from_slice(&height.to_be_bytes());
    png.extend(std::iter::repeat_n(7u8, 9 + padding));
    png
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_decoding_is_strict() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let text = encode_base64(&bytes);
            assert_eq!(decode_base64(&text), Some(bytes));
        }
        assert_eq!(encode_base64(b"png"), "cG5n");
        assert_eq!(encode_base64(b"pn"), "cG4=");
        for bad in [
            "abc", "ab=c", "a===", "cG4=cG5n", "cG5n\n", "cG5-", "cG5_", "cG5=", "cG4", "Zm9=",
        ] {
            assert_eq!(decode_base64(bad), None, "{bad}");
        }
    }

    fn header(total: u32, bytes: usize) -> PieceHeader {
        PieceHeader {
            total,
            width: 1280,
            height: 720,
            bytes: bytes as u64,
            truncated: false,
        }
    }

    #[test]
    fn a_screenshot_assembles_only_from_consistent_bounded_pieces() {
        let png = test_png(1280, 720, 100_000);
        let pieces = base64_pieces(&png);
        assert_eq!(pieces.len(), 3);
        assert!(pieces.iter().all(|p| p.len() <= MAX_SCREENSHOT_PIECE_CHARS));
        let h = header(3, png.len());
        let mut assembly = ScreenshotAssembly::start(h, 0, &pieces[0]).unwrap();
        assert_eq!(assembly.next(), Some(1));
        // Out of order, a changed header or bad text is refused.
        assert!(assembly.push(h, 2, &pieces[2]).is_err());
        assert!(assembly
            .push(
                PieceHeader {
                    truncated: true,
                    ..h
                },
                1,
                &pieces[1]
            )
            .is_err());
        assert!(assembly.push(h, 1, "not base64!").is_err());
        assembly.push(h, 1, &pieces[1]).unwrap();
        assembly.push(h, 2, &pieces[2]).unwrap();
        assert_eq!(assembly.next(), None);
        let shot = assembly.finish().unwrap();
        assert_eq!(
            (shot.width, shot.height, shot.png),
            (1280, 720, png.clone())
        );
        // A size that disagrees with the PNG, an incomplete set, or bytes
        // past the count are refused.
        let lying = PieceHeader {
            width: 640,
            ..header(3, png.len())
        };
        let mut wrong = ScreenshotAssembly::start(lying, 0, &pieces[0]).unwrap();
        wrong.push(lying, 1, &pieces[1]).unwrap();
        wrong.push(lying, 2, &pieces[2]).unwrap();
        assert!(wrong.finish().is_err());
        assert!(
            ScreenshotAssembly::start(header(3, png.len()), 0, &pieces[0])
                .unwrap()
                .finish()
                .is_err()
        );
        assert!(ScreenshotAssembly::start(header(1, 10), 0, &pieces[0]).is_err());
        // Bounds before anything is decoded.
        for bad in [
            header(0, 10),
            header(MAX_SCREENSHOT_PIECES + 1, 10),
            header(1, 0),
            header(1, MAX_SCREENSHOT_BYTES + 1),
            PieceHeader {
                width: MAX_SCREENSHOT_WIDTH + 1,
                ..header(1, 10)
            },
            PieceHeader {
                height: MAX_SCREENSHOT_HEIGHT + 1,
                ..header(1, 10)
            },
            PieceHeader {
                height: 0,
                ..header(1, 10)
            },
        ] {
            assert!(
                ScreenshotAssembly::start(bad, 0, "cG5n").is_err(),
                "{bad:?}"
            );
        }
        assert!(ScreenshotAssembly::start(header(1, 3), 0, "").is_err());
        let long = "A".repeat(MAX_SCREENSHOT_PIECE_CHARS + 4);
        assert!(ScreenshotAssembly::start(header(1, MAX_SCREENSHOT_BYTES), 0, &long).is_err());
        assert_eq!(png_dimensions(b"\x89PNG\r\n\x1a\n"), None);
        assert!(
            MAX_SCREENSHOT_PIECES as usize * (MAX_SCREENSHOT_PIECE_CHARS / 4 * 3)
                >= MAX_SCREENSHOT_BYTES
        );
    }

    #[test]
    fn tab_reports_are_checked() {
        let tab = |tab: u32, url: &str| WorkerTab {
            tab,
            url: url.into(),
        };
        let ok = TabsState::checked(
            2,
            vec![
                tab(1, "https://fixture.test/"),
                tab(2, "about:blank"),
                tab(5, ""),
            ],
        )
        .unwrap();
        assert_eq!(ok.active_url(), Some("about:blank"));
        assert!(TabsState::checked(0, vec![]).is_ok());
        for (active, tabs) in [
            (3, vec![tab(1, "https://fixture.test/")]),
            (
                1,
                vec![tab(1, "https://a.test/"), tab(1, "https://a.test/")],
            ),
            (
                2,
                vec![tab(2, "https://a.test/"), tab(1, "https://a.test/")],
            ),
            (0, vec![tab(0, "https://a.test/")]),
            (0, vec![tab(MAX_TAB_ID + 1, "")]),
            (1, vec![tab(1, "http://a.test/")]),
            (1, vec![tab(1, "chrome-error://chromewebdata/")]),
            (1, vec![tab(1, "https://a.test/\u{7}")]),
            (1, (1..=9).map(|i| tab(i, "")).collect()),
        ] {
            assert!(
                TabsState::checked(active, tabs.clone()).is_err(),
                "{tabs:?}"
            );
        }
    }
}
