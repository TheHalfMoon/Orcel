// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Exact-window capture rules (XP-07).
//!
//! The pixels come from Cua's capture modules (`cua_adapter::capture_window`,
//! patch P-08). This module holds what Orcel adds around them, in the order
//! the worker applies it:
//!
//! 1. Scope. Only the bound window is read. The request has no display,
//!    monitor or region form, and the host never calls Cua's display
//!    capture.
//! 2. Protected surfaces. [`is_protected_window`] mirrors the kernel rule in
//!    `crates/orcel-provider-uia/src/lib.rs` (title and class markers per OS)
//!    and is checked before any pixel is read. The protected executables of
//!    `map.rs` are refused earlier, with the owner.
//! 3. Exposure. On X11, Cua reads the window's area of the screen, so a
//!    window covered by another one would carry the other window's pixels.
//!    [`x11::exposure`] refuses a covered, clipped or unmapped window before
//!    the capture and again after it.
//! 4. Bounds. At most 7680x4320 and 8 MiB of RGBA, as on Windows. A larger
//!    window is refused with `output_limit`, never scaled down.
//! 5. Prompts. Nothing here or in the capture path raises a permission
//!    dialog. On macOS the worker captures only with Screen Recording
//!    granted and, from macOS 15, with replayd's direct-capture consent
//!    already recorded for the app macOS holds responsible for the host
//!    ([`macos::direct_capture_consent`]).
//!
//! No pointer is drawn: X11 `GetImage` never includes it, and P-08 turns it
//! off in the ScreenCaptureKit configuration.

use crate::protocol::{CaptureFact, MAX_CAPTURE_BYTES, MAX_CAPTURE_HEIGHT, MAX_CAPTURE_WIDTH};
use base64::Engine as _;

/// The only pixel format sent, as on Windows.
pub const PIXEL_FORMAT: &str = "rgba8";

/// Mirror of `PROTECTED_WINDOW_MARKERS` in `orcel-provider-uia`: Orcel's own
/// approval, trust and revoke surfaces.
pub const PROTECTED_WINDOW_MARKERS: &[&str] = &[
    "orcelapprove",
    "orcel approval",
    "orcel trust",
    "orcel emergency revoke",
];

/// Mirror of `OS_PROTECTED_WINDOW_MARKERS` in `orcel-provider-uia` for the
/// OS this host serves: lock screens and authentication or password
/// dialogs. `protected_markers_match_the_kernel_rule` keeps the two equal.
#[cfg(target_os = "macos")]
pub const OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[
    "loginwindow",
    "securityagent",
    "screensaver",
    "coreautha",
    "authorizationhost",
];
#[cfg(not(target_os = "macos"))]
pub const OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[
    "polkit",
    "screensaver",
    "i3lock",
    "swaylock",
    "light-locker",
    "kscreenlocker",
    "xsecurelock",
    "pinentry",
    "askpass",
    "gcr-prompter",
    "kwalletd",
];

/// The kernel's `is_protected_window`, applied by the host before capture.
/// `class` is the owning application and executable on macOS and Linux.
pub fn is_protected_window(title: &str, class: &str) -> bool {
    let haystack = format!("{title} {class}").to_ascii_lowercase();
    PROTECTED_WINDOW_MARKERS
        .iter()
        .chain(OS_PROTECTED_WINDOW_MARKERS)
        .any(|marker| haystack.contains(marker))
}

/// Why a frame was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameRefusal {
    /// Over 7680x4320 or 8 MiB of RGBA (`output_limit`).
    TooLarge(String),
    /// Empty or undecodable output (`provider_unavailable`).
    Unreadable(String),
}

/// Whether a window of these reported dimensions cannot fit the bounds. The
/// worker checks this before capturing; a frame is checked again exactly.
/// Reported points never exceed captured pixels, so this refuses nothing
/// the exact check would allow.
pub fn reported_size_exceeds_bounds(width: f64, height: f64) -> bool {
    !(width.is_finite() && height.is_finite())
        || width > f64::from(MAX_CAPTURE_WIDTH)
        || height > f64::from(MAX_CAPTURE_HEIGHT)
        || width.max(0.0) * height.max(0.0) * 4.0 > MAX_CAPTURE_BYTES as f64
}

fn check_dimensions(width: u32, height: u32) -> Result<usize, FrameRefusal> {
    if width == 0 || height == 0 {
        return Err(FrameRefusal::Unreadable(format!(
            "the captured frame is empty ({width}x{height})"
        )));
    }
    if width > MAX_CAPTURE_WIDTH || height > MAX_CAPTURE_HEIGHT {
        return Err(FrameRefusal::TooLarge(format!(
            "the window is {width}x{height} pixels, over the {MAX_CAPTURE_WIDTH}x{MAX_CAPTURE_HEIGHT} capture bound"
        )));
    }
    let bytes = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .filter(|bytes| *bytes <= MAX_CAPTURE_BYTES)
        .ok_or_else(|| {
            FrameRefusal::TooLarge(format!(
                "the window is {width}x{height} pixels, over the {MAX_CAPTURE_BYTES}-byte capture bound"
            ))
        })?;
    Ok(bytes)
}

/// Converts Cua's PNG of one window into the wire frame: 8-bit RGBA. The
/// header is read and bounded before anything is decoded.
pub fn frame_from_png(png: &[u8]) -> Result<CaptureFact, FrameRefusal> {
    use image::{ImageFormat, ImageReader, Limits};
    let unreadable = |error: image::ImageError| {
        FrameRefusal::Unreadable(format!("the captured frame is not a readable PNG: {error}"))
    };
    let reader = || ImageReader::with_format(std::io::Cursor::new(png), ImageFormat::Png);
    let (width, height) = reader().into_dimensions().map_err(unreadable)?;
    let expected = check_dimensions(width, height)?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_CAPTURE_WIDTH);
    limits.max_image_height = Some(MAX_CAPTURE_HEIGHT);
    // The decoder may hold one 16-bit RGBA copy beside the 8-bit result.
    limits.max_alloc = Some(3 * MAX_CAPTURE_BYTES as u64);
    let mut decoder = reader();
    decoder.limits(limits);
    let rgba = decoder.decode().map_err(unreadable)?.into_rgba8();
    if rgba.width() != width || rgba.height() != height || rgba.as_raw().len() != expected {
        return Err(FrameRefusal::Unreadable(
            "the decoded frame does not match its header".to_owned(),
        ));
    }
    Ok(CaptureFact {
        width,
        height,
        pixel_format: PIXEL_FORMAT.to_owned(),
        pixels_b64: base64::engine::general_purpose::STANDARD.encode(rgba.as_raw()),
    })
}

/// X11 exposure of one window, read on the host's own connection.
#[cfg(target_os = "linux")]
pub mod x11 {
    use x11rb::connection::Connection as _;
    use x11rb::protocol::xproto::{ConnectionExt as _, MapState, Window, WindowClass};
    use x11rb::rust_connection::RustConnection;

    /// What the screen shows of a window's own area.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Exposure {
        /// Every pixel of the window is its own.
        Exposed,
        /// Another mapped window overlaps it.
        Covered,
        /// Part of it is off screen or outside a parent.
        Clipped,
        /// It is not viewable (unmapped, minimized, or a parent is).
        NotViewable,
    }

    /// A rectangle in root coordinates: x, y, width, height.
    pub type Rect = (i32, i32, i32, i32);

    pub fn intersects(a: Rect, b: Rect) -> bool {
        a.0 < b.0 + b.2 && b.0 < a.0 + a.2 && a.1 < b.1 + b.3 && b.1 < a.1 + a.3
    }

    pub fn contains(outer: Rect, inner: Rect) -> bool {
        inner.0 >= outer.0
            && inner.1 >= outer.1
            && inner.0 + inner.2 <= outer.0 + outer.2
            && inner.1 + inner.3 <= outer.1 + outer.3
    }

    /// The decision on facts already read: the target's rectangle, the
    /// rectangles it must lie inside (the screen, then each ancestor), and
    /// the viewable windows stacked above its top-level window.
    pub fn classify(target: Rect, containers: &[Rect], above: &[Rect]) -> Exposure {
        if target.2 <= 0 || target.3 <= 0 {
            return Exposure::NotViewable;
        }
        if !containers.iter().all(|outer| contains(*outer, target)) {
            return Exposure::Clipped;
        }
        if above.iter().any(|other| intersects(*other, target)) {
            return Exposure::Covered;
        }
        Exposure::Exposed
    }

    fn rect_in_root(conn: &RustConnection, window: Window, root: Window) -> Result<Rect, String> {
        let geometry = conn
            .get_geometry(window)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        let origin = conn
            .translate_coordinates(window, root, 0, 0)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        Ok((
            i32::from(origin.dst_x),
            i32::from(origin.dst_y),
            i32::from(geometry.width),
            i32::from(geometry.height),
        ))
    }

    /// Reads the exposure of `xid` on `$DISPLAY`. A compositing manager
    /// keeps a covered window's own pixels, but whether this one is
    /// redirected cannot be read, so a covered window is refused there too.
    pub fn exposure(xid: u64) -> Result<Exposure, String> {
        let window = Window::try_from(xid).map_err(|_| "window id is not an X11 id".to_owned())?;
        let (conn, screen) = RustConnection::connect(None).map_err(|e| e.to_string())?;
        let screen = conn
            .setup()
            .roots
            .get(screen)
            .ok_or_else(|| "the X11 screen is unknown".to_owned())?;
        let root = screen.root;
        let attributes = conn
            .get_window_attributes(window)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?;
        if attributes.map_state != MapState::VIEWABLE {
            return Ok(Exposure::NotViewable);
        }
        let target = rect_in_root(&conn, window, root)?;
        let mut containers = vec![(
            0,
            0,
            i32::from(screen.width_in_pixels),
            i32::from(screen.height_in_pixels),
        )];
        // Walk up to the root's child that holds the window (the window
        // manager's frame, or the window itself).
        let mut top = window;
        for _ in 0..64 {
            let tree = conn
                .query_tree(top)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?;
            if tree.parent == root || tree.parent == x11rb::NONE {
                break;
            }
            top = tree.parent;
            containers.push(rect_in_root(&conn, top, root)?);
        }
        let stack = conn
            .query_tree(root)
            .map_err(|e| e.to_string())?
            .reply()
            .map_err(|e| e.to_string())?
            .children;
        let position = stack
            .iter()
            .position(|child| *child == top)
            .ok_or_else(|| "the window is not in the root stacking order".to_owned())?;
        let mut above = Vec::new();
        for sibling in &stack[position + 1..] {
            let Ok(cookie) = conn.get_window_attributes(*sibling) else {
                continue;
            };
            // A sibling destroyed meanwhile covers nothing.
            let Ok(sibling_attributes) = cookie.reply() else {
                continue;
            };
            if sibling_attributes.map_state != MapState::VIEWABLE
                || sibling_attributes.class == WindowClass::INPUT_ONLY
            {
                continue;
            }
            let Ok(cookie) = conn.get_geometry(*sibling) else {
                continue;
            };
            let Ok(geometry) = cookie.reply() else {
                continue;
            };
            let border = 2 * i32::from(geometry.border_width);
            above.push((
                i32::from(geometry.x),
                i32::from(geometry.y),
                i32::from(geometry.width) + border,
                i32::from(geometry.height) + border,
            ));
        }
        Ok(classify(target, &containers, &above))
    }
}

/// macOS direct-capture consent for a bare host binary.
#[cfg(target_os = "macos")]
pub mod macos {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// The `.app` bundle that holds `executable`, from its
    /// `X.app/Contents/MacOS/` layout.
    pub fn app_bundle_of(executable: &Path) -> Option<PathBuf> {
        executable
            .ancestors()
            .find(|candidate| {
                candidate.extension().is_some_and(|ext| ext == "app")
                    && executable.starts_with(candidate.join("Contents").join("MacOS"))
            })
            .map(Path::to_path_buf)
    }

    /// The process macOS holds responsible for this one (the app TCC and
    /// replayd attribute a bare binary's requests to). The libSystem call is
    /// looked up at run time; a system without it is unknown.
    fn responsible_pid() -> Option<u32> {
        type Responsible = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;
        // SAFETY: dlsym with RTLD_DEFAULT only searches the loaded images for
        // a NUL-terminated symbol name; it runs no code of the target.
        let symbol = unsafe {
            libc::dlsym(
                libc::RTLD_DEFAULT,
                c"responsibility_get_pid_responsible_for_pid".as_ptr(),
            )
        };
        if symbol.is_null() {
            return None;
        }
        // SAFETY: the symbol is libSystem's
        // `pid_t responsibility_get_pid_responsible_for_pid(pid_t)`, so a
        // function pointer of exactly that signature is the right type.
        let responsible: Responsible = unsafe { std::mem::transmute(symbol) };
        // SAFETY: the call only reads kernel state for the given pid and
        // returns a pid or a negative value; it takes no pointers.
        let pid = unsafe { responsible(libc::pid_t::try_from(std::process::id()).ok()?) };
        u32::try_from(pid).ok().filter(|pid| *pid > 0)
    }

    fn home_directory() -> Option<PathBuf> {
        let uid = orcel_platform::session::effective_uid()?;
        // SAFETY: an all-zero passwd is a valid out-parameter value; every
        // pointer in it is null until getpwuid_r fills it.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buffer = vec![0 as libc::c_char; 16 * 1024];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `entry`, `buffer` (of exactly `buffer.len()` bytes) and
        // `result` are live and writable for the call, and getpwuid_r writes
        // only inside them.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() || entry.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success pw_dir points to a NUL-terminated string inside
        // `buffer`, which outlives this borrow.
        let directory = unsafe { CStr::from_ptr(entry.pw_dir) };
        let directory = PathBuf::from(OsStr::from_bytes(directory.to_bytes()));
        directory.is_absolute().then_some(directory)
    }

    /// `Ok` when a capture cannot raise replayd's direct-capture alert:
    /// before macOS 15, or when the approvals file records the responsible
    /// app. Every unknown fails closed, with the reason.
    pub fn direct_capture_consent() -> Result<(), String> {
        let bundle = responsible_pid()
            .and_then(crate::worker::executable_path)
            .and_then(|path| std::fs::canonicalize(path).ok())
            .and_then(|path| app_bundle_of(&path));
        let home = home_directory().ok_or_else(|| {
            "direct_capture_consent_unknown: the user's home directory is unreadable".to_owned()
        })?;
        let bundle_path = bundle.clone().unwrap_or_default();
        if platform_macos::capture_consent::direct_capture_consent_recorded(&home, &bundle_path) {
            return Ok(());
        }
        Err(match bundle {
            Some(bundle) => format!(
                "direct_capture_consent_missing: macOS has not recorded direct screen capture for {}; \
                 the host never raises that alert",
                bundle.display()
            ),
            None => "direct_capture_consent_unknown: the app macOS holds responsible for the host \
                     is not an app bundle, so its consent cannot be read; the host never raises \
                     that alert"
                .to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(width: u32, height: u32, pixel: [u8; 4]) -> Vec<u8> {
        let image = image::RgbaImage::from_pixel(width, height, image::Rgba(pixel));
        let mut out = std::io::Cursor::new(Vec::new());
        image.write_to(&mut out, image::ImageFormat::Png).unwrap();
        out.into_inner()
    }

    #[test]
    fn a_png_frame_becomes_unpadded_rgba8() {
        let frame = frame_from_png(&png(3, 2, [224, 17, 157, 255])).unwrap();
        assert_eq!((frame.width, frame.height), (3, 2));
        assert_eq!(frame.pixel_format, "rgba8");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&frame.pixels_b64)
            .unwrap();
        assert_eq!(raw.len(), 3 * 2 * 4);
        assert!(raw.chunks_exact(4).all(|px| px == [224, 17, 157, 255]));
    }

    #[test]
    fn oversize_frames_are_refused_before_decoding_never_scaled() {
        // Wider than 7680.
        assert!(matches!(
            frame_from_png(&png(7681, 1, [0; 4])),
            Err(FrameRefusal::TooLarge(_))
        ));
        // Taller than 4320.
        assert!(matches!(
            frame_from_png(&png(1, 4321, [0; 4])),
            Err(FrameRefusal::TooLarge(_))
        ));
        // Inside both edges but over 8 MiB: 2048x1025x4 > 8 MiB.
        assert!(matches!(
            check_dimensions(2048, 1025),
            Err(FrameRefusal::TooLarge(_))
        ));
        assert_eq!(check_dimensions(2048, 1024), Ok(MAX_CAPTURE_BYTES));
        assert!(matches!(
            check_dimensions(0, 10),
            Err(FrameRefusal::Unreadable(_))
        ));
        assert!(matches!(
            frame_from_png(b"not a png"),
            Err(FrameRefusal::Unreadable(_))
        ));
        assert!(reported_size_exceeds_bounds(7681.0, 10.0));
        assert!(reported_size_exceeds_bounds(10.0, 4321.0));
        assert!(reported_size_exceeds_bounds(4000.0, 4000.0));
        assert!(reported_size_exceeds_bounds(f64::NAN, 10.0));
        assert!(!reported_size_exceeds_bounds(1920.0, 1080.0));
    }

    /// A header that claims a huge image is refused from the header alone.
    #[test]
    fn a_forged_png_header_is_bounded_without_allocating() {
        let mut forged = png(1, 1, [0; 4]);
        // IHDR width and height sit at bytes 16..24.
        forged[16..20].copy_from_slice(&60_000u32.to_be_bytes());
        forged[20..24].copy_from_slice(&60_000u32.to_be_bytes());
        assert!(frame_from_png(&forged).is_err());
    }

    #[cfg(target_os = "macos")]
    const OS_SURFACES: &[(&str, &str)] = &[
        ("", "SecurityAgent"),
        ("", "coreautha"),
        ("Login", "loginwindow"),
        ("", "ScreenSaverEngine"),
        ("", "AuthorizationHost"),
    ];
    #[cfg(not(target_os = "macos"))]
    const OS_SURFACES: &[(&str, &str)] = &[
        ("Authenticate", "polkit-gnome-authentication-agent-1"),
        ("", "i3lock"),
        ("", "swaylock"),
        ("Unlock", "kscreenlocker_greet"),
        ("Passphrase", "pinentry-gnome3"),
        ("OpenSSH Authentication", "ssh-askpass"),
        ("Unlock Keyring", "gcr-prompter"),
        ("", "kwalletd6"),
    ];

    #[test]
    fn lock_password_and_orcel_approval_surfaces_are_protected() {
        for (title, class) in OS_SURFACES {
            assert!(is_protected_window(title, class), "{title} {class}");
        }
        for title in [
            "Orcel approval SOFT",
            "Orcel approval STRONG",
            "Orcel Approval Probe 1",
            "OrcelApprove",
            "Orcel Trust",
        ] {
            assert!(is_protected_window(title, "osascript"), "{title}");
        }
        assert!(!is_protected_window("Untitled - Editor", "gedit"));
    }

    /// The host's markers are the kernel's, read from its source, so the
    /// host can never capture a window the registry would protect.
    #[test]
    fn protected_markers_match_the_kernel_rule() {
        let kernel =
            include_str!("../../../crates/orcel-provider-uia/src/lib.rs").replace("\r\n", "\n");
        let kernel = kernel.as_str();
        fn block<'a>(source: &'a str, header: &str) -> Vec<&'a str> {
            let start = source
                .find(header)
                .expect("the kernel names the marker list");
            let body = &source[start + header.len()..];
            let end = body.find("];").expect("marker list ends");
            body[..end].split('"').skip(1).step_by(2).collect()
        }
        assert_eq!(
            block(kernel, "const PROTECTED_WINDOW_MARKERS: &[&str] = &["),
            PROTECTED_WINDOW_MARKERS
        );
        #[cfg(target_os = "macos")]
        let header =
            "#[cfg(target_os = \"macos\")]\nconst OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[";
        #[cfg(not(target_os = "macos"))]
        let header = "#[cfg(all(unix, not(target_os = \"macos\")))]\nconst OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[";
        assert_eq!(block(kernel, header), OS_PROTECTED_WINDOW_MARKERS);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn x11_exposure_refuses_covered_clipped_and_hidden_windows() {
        use x11::{classify, Exposure};
        let screen = (0, 0, 1280, 800);
        let target = (40, 40, 320, 200);
        assert_eq!(classify(target, &[screen], &[]), Exposure::Exposed);
        // A window above that touches one pixel covers it.
        assert_eq!(
            classify(target, &[screen], &[(359, 239, 10, 10)]),
            Exposure::Covered
        );
        // Adjacent is not covering.
        assert_eq!(
            classify(target, &[screen], &[(360, 40, 10, 10)]),
            Exposure::Exposed
        );
        // Off the screen edge, or outside its frame.
        assert_eq!(
            classify((1200, 40, 320, 200), &[screen], &[]),
            Exposure::Clipped
        );
        assert_eq!(
            classify(target, &[screen, (40, 40, 100, 100)], &[]),
            Exposure::Clipped
        );
        assert_eq!(
            classify((40, 40, 0, 200), &[screen], &[]),
            Exposure::NotViewable
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_bundles_are_found_only_for_bundled_executables() {
        use std::path::Path;
        assert_eq!(
            macos::app_bundle_of(Path::new(
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"
            ))
            .as_deref(),
            Some(Path::new("/System/Applications/Utilities/Terminal.app"))
        );
        assert_eq!(
            macos::app_bundle_of(Path::new("/usr/local/bin/orcel-native-host")),
            None
        );
        assert_eq!(
            macos::app_bundle_of(Path::new("/Applications/Odd.app/orcel-native-host")),
            None
        );
    }
}
