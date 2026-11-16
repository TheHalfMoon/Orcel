//! SG-000119 A2 build script: Tauri's ACL, Windows resources and context
//! codegen through `tauri-build` (no Tauri CLI).
//!
//! tauri-build embeds a window icon in the Windows resources and refuses to
//! build without one. Rather than a binary file in the repository, the icon
//! is drawn here into OUT_DIR: a 32x32 dark square with a light ring.
//! A2 registers no command, so there is no `AppManifest` yet; slice A3 lists
//! exactly its five commands here.

use std::path::PathBuf;

const SIZE: usize = 32;

/// A 32-bit 32x32 icon: one ICONDIR entry pointing at a BMP (BITMAPINFOHEADER,
/// bottom-up BGRA pixels, then the AND mask).
fn icon() -> Vec<u8> {
    let pixels = SIZE * SIZE * 4;
    let mask = SIZE * 4; // 32 rows of 32 bits, already 4-byte aligned
    let image = 40 + pixels + mask;
    let mut out = Vec::with_capacity(6 + 16 + image);
    // ICONDIR: reserved, type 1 (icon), one image.
    out.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    // ICONDIRENTRY: width, height, colours, reserved, planes, bit count,
    // size, offset.
    out.extend_from_slice(&[SIZE as u8, SIZE as u8, 0, 0, 1, 0, 32, 0]);
    out.extend_from_slice(&(image as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes());
    // BITMAPINFOHEADER; the height counts the colour and mask halves.
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&(SIZE as i32).to_le_bytes());
    out.extend_from_slice(&((SIZE * 2) as i32).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&[0; 4]); // BI_RGB
    out.extend_from_slice(&(pixels as u32).to_le_bytes());
    out.extend_from_slice(&[0; 16]);
    let centre = (SIZE as f32 - 1.0) / 2.0;
    for row in (0..SIZE).rev() {
        for column in 0..SIZE {
            let dx = column as f32 - centre;
            let dy = row as f32 - centre;
            let distance = (dx * dx + dy * dy).sqrt();
            let ring = (9.0..=12.5).contains(&distance);
            let [b, g, r] = if ring {
                [0xF2, 0xEE, 0xE8]
            } else {
                [0x2A, 0x1E, 0x16]
            };
            out.extend_from_slice(&[b, g, r, 0xFF]);
        }
    }
    out.extend(std::iter::repeat_n(0u8, mask));
    out
}

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let icon_path = out_dir.join("orcel-control-room.ico");
    std::fs::write(&icon_path, icon()).expect("write the window icon");
    let attributes = tauri_build::Attributes::new()
        .windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path(&icon_path));
    tauri_build::try_build(attributes).expect("tauri-build (ACL, resources, context)");
}
