//! Review of #849: the names in a repository's index. Git checks a name when
//! it adds one, not when it reads an index file, and joins it to the working
//! tree for every comparison, so a name that is not a plain relative path
//! would lead it out of the working tree. The whole listing is checked, as
//! bytes, before any command that compares the index with the working tree.
//! A name any platform reads as Git's own folder is refused everywhere; a
//! name that only means something else on Windows (a drive, a backslash, a
//! colon, a trailing dot or space, a device) is refused there, where it is an
//! ordinary name elsewhere.

use crate::GitProviderError;
use orcel_contracts::FailureCode;
use std::collections::BTreeSet;

/// The largest index listing the provider checks; a larger one is refused.
pub(crate) const MAX_INDEX_BYTES: usize = 256 * 1024 * 1024;

fn refused() -> GitProviderError {
    GitProviderError::new(
        FailureCode::PathEscape,
        "Git's index has a name that is not a plain path in the working tree; Orcel does not run Git in the repository",
    )
}

/// Whether a path component is read as `.git` somewhere: any case, `git~1`
/// and the like, with code points HFS+ ignores, or with what Windows drops.
fn is_git_folder_name(part: &str) -> bool {
    let plain: String = part
        .chars()
        .filter(|c| {
            !matches!(*c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}')
        })
        .collect();
    let plain = plain.trim_end_matches(['.', ' ']);
    plain.eq_ignore_ascii_case(".git")
        || plain
            .get(..4)
            .filter(|head| head.eq_ignore_ascii_case("git~"))
            .is_some_and(|_| plain.len() > 4 && plain[4..].bytes().all(|b| b.is_ascii_digit()))
}

/// Whether Windows reads a component as a device, whatever its extension.
fn is_device_name(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let numbered = |prefix: &str| {
        stem.strip_prefix(prefix).is_some_and(|rest| {
            let mut chars = rest.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}'))
                && chars.next().is_none()
        })
    };
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered("COM")
        || numbered("LPT")
}

/// A name in the index that is a plain path in the working tree.
pub(crate) fn plain_path(name: &[u8], windows: bool) -> Result<&str, GitProviderError> {
    let path = std::str::from_utf8(name).map_err(|_| refused())?;
    if path.chars().any(|c| c == '\0') {
        return Err(refused());
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." || is_git_folder_name(part) {
            return Err(refused());
        }
        if windows
            && (part.contains(['\\', ':'])
                || part.ends_with(['.', ' '])
                || part.chars().any(|c| c.is_ascii_control())
                || is_device_name(part))
        {
            return Err(refused());
        }
    }
    Ok(path)
}

/// The folders the index has entries in.
pub(crate) struct IndexFolders {
    /// As the index names them.
    folders: BTreeSet<String>,
    /// Lowercase, for a file system that ignores case.
    folded: BTreeSet<String>,
    gitlinks: Vec<String>,
}

impl IndexFolders {
    /// Parses `ls-files --stage -z`: `<mode> <id> <stage>\t<name>\0`.
    pub(crate) fn parse(listing: &[u8]) -> Result<Self, GitProviderError> {
        let mut parsed = Self {
            folders: BTreeSet::new(),
            folded: BTreeSet::new(),
            gitlinks: Vec::new(),
        };
        let body = match listing {
            [] => return Ok(parsed),
            [body @ .., 0] => body,
            _ => return Err(refused()),
        };
        for entry in body.split(|byte| *byte == 0) {
            let tab = entry
                .iter()
                .position(|byte| *byte == b'\t')
                .ok_or_else(refused)?;
            let path = plain_path(&entry[tab + 1..], cfg!(windows))?;
            if entry.starts_with(b"160000 ") {
                parsed.gitlinks.push(path.to_owned());
            }
            for (at, _) in path.match_indices('/').rev() {
                // Every shorter folder is there already.
                if !parsed.folders.insert(path[..at].to_owned()) {
                    break;
                }
                parsed.folded.insert(path[..at].to_lowercase());
            }
        }
        Ok(parsed)
    }

    pub(crate) fn folders(&self) -> impl Iterator<Item = &String> {
        self.folders.iter()
    }

    pub(crate) fn gitlinks(&self) -> impl Iterator<Item = &String> {
        self.gitlinks.iter()
    }

    /// Which of `dirs` hold tracked entries, whatever their case.
    pub(crate) fn tracked(&self, dirs: &[String]) -> BTreeSet<String> {
        dirs.iter()
            .filter(|dir| self.folded.contains(&dir.to_lowercase()))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_judged_as_each_platform_reads_them() {
        for name in [
            "a.txt",
            "a/b.txt",
            "..a/b",
            "a..b/c",
            ".gitignore",
            "x/.github/y",
            "git~x",
            "é/ü",
        ] {
            assert!(plain_path(name.as_bytes(), true).is_ok(), "{name}");
        }
        for name in [
            "",
            "/a",
            "a/",
            "a//b",
            ".",
            "..",
            "a/..",
            "../a",
            ".git",
            ".GIT/x",
            "x/.git",
            "GIT~1",
            "x/git~12/y",
            ".git./x",
            ".git /x",
            ".g\u{200d}it/x",
        ] {
            assert!(plain_path(name.as_bytes(), false).is_err(), "{name:?}");
        }
        for name in [
            "C:/x",
            "C:x",
            "a:b",
            "a\\b",
            "a./b",
            "a /b",
            "nul",
            "x/NUL.txt",
            "com1",
            "LPT9.log",
            "aux .c",
            "a\u{1}b",
        ] {
            assert!(plain_path(name.as_bytes(), true).is_err(), "{name:?}");
            assert!(plain_path(name.as_bytes(), false).is_ok(), "{name:?}");
        }
        assert!(plain_path(b"a/\xff", false).is_err());
    }

    #[test]
    fn a_listing_gives_the_folders_it_has_entries_in() {
        let listing =
            b"100644 0 0\ta.txt\x00100644 0 0\tA/b/c.txt\x00160000 0 0\tsub\x00100644 0 0\tA/d\x00";
        let parsed = IndexFolders::parse(listing).expect("parses");
        assert_eq!(parsed.folders().collect::<Vec<_>>(), ["A", "A/b"]);
        assert_eq!(parsed.gitlinks().collect::<Vec<_>>(), ["sub"]);
        let asked = ["a".to_owned(), "a/B".to_owned(), "sub".to_owned()];
        assert_eq!(parsed.tracked(&asked).len(), 2);
        assert!(IndexFolders::parse(b"").is_ok());
        assert!(IndexFolders::parse(b"100644 0 0\ta.txt").is_err());
        assert!(IndexFolders::parse(b"a.txt\x00").is_err());
    }
}
