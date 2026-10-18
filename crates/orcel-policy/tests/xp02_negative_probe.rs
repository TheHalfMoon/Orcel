//! XP-02 negative probe: a Windows-only assumption with no cfg gate.
//! It must fail on the macOS leg. It is reverted in the next commit.

#[test]
fn xp02_ungated_windows_only_assumption() {
    assert!(std::path::Path::new(r"C:\Windows\System32").is_dir());
}
