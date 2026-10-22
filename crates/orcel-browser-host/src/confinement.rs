//! SG-000108 worker-launch confinement (decision record:
//! `docs/security/SG-000108_ENGINE_ATTACHMENT_DECISION.md`).
//!
//! The worker launches the verified engine with exactly the argv built
//! here: the SG-000074 frozen flags, the Orcel-owned profile, and six
//! confinement flags whose values are either fixed or built by the host
//! from destinations that already passed `validate_navigation`. Admitted
//! names resolve only to their pinned public address on port 443; every
//! other name resolves to nothing; IP literals and unmapped names are sent
//! to a proxy address that cannot accept a connection on Windows; WebRTC is
//! limited to proxied transport and QUIC is off. The SG-000074 `build_argv`
//! path is unchanged and still refuses every flag added here.

use crate::argv::{ALLOWED_FLAGS, FORBIDDEN_FLAGS, INITIAL_URL};
use crate::discovery::EngineKind;
use crate::error::HostError;
use crate::navigation::{is_public_address, validate_navigation, DnsResolver, NavigationTarget};
use std::net::IpAddr;
use std::path::Path;

/// Destinations admitted into one engine lifetime. Widening the set is a
/// host-mediated relaunch, never an in-place change.
pub const MAX_ADMITTED_DESTINATIONS: usize = 16;

/// Maximum admitted hostname length (DNS limit).
const MAX_ADMITTED_HOST_BYTES: usize = 253;

const PIPE_FLAG: &str = "--remote-debugging-pipe";
const RESOLVER_FLAG: &str = "--host-resolver-rules";
const PROXY_FLAG: &str = "--proxy-server";
const BYPASS_FLAG: &str = "--proxy-bypass-list";
const WEBRTC_FLAG: &str = "--webrtc-ip-handling-policy";
const QUIC_FLAG: &str = "--disable-quic";
/// SharedWorker requests are never routed (measured), so the API is removed
/// from the engine (SG-000108 slice 3a amendment).
const SHARED_WORKER_FLAG: &str = "--disable-blink-features=SharedWorker";
/// #324: browser-process services that reach the network outside the
/// resolver and no-route layers. Media Router (Cast device sockets to LAN
/// addresses, mDNS discovery) and Edge's account integration (implicit
/// Windows-account sign-in, OneAuth/WAM, the Microsoft 365 "Substrate"
/// account info) were measured connecting to the LAN and to Microsoft 365
/// from a confined lifetime; none is needed by a headless automation
/// browser. WebRTC's mDNS responder (WebRtcHideLocalIpsWithMdns) bound
/// UDP 5353 on all interfaces and answers LAN queries: off as well (WebRTC
/// sends no non-proxied UDP under the policy flag above). The native
/// network-endpoint test verifies what the job holds and sends.
const DISABLED_FEATURES_FLAG: &str = "--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns";

/// The no-route proxy: connecting to 0.0.0.0 fails on Windows even when a
/// local process listens on port 9 (Windows-only; on Linux it is loopback).
const NO_ROUTE_PROXY: &str = "http://0.0.0.0:9";
/// The WebRTC policy proven to refuse UDP; the `--force-` spelling is
/// ignored by the engine and must not be used.
const WEBRTC_POLICY: &str = "disable_non_proxied_udp";
/// Every pin carries the SG-000075 port.
const PINNED_PORT: u16 = 443;

/// One destination admitted into an engine lifetime: a validated public
/// HTTPS name and the public address the host pinned for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedDestination {
    host: String,
    pin: IpAddr,
}

impl AdmittedDestination {
    /// Admit a destination: run the SG-000075 `validate_navigation` for the
    /// URL, which resolves the name and pins its lowest public address with
    /// `select_public_address`, then apply the stricter rule-string hygiene.
    /// This is the only public constructor, so every pin comes from the
    /// host's own resolution of that name.
    pub fn admit(url: &str, resolver: &impl DnsResolver) -> Result<Self, HostError> {
        // The name's hygiene first, so nothing malformed or local-only ever
        // reaches the system resolver (judge, PR #428).
        let parsed = crate::navigation::parse_navigation_url(url)?;
        validate_admitted_host(&parsed.host)?;
        refuse_local_namespace(&parsed.host)?;
        let (target, pin) = validate_navigation(url, resolver)?;
        Self::checked(&target, pin)
    }

    fn checked(target: &NavigationTarget, pin: IpAddr) -> Result<Self, HostError> {
        if target.scheme != "https" || target.port != PINNED_PORT {
            return Err(HostError::Invalid(
                "admitted destination must be https on port 443".into(),
            ));
        }
        validate_admitted_host(&target.host)?;
        if !is_public_address(&pin) {
            return Err(HostError::Invalid(
                "admitted destination pin is not a public address".into(),
            ));
        }
        Ok(Self {
            host: target.host.clone(),
            pin,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn pin(&self) -> IpAddr {
        self.pin
    }

    /// Test-only: pin a fixture name to a non-public (loopback) address.
    /// Compiled only into this crate's unit tests; release builds cannot
    /// construct a non-public pin.
    #[cfg(any(test, all(windows, feature = "live-browser-test")))]
    pub(crate) fn fixture(host: &str, pin: IpAddr) -> Result<Self, HostError> {
        validate_admitted_host(host)?;
        Ok(Self {
            host: host.to_owned(),
            pin,
        })
    }
}

/// Names that only a local network answers (mDNS, home networks, private
/// zones): a public destination is never one of them.
fn refuse_local_namespace(host: &str) -> Result<(), HostError> {
    const LOCAL: &[&str] = &[
        "local",
        "localhost",
        "internal",
        "home.arpa",
        "lan",
        "intranet",
        "corp",
    ];
    if LOCAL
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    {
        return Err(HostError::Invalid(
            "admitted host is in a local-only namespace".into(),
        ));
    }
    Ok(())
}

/// Hostname hygiene for rule and bypass strings: lowercase ASCII LDH, at
/// least two labels of 1..=63 bytes, at most 253 bytes, no label starting
/// or ending with a hyphen, and a last label that can never be parsed as
/// part of an IPv4 address (not all-numeric, not `0x`-prefixed). This rules
/// out wildcards, IP literals, and the `,` `;` and whitespace separators.
pub fn validate_admitted_host(host: &str) -> Result<(), HostError> {
    let invalid = |detail: &str| Err(HostError::Invalid(format!("admitted host {detail}")));
    if host.is_empty() || host.len() > MAX_ADMITTED_HOST_BYTES {
        return invalid("is empty or oversized");
    }
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
    }) {
        return invalid("must be lowercase ASCII letters, digits, hyphens and dots");
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return invalid("requires at least two labels");
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return invalid("has an empty or oversized label");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return invalid("has a label starting or ending with a hyphen");
        }
    }
    let last = labels[labels.len() - 1];
    if last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x") {
        return invalid("has a numeric last label");
    }
    Ok(())
}

fn checked_destinations(destinations: &[AdmittedDestination]) -> Result<(), HostError> {
    if destinations.is_empty() {
        return Err(HostError::Invalid(
            "worker launch requires at least one admitted destination".into(),
        ));
    }
    if destinations.len() > MAX_ADMITTED_DESTINATIONS {
        return Err(HostError::Invalid(
            "too many admitted destinations for one engine lifetime".into(),
        ));
    }
    for (index, destination) in destinations.iter().enumerate() {
        // Re-check here as well: the fields are private, but the strings
        // below are security-critical and must never carry a separator.
        validate_admitted_host(&destination.host)?;
        if destinations[..index]
            .iter()
            .any(|earlier| earlier.host == destination.host)
        {
            return Err(HostError::Invalid(
                "admitted destinations contain a duplicate host".into(),
            ));
        }
    }
    Ok(())
}

/// `MAP <name> <pin>:443, …, MAP * ~NOTFOUND`.
pub fn resolver_rules(destinations: &[AdmittedDestination]) -> Result<String, HostError> {
    checked_destinations(destinations)?;
    let mut rules: Vec<String> = destinations
        .iter()
        .map(|destination| match destination.pin {
            IpAddr::V4(address) => format!("MAP {} {address}:{PINNED_PORT}", destination.host),
            IpAddr::V6(address) => format!("MAP {} [{address}]:{PINNED_PORT}", destination.host),
        })
        .collect();
    rules.push("MAP * ~NOTFOUND".into());
    Ok(rules.join(", "))
}

/// `<name>;…;<-loopback>`: only admitted names bypass the no-route proxy,
/// and the engine's implicit loopback bypass is removed.
pub fn proxy_bypass_list(destinations: &[AdmittedDestination]) -> Result<String, HostError> {
    checked_destinations(destinations)?;
    let mut entries: Vec<&str> = destinations.iter().map(|d| d.host.as_str()).collect();
    entries.push("<-loopback>");
    Ok(entries.join(";"))
}

/// Build the exact worker-launch argv: the SG-000074 frozen flags, the
/// profile, the eight confinement flags, and the blank initial page.
pub fn build_worker_argv(
    profile_dir: &Path,
    destinations: &[AdmittedDestination],
) -> Result<Vec<String>, HostError> {
    let profile = profile_dir
        .to_str()
        .ok_or_else(|| HostError::Invalid("profile directory is not UTF-8".into()))?;
    if profile.is_empty() {
        return Err(HostError::Invalid("profile directory is empty".into()));
    }
    let mut argv: Vec<String> = ALLOWED_FLAGS.iter().map(|flag| flag.to_string()).collect();
    argv.push(format!("--user-data-dir={profile}"));
    argv.push(PIPE_FLAG.into());
    argv.push(format!("{RESOLVER_FLAG}={}", resolver_rules(destinations)?));
    argv.push(format!("{PROXY_FLAG}={NO_ROUTE_PROXY}"));
    argv.push(format!(
        "{BYPASS_FLAG}={}",
        proxy_bypass_list(destinations)?
    ));
    argv.push(format!("{WEBRTC_FLAG}={WEBRTC_POLICY}"));
    argv.push(QUIC_FLAG.into());
    argv.push(SHARED_WORKER_FLAG.into());
    argv.push(DISABLED_FEATURES_FLAG.into());
    argv.push(INITIAL_URL.into());
    Ok(argv)
}

/// Accept a worker argv only if it equals, element for element, the argv
/// the host builds for this profile and destination set. Any added,
/// missing, reordered, or re-valued flag fails closed, and no forbidden
/// flag can appear in any form.
pub fn assert_worker_argv_exact(
    argv: &[String],
    profile_dir: &Path,
    destinations: &[AdmittedDestination],
) -> Result<(), HostError> {
    // The exact comparison below already refuses these; this pass only
    // names the forbidden flag in the error.
    for arg in argv {
        let flag = arg.split('=').next().unwrap_or(arg);
        if FORBIDDEN_FLAGS.contains(&flag) {
            return Err(HostError::Invalid(format!("forbidden engine flag: {flag}")));
        }
    }
    let expected = build_worker_argv(profile_dir, destinations)?;
    if argv != expected.as_slice() {
        return Err(HostError::Invalid(
            "worker argv differs from the host-built argv".into(),
        ));
    }
    Ok(())
}

/// What a managed-policy registry key holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKeyState {
    Absent,
    Empty,
    Populated,
    Unreadable,
}

/// The registry hive of a mandatory policy key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyHive {
    LocalMachine,
    CurrentUser,
}

/// Read-only source of policy key states (the registry in production).
pub trait PolicySource {
    fn key_state(&self, hive: PolicyHive, subkey: &str) -> PolicyKeyState;
}

/// Mandatory policy keys for an engine family. A `Recommended` subkey sits
/// under the same key and is therefore refused as well.
pub fn policy_keys(kind: EngineKind) -> &'static [&'static str] {
    match kind {
        EngineKind::Edge => &["SOFTWARE\\Policies\\Microsoft\\Edge"],
        // Google Chrome reads Google\Chrome; Chromium builds read Chromium.
        EngineKind::Chromium => &[
            "SOFTWARE\\Policies\\Google\\Chrome",
            "SOFTWARE\\Policies\\Chromium",
        ],
    }
}

/// Launch precondition: refuse when any mandatory browser policy value or
/// subkey is present in either hive, because managed policy outranks the
/// confinement flags. An unreadable key fails closed.
pub fn assert_no_managed_policy(
    kind: EngineKind,
    source: &impl PolicySource,
) -> Result<(), HostError> {
    for subkey in policy_keys(kind) {
        for hive in [PolicyHive::LocalMachine, PolicyHive::CurrentUser] {
            match source.key_state(hive, subkey) {
                PolicyKeyState::Absent | PolicyKeyState::Empty => {}
                PolicyKeyState::Populated => {
                    return Err(HostError::Invalid(format!(
                        "managed browser policy is present ({hive:?}\\{subkey}); launch refused"
                    )))
                }
                PolicyKeyState::Unreadable => {
                    return Err(HostError::Platform(format!(
                        "managed browser policy cannot be read ({hive:?}\\{subkey}); launch refused"
                    )))
                }
            }
        }
    }
    Ok(())
}

/// Combine the 64-bit and 32-bit registry views of one key: a populated
/// or unreadable view decides (first one wins), otherwise any empty view
/// makes the key empty, otherwise it is absent.
#[cfg(any(windows, test))]
fn merge_views(views: &[PolicyKeyState]) -> PolicyKeyState {
    let mut state = PolicyKeyState::Absent;
    for view in views {
        match view {
            PolicyKeyState::Absent => {}
            PolicyKeyState::Empty => state = PolicyKeyState::Empty,
            decisive => return *decisive,
        }
    }
    state
}

/// The production registry policy source: both registry views of each key
/// are read with `KEY_READ` only; nothing is written or changed.
#[derive(Debug, Default, Clone, Copy)]
pub struct RegistryPolicySource;

impl PolicySource for RegistryPolicySource {
    fn key_state(&self, hive: PolicyHive, subkey: &str) -> PolicyKeyState {
        registry::key_state(hive, subkey)
    }
}

#[cfg(windows)]
mod registry {
    use super::{merge_views, PolicyHive, PolicyKeyState};
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryInfoKeyW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
        KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };

    pub(super) fn key_state(hive: PolicyHive, subkey: &str) -> PolicyKeyState {
        let root = match hive {
            PolicyHive::LocalMachine => HKEY_LOCAL_MACHINE,
            PolicyHive::CurrentUser => HKEY_CURRENT_USER,
        };
        merge_views(&[
            view_state(root, subkey, KEY_WOW64_64KEY),
            view_state(root, subkey, KEY_WOW64_32KEY),
        ])
    }

    fn view_state(root: HKEY, subkey: &str, view: u32) -> PolicyKeyState {
        let wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
        let mut key: HKEY = 0;
        // SAFETY: `wide` is NUL-terminated and outlives the call; `key`
        // receives the opened handle, closed below on every path.
        let status = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ | view, &mut key) };
        if status == ERROR_FILE_NOT_FOUND {
            return PolicyKeyState::Absent;
        }
        if status != ERROR_SUCCESS {
            return PolicyKeyState::Unreadable;
        }
        let mut subkeys: u32 = 0;
        let mut values: u32 = 0;
        // SAFETY: `key` is open; only the two counts are requested and every
        // other out-parameter is null, which the API permits.
        let status = unsafe {
            RegQueryInfoKeyW(
                key,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut values,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // SAFETY: `key` was opened above and is closed exactly once.
        unsafe { RegCloseKey(key) };
        if status != ERROR_SUCCESS {
            return PolicyKeyState::Unreadable;
        }
        if subkeys == 0 && values == 0 {
            PolicyKeyState::Empty
        } else {
            PolicyKeyState::Populated
        }
    }
}

#[cfg(not(windows))]
mod registry {
    use super::{PolicyHive, PolicyKeyState};

    /// The confinement design is Windows-only; elsewhere the precondition
    /// cannot be established and fails closed.
    pub(super) fn key_state(_hive: PolicyHive, _subkey: &str) -> PolicyKeyState {
        PolicyKeyState::Unreadable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigation::parse_navigation_url;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    /// Index of the first confinement flag: the frozen flags, then the profile.
    const FIRST_CONFINEMENT: usize = ALLOWED_FLAGS.len() + 1;

    struct FakeDns(Vec<IpAddr>);

    impl DnsResolver for FakeDns {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
            Ok(self.0.clone())
        }
    }

    /// A resolver that records every name it was asked for.
    struct RecordingDns(std::cell::RefCell<Vec<String>>);

    impl DnsResolver for RecordingDns {
        fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
            self.0.borrow_mut().push(host.to_owned());
            Ok(vec!["93.184.215.14".parse().unwrap()])
        }
    }

    /// Judge, PR #428: a name's hygiene is checked before it is resolved,
    /// and local-only namespaces are never admitted or even looked up.
    #[test]
    fn names_are_checked_before_they_reach_the_resolver() {
        let dns = RecordingDns(std::cell::RefCell::new(Vec::new()));
        for url in [
            "https://printer.local/",
            "https://router.home.arpa/",
            "https://metadata.internal/",
            "https://nas.lan/",
            "https://wiki.corp/",
            "https://localhost/",
            "https://a.localhost/",
            "https://exa_mple.com/",
        ] {
            assert!(AdmittedDestination::admit(url, &dns).is_err(), "{url}");
        }
        assert!(dns.0.borrow().is_empty(), "resolved: {:?}", dns.0.borrow());
        assert!(AdmittedDestination::admit("https://example.com/", &dns).is_ok());
        assert_eq!(dns.0.borrow().as_slice(), ["example.com"]);
    }

    fn admitted(url: &str, pin: IpAddr) -> AdmittedDestination {
        AdmittedDestination::admit(url, &FakeDns(vec![pin])).unwrap()
    }

    fn public_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))
    }

    fn public_v6() -> IpAddr {
        "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap()
    }

    fn profile() -> PathBuf {
        PathBuf::from("C:\\orcel\\profile")
    }

    #[test]
    fn worker_argv_is_exact() {
        let destinations = vec![
            admitted("https://example.com/", public_v4()),
            admitted("https://docs.example.org/", public_v6()),
        ];
        let argv = build_worker_argv(&profile(), &destinations).unwrap();
        let expected: Vec<String> = [
            "--headless",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--no-service-autorun",
            "--user-data-dir=C:\\orcel\\profile",
            "--remote-debugging-pipe",
            "--host-resolver-rules=MAP example.com 93.184.215.14:443, MAP docs.example.org [2606:2800:21f:cb07:6820:80da:af6b:8b2c]:443, MAP * ~NOTFOUND",
            "--proxy-server=http://0.0.0.0:9",
            "--proxy-bypass-list=example.com;docs.example.org;<-loopback>",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--disable-quic",
            "--disable-blink-features=SharedWorker",
            "--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns",
            "about:blank",
        ]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
        assert_eq!(argv, expected);
        assert_worker_argv_exact(&argv, &profile(), &destinations).unwrap();
    }

    #[test]
    fn legacy_sg000074_argv_still_refuses_every_confinement_flag() {
        let destinations = vec![admitted("https://example.com/", public_v4())];
        let argv = build_worker_argv(&profile(), &destinations).unwrap();
        for arg in &argv[FIRST_CONFINEMENT..argv.len() - 1] {
            let legacy = vec![
                "--headless".to_string(),
                "--user-data-dir=C:\\orcel\\profile".to_string(),
                arg.clone(),
            ];
            assert!(crate::argv::assert_argv_clean(&legacy).is_err(), "{arg}");
        }
    }

    #[test]
    fn any_deviation_from_the_host_built_argv_is_refused() {
        let destinations = vec![admitted("https://example.com/", public_v4())];
        let good = build_worker_argv(&profile(), &destinations).unwrap();
        let mut cases: Vec<Vec<String>> = Vec::new();
        // Each confinement flag removed, value-stripped, or re-valued.
        for index in FIRST_CONFINEMENT..good.len() - 1 {
            let mut removed = good.clone();
            removed.remove(index);
            cases.push(removed);
            let mut bare = good.clone();
            bare[index] = good[index].split('=').next().unwrap().to_string();
            if bare[index] != good[index] {
                cases.push(bare);
            }
        }
        let revalued = [
            "--proxy-server=http://127.0.0.1:9",
            "--proxy-bypass-list=example.com;evil.example;<-loopback>",
            "--proxy-bypass-list=*",
            "--webrtc-ip-handling-policy=default",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--host-resolver-rules=MAP * ~NOTFOUND",
            "--host-resolver-rules=MAP example.com 93.184.215.14:443, MAP evil.example 10.0.0.1:443, MAP * ~NOTFOUND",
        ];
        for value in revalued {
            let flag = value.split('=').next().unwrap();
            let mut changed = good.clone();
            if let Some(slot) = changed.iter_mut().find(|arg| arg.starts_with(flag)) {
                *slot = value.to_string();
            } else {
                changed.insert(9, value.to_string());
            }
            cases.push(changed);
        }
        // Additions, including every forbidden flag, and a reorder.
        for extra in FORBIDDEN_FLAGS.iter().map(|flag| flag.to_string()).chain([
            "--remote-debugging-port=9222".to_string(),
            "--evil".to_string(),
        ]) {
            let mut added = good.clone();
            added.insert(9, extra);
            cases.push(added);
        }
        let mut reordered = good.clone();
        reordered.swap(9, 10);
        cases.push(reordered);
        let mut other_profile = good.clone();
        other_profile[FIRST_CONFINEMENT - 1] =
            "--user-data-dir=C:\\Users\\me\\AppData\\Local\\Microsoft\\Edge\\User Data".into();
        cases.push(other_profile);
        for case in &cases {
            assert!(
                assert_worker_argv_exact(case, &profile(), &destinations).is_err(),
                "{case:?}"
            );
        }
        assert!(cases.len() > 20);
    }

    #[test]
    fn hostname_hygiene_refuses_separators_wildcards_and_numeric_names() {
        for host in [
            "example.com",
            "a.b.example.org",
            "xn--bcher-kva.example",
            "a-1.example.net",
        ] {
            validate_admitted_host(host).unwrap();
        }
        for host in [
            "",
            "localhost",
            "Example.com",
            "*.example.com",
            "example.com,evil.example",
            "example.com;evil.example",
            "example.com evil.example",
            "example.com\tx",
            "exa_mple.com",
            "-a.example.com",
            "a-.example.com",
            "a..example.com",
            ".example.com",
            "example.com.",
            "10.0.0.1",
            "a.0x7f",
            "a.123",
            "127.1",
            "~notfound.example",
            "a=b.example",
            "<-loopback>",
            "[::1]",
        ] {
            assert!(validate_admitted_host(host).is_err(), "{host}");
        }
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(validate_admitted_host(&long_label).is_err());
        let long_name = format!("{}.example", "a.".repeat(124));
        assert!(validate_admitted_host(&long_name).is_err());
    }

    #[test]
    fn only_validated_public_destinations_are_admitted() {
        let target = parse_navigation_url("https://example.com/").unwrap();
        for pin in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "fd00:ec2::254".parse().unwrap(),
            "::ffff:127.0.0.1".parse().unwrap(),
        ] {
            assert!(AdmittedDestination::checked(&target, pin).is_err(), "{pin}");
        }
        let literal = parse_navigation_url("https://93.184.215.14/").unwrap();
        assert!(AdmittedDestination::checked(&literal, public_v4()).is_err());
        let mut other_port = target.clone();
        other_port.port = 8443;
        assert!(AdmittedDestination::checked(&other_port, public_v4()).is_err());
        let mut plain = target;
        plain.scheme = "http".into();
        assert!(AdmittedDestination::checked(&plain, public_v4()).is_err());
    }

    #[test]
    fn destination_sets_are_bounded_and_unique() {
        assert!(build_worker_argv(&profile(), &[]).is_err());
        let one = admitted("https://example.com/", public_v4());
        assert!(build_worker_argv(&profile(), &[one.clone(), one]).is_err());
        let many: Vec<AdmittedDestination> = (0..=MAX_ADMITTED_DESTINATIONS)
            .map(|index| admitted(&format!("https://h{index}.example.com/"), public_v4()))
            .collect();
        assert!(build_worker_argv(&profile(), &many).is_err());
        assert!(build_worker_argv(&profile(), &many[..MAX_ADMITTED_DESTINATIONS]).is_ok());
    }

    #[test]
    fn fixture_pins_exist_only_in_tests_and_keep_hygiene() {
        let fixture =
            AdmittedDestination::fixture("fixture.test", IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        assert_eq!(
            resolver_rules(&[fixture]).unwrap(),
            "MAP fixture.test 127.0.0.1:443, MAP * ~NOTFOUND"
        );
        assert!(
            AdmittedDestination::fixture("127.0.0.1", IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err()
        );
    }

    #[test]
    fn admission_pins_the_lowest_public_address_of_the_name_itself() {
        let mixed = FakeDns(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c".parse().unwrap(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ]);
        let destination = AdmittedDestination::admit("https://example.com/", &mixed).unwrap();
        assert_eq!(
            destination.pin(),
            crate::navigation::select_public_address(&mixed.0).unwrap()
        );
        assert!(is_public_address(&destination.pin()));
        for (url, dns) in [
            (
                "https://example.com/",
                FakeDns(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            ),
            ("https://example.com/", FakeDns(vec![])),
            ("http://example.com/", FakeDns(vec![public_v4()])),
            ("https://example.com:8443/", FakeDns(vec![public_v4()])),
            ("https://169.254.169.254/", FakeDns(vec![public_v4()])),
            ("https://93.184.215.14/", FakeDns(vec![public_v4()])),
        ] {
            assert!(AdmittedDestination::admit(url, &dns).is_err(), "{url}");
        }
        // The SG-000075 parser normalizes case; the rule string is lowercase.
        let upper = AdmittedDestination::admit("https://Example.COM/", &FakeDns(vec![public_v4()]))
            .unwrap();
        assert_eq!(upper.host(), "example.com");
    }

    #[test]
    fn mapped_public_ipv6_pins_are_bracketed() {
        let mapped: IpAddr = "::ffff:93.184.215.14".parse().unwrap();
        if is_public_address(&mapped) {
            let rules = resolver_rules(&[admitted("https://example.com/", mapped)]).unwrap();
            assert_eq!(
                rules,
                "MAP example.com [::ffff:93.184.215.14]:443, MAP * ~NOTFOUND"
            );
        } else {
            assert!(
                AdmittedDestination::admit("https://example.com/", &FakeDns(vec![mapped])).is_err()
            );
        }
    }

    #[test]
    fn registry_views_merge_fail_closed() {
        use PolicyKeyState::*;
        assert_eq!(merge_views(&[Absent, Absent]), Absent);
        assert_eq!(merge_views(&[Empty, Absent]), Empty);
        assert_eq!(merge_views(&[Absent, Empty]), Empty);
        for decisive in [Populated, Unreadable] {
            for other in [Absent, Empty, Populated, Unreadable] {
                assert_ne!(merge_views(&[decisive, other]), Absent);
                assert_ne!(merge_views(&[decisive, other]), Empty);
                assert_ne!(merge_views(&[other, decisive]), Absent);
                assert_ne!(merge_views(&[other, decisive]), Empty);
            }
        }
    }

    struct FakePolicy(Vec<(PolicyHive, &'static str, PolicyKeyState)>);

    impl PolicySource for FakePolicy {
        fn key_state(&self, hive: PolicyHive, subkey: &str) -> PolicyKeyState {
            self.0
                .iter()
                .find(|(h, k, _)| *h == hive && *k == subkey)
                .map(|(_, _, state)| *state)
                .unwrap_or(PolicyKeyState::Absent)
        }
    }

    #[test]
    fn any_mandatory_policy_refuses_launch() {
        let edge = "SOFTWARE\\Policies\\Microsoft\\Edge";
        let chrome = "SOFTWARE\\Policies\\Google\\Chrome";
        assert!(assert_no_managed_policy(EngineKind::Edge, &FakePolicy(vec![])).is_ok());
        assert!(assert_no_managed_policy(
            EngineKind::Edge,
            &FakePolicy(vec![(
                PolicyHive::LocalMachine,
                edge,
                PolicyKeyState::Empty
            )])
        )
        .is_ok());
        for hive in [PolicyHive::LocalMachine, PolicyHive::CurrentUser] {
            for state in [PolicyKeyState::Populated, PolicyKeyState::Unreadable] {
                assert!(assert_no_managed_policy(
                    EngineKind::Edge,
                    &FakePolicy(vec![(hive, edge, state)])
                )
                .is_err());
                assert!(assert_no_managed_policy(
                    EngineKind::Chromium,
                    &FakePolicy(vec![(hive, chrome, state)])
                )
                .is_err());
            }
        }
        for hive in [PolicyHive::LocalMachine, PolicyHive::CurrentUser] {
            assert!(assert_no_managed_policy(
                EngineKind::Chromium,
                &FakePolicy(vec![(
                    hive,
                    "SOFTWARE\\Policies\\Chromium",
                    PolicyKeyState::Populated
                )])
            )
            .is_err());
        }
        // A Chrome policy does not bind Edge, and vice versa.
        assert!(assert_no_managed_policy(
            EngineKind::Edge,
            &FakePolicy(vec![(
                PolicyHive::LocalMachine,
                chrome,
                PolicyKeyState::Populated
            )])
        )
        .is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn registry_policy_source_reads_a_real_key_without_failing_open() {
        // A key that exists on every Windows install with values: it must
        // read as populated, proving the reader does not report absence
        // for a key it can open.
        let state = RegistryPolicySource.key_state(
            PolicyHive::LocalMachine,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        );
        assert_eq!(state, PolicyKeyState::Populated);
        let absent = RegistryPolicySource.key_state(
            PolicyHive::CurrentUser,
            "SOFTWARE\\Policies\\Orcel\\SG000108\\DefinitelyAbsent",
        );
        assert_eq!(absent, PolicyKeyState::Absent);
    }

    #[cfg(not(windows))]
    #[test]
    fn policy_precondition_fails_closed_off_windows() {
        assert!(assert_no_managed_policy(EngineKind::Edge, &RegistryPolicySource).is_err());
    }
}
