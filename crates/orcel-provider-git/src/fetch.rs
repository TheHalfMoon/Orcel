use super::{GitProvider, GitProviderError};
use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::Path;

pub const FETCH_NAMESPACE: &str = "refs/remotes/orcel";
pub const PRIOR_ABSENT: &str = "ABSENT";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitFetchDestination {
    pub id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchPreview {
    pub repository_root: String,
    pub head: String,
    pub branch: String,
    pub policy_id: String,
    pub canonical_url: String,
    pub hostname: String,
    pub port: u16,
    pub source_ref: String,
    pub destination_ref: String,
    pub prior: String,
}

impl FetchPreview {
    pub fn to_json(&self) -> Value {
        json!({
            "repository_root": self.repository_root,
            "head": self.head,
            "branch": self.branch,
            "policy_id": self.policy_id,
            "canonical_url": self.canonical_url,
            "hostname": self.hostname,
            "port": self.port,
            "source_ref": self.source_ref,
            "destination_ref": self.destination_ref,
            "prior": self.prior,
        })
    }
}

pub trait DnsResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, GitProviderError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, GitProviderError> {
        let mut addresses = Vec::new();
        let candidates = (hostname, 443)
            .to_socket_addrs()
            .map_err(|error| provider_error(format!("resolve destination hostname: {error}")))?;
        for candidate in candidates {
            let address = candidate.ip();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(provider_error(
                "destination hostname resolved to no addresses",
            ));
        }
        addresses.sort_by_key(|address| address.to_string());
        Ok(addresses)
    }
}

pub fn parse_destination(id: &str, url: &str) -> Result<GitFetchDestination, GitProviderError> {
    let policy_id = validate_policy_id(id)?;
    let (hostname, port, canonical) = validate_canonical_https_url(url)?;
    Ok(GitFetchDestination {
        id: policy_id,
        canonical_url: canonical,
        hostname,
        port,
    })
}

pub fn validate_policy_id(id: &str) -> Result<String, GitProviderError> {
    if id.is_empty() || id.len() > 64 {
        return Err(invalid(
            "Git destination policy id must contain 1..=64 characters",
        ));
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit() {
        return Err(invalid(
            "Git destination policy id must start with a lowercase letter or digit",
        ));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(invalid(
            "Git destination policy id must use only lowercase letters, digits, and hyphen",
        ));
    }
    if id.starts_with('-') || id.ends_with('-') || id.contains("--") {
        return Err(invalid(
            "Git destination policy id has an unsafe hyphen placement",
        ));
    }
    Ok(id.to_owned())
}

pub fn validate_branch(branch: &str) -> Result<String, GitProviderError> {
    if branch.is_empty() || branch.len() > 255 {
        return Err(invalid("Git fetch branch is empty or too large"));
    }
    if branch == "refs" || branch.starts_with("refs/") {
        return Err(invalid(
            "Git fetch branch must be a short name, not a full ref",
        ));
    }
    if branch.bytes().any(|byte| {
        matches!(
            byte,
            0 | b'\n' | b'\r' | b'\t' | b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\'
        )
    }) {
        return Err(invalid("Git fetch branch contains unsafe characters"));
    }
    if branch.starts_with('-') || branch.starts_with('/') || branch.starts_with('.') {
        return Err(invalid("Git fetch branch has an unsafe leading component"));
    }
    if branch.ends_with('/') || branch.ends_with('.') || branch.ends_with(".lock") {
        return Err(invalid("Git fetch branch has an unsafe trailing component"));
    }
    if branch.contains("//") || branch.contains("/.") || branch.contains(".lock/") {
        return Err(invalid("Git fetch branch contains an unsafe path sequence"));
    }
    for component in branch.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(
                "Git fetch branch contains an empty or dot component",
            ));
        }
        if component.starts_with('.') || component.ends_with(".lock") {
            return Err(invalid("Git fetch branch component is unsafe"));
        }
        if component == "@" {
            return Err(invalid("Git fetch branch component is unsafe"));
        }
    }
    if branch.contains("..") || branch.contains("@{") {
        return Err(invalid("Git fetch branch contains an unsafe sequence"));
    }
    Ok(branch.to_owned())
}

pub fn source_ref(branch: &str) -> String {
    format!("refs/heads/{branch}")
}

pub fn destination_ref(policy_id: &str, branch: &str) -> String {
    format!("{FETCH_NAMESPACE}/{policy_id}/{branch}")
}

pub fn validate_canonical_https_url(url: &str) -> Result<(String, u16, String), GitProviderError> {
    if url.is_empty() || url.len() > 2048 {
        return Err(invalid("Git destination URL is empty or too large"));
    }
    if url.contains('\0')
        || url.contains('\n')
        || url.contains('\r')
        || url.contains('\t')
        || url.contains(' ')
    {
        return Err(invalid(
            "Git destination URL contains unsafe whitespace or control data",
        ));
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("https://") {
        return Err(invalid("Git destination URL must use the https scheme"));
    }
    let rest = &url["https://".len()..];
    if rest.is_empty() {
        return Err(invalid("Git destination URL is missing a hostname"));
    }
    if rest.contains('@') {
        return Err(invalid("Git destination URL must not contain userinfo"));
    }
    if rest.contains('?') {
        return Err(invalid("Git destination URL must not contain a query"));
    }
    if rest.contains('#') {
        return Err(invalid("Git destination URL must not contain a fragment"));
    }
    if rest.contains('\\') {
        return Err(invalid("Git destination URL must not contain a backslash"));
    }
    let authority_and_path = rest;
    let (authority, path) = match authority_and_path.find('/') {
        Some(index) => (&authority_and_path[..index], &authority_and_path[index..]),
        None => (authority_and_path, "/"),
    };
    if authority.is_empty() {
        return Err(invalid("Git destination URL is missing a hostname"));
    }
    if path.is_empty() || !path.starts_with('/') {
        return Err(invalid("Git destination URL path is invalid"));
    }
    if path.contains("/..") || path.contains("/./") || path.ends_with("/.") {
        return Err(invalid(
            "Git destination URL path contains an unsafe sequence",
        ));
    }
    let (hostname_part, port) = match authority.rfind(':') {
        Some(index) => {
            let host = &authority[..index];
            let port_text = &authority[index + 1..];
            if port_text.is_empty() {
                return Err(invalid("Git destination URL has an empty port"));
            }
            if !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("Git destination URL port must be numeric"));
            }
            let port: u16 = port_text
                .parse()
                .map_err(|_| invalid("Git destination URL port is invalid"))?;
            if port != 443 {
                return Err(invalid(
                    "Git destination URL must use implicit or explicit port 443 only",
                ));
            }
            (host, port)
        }
        None => (authority, 443u16),
    };
    if hostname_part.is_empty() || hostname_part.len() > 253 {
        return Err(invalid("Git destination hostname is empty or too large"));
    }
    if hostname_part.contains(':') {
        return Err(invalid(
            "Git destination hostname must be a DNS hostname, not a literal address",
        ));
    }
    validate_dns_hostname(hostname_part)?;
    if looks_like_scp_syntax(url) {
        return Err(invalid("Git destination URL must not use SCP-style syntax"));
    }
    let hostname_lower = hostname_part.to_ascii_lowercase();
    let canonical = if port == 443 && !authority.contains(':') {
        format!("https://{hostname_lower}{path}")
    } else {
        format!("https://{hostname_lower}:443{path}")
    };
    if !canonical.ends_with(".git") && !path.contains('/') {
        return Err(invalid("Git destination URL path is invalid"));
    }
    Ok((hostname_lower, 443u16, canonical))
}

fn looks_like_scp_syntax(url: &str) -> bool {
    if let Some(without_scheme) = url.strip_prefix("https://") {
        if without_scheme.contains(':') {
            let after_host = without_scheme.find('/').unwrap_or(without_scheme.len());
            let authority = &without_scheme[..after_host];
            if authority.matches(':').count() > 1 {
                return true;
            }
        }
        return false;
    }
    true
}

fn validate_dns_hostname(hostname: &str) -> Result<(), GitProviderError> {
    if hostname.len() > 253 {
        return Err(invalid("Git destination hostname is too large"));
    }
    if hostname.starts_with('-')
        || hostname.starts_with('.')
        || hostname.ends_with('-')
        || hostname.ends_with('.')
    {
        return Err(invalid(
            "Git destination hostname has an unsafe leading or trailing character",
        ));
    }
    if hostname.contains("..") {
        return Err(invalid("Git destination hostname contains an empty label"));
    }
    let has_dot = hostname.contains('.');
    let mut has_alpha = false;
    for label in hostname.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(invalid(
                "Git destination hostname label is empty or too large",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid(
                "Git destination hostname label has an unsafe hyphen",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid(
                "Git destination hostname label uses unsafe characters",
            ));
        }
        has_alpha = has_alpha || label.bytes().any(|byte| byte.is_ascii_alphabetic());
    }
    if !has_dot {
        return Err(invalid(
            "Git destination hostname must be a dotted DNS hostname",
        ));
    }
    if !has_alpha {
        return Err(invalid(
            "Git destination hostname must contain at least one letter",
        ));
    }
    if hostname.parse::<IpAddr>().is_ok() {
        return Err(invalid(
            "Git destination hostname must be a DNS hostname, not a literal address",
        ));
    }
    Ok(())
}

pub fn validate_expected_head(value: &str) -> Result<(), GitProviderError> {
    if value.len() != 40
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "Git fetch expected_head must be an exact lowercase 40-hex object id",
        ));
    }
    Ok(())
}

pub fn validate_expected_prior(value: &str) -> Result<(), GitProviderError> {
    if value == PRIOR_ABSENT {
        return Ok(());
    }
    validate_expected_head(value).map_err(|_| {
        invalid("Git fetch expected_prior must be a lowercase 40-hex object id or ABSENT")
    })
}

pub fn is_public_address(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => is_public_ipv6(value),
    }
}

fn is_public_ipv4(value: &Ipv4Addr) -> bool {
    let octets = value.octets();
    if value.is_loopback()
        || value.is_unspecified()
        || value.is_multicast()
        || value.is_link_local()
        || value.is_private()
    {
        return false;
    }
    if value.is_broadcast() || value.is_documentation() {
        return false;
    }
    if octets[0] == 0 {
        return false;
    }
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
        return false;
    }
    if octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2) {
        return false;
    }
    if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
        return false;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return false;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return false;
    }
    if octets[0] >= 240 {
        return false;
    }
    true
}

fn is_public_ipv6(value: &Ipv6Addr) -> bool {
    if value.is_loopback() || value.is_unspecified() || value.is_multicast() {
        return false;
    }
    let segments = value.segments();
    if (segments[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if (segments[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0002 {
        return false;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0001 {
        return false;
    }
    if segments[0] == 0x2002 {
        return false;
    }
    if segments[0] == 0x0064 && (segments[1] & 0xffc0) == 0xff00 {
        return false;
    }
    if value.octets()[0] == 0 && value.octets()[1] == 0 {
        return false;
    }
    if let Some(mapped) = value.to_ipv4_mapped() {
        return is_public_ipv4(&mapped);
    }
    if value.to_ipv4().is_some() {
        return false;
    }
    true
}

pub fn select_pinned_address(addresses: &[IpAddr]) -> Result<IpAddr, GitProviderError> {
    if addresses.is_empty() {
        return Err(provider_error(
            "destination hostname resolved to no addresses",
        ));
    }
    let mut public: Vec<IpAddr> = addresses
        .iter()
        .copied()
        .filter(is_public_address)
        .collect();
    if public.is_empty() {
        return Err(GitProviderError::new(
            FailureCode::CapabilityDenied,
            "destination resolved only to non-public addresses; fetch is denied",
        ));
    }
    public.sort_by_key(|address| address.to_string());
    public.dedup();
    Ok(public[0])
}

#[derive(Debug, Clone, Copy)]
pub struct ApprovedFetch<'a> {
    pub relative: &'a str,
    pub destination: &'a GitFetchDestination,
    pub policy_id: &'a str,
    pub branch: &'a str,
    pub expected_head: &'a str,
    pub expected_prior: &'a str,
    pub pinned: &'a IpAddr,
}

impl GitProvider {
    pub fn fetch_preview(
        &self,
        relative: &str,
        policy_id: &str,
        branch: &str,
        destination: &GitFetchDestination,
    ) -> Result<FetchPreview, GitProviderError> {
        let validated_policy = validate_policy_id(policy_id)?;
        if validated_policy != destination.id {
            return Err(invalid(
                "Git fetch preview policy id does not match the configured destination",
            ));
        }
        let validated_branch = validate_branch(branch)?;
        let repo = self.repository_root(relative)?;
        let head = self.preview_head(&repo)?;
        let current_branch = self.preview_branch(&repo)?;
        let _ = current_branch;
        let source = source_ref(&validated_branch);
        let dest = destination_ref(&validated_policy, &validated_branch);
        let prior = self.destination_prior(&repo, &dest)?;
        Ok(FetchPreview {
            repository_root: self.relative_display(&repo),
            head,
            branch: validated_branch,
            policy_id: validated_policy,
            canonical_url: destination.canonical_url.clone(),
            hostname: destination.hostname.clone(),
            port: destination.port,
            source_ref: source,
            destination_ref: dest,
            prior,
        })
    }

    fn preview_head(&self, repo: &Path) -> Result<String, GitProviderError> {
        let output = self.run_git(repo, &["rev-parse", "--verify", "HEAD"])?;
        let value = output.stdout.trim().to_owned();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_error("Git returned an invalid HEAD object id"));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn preview_branch(&self, repo: &Path) -> Result<Option<String>, GitProviderError> {
        let output = self.run_git(repo, &["branch", "--show-current"])?;
        let branch = output.stdout.trim().to_owned();
        Ok((!branch.is_empty()).then_some(branch))
    }

    fn destination_prior(&self, repo: &Path, dest: &str) -> Result<String, GitProviderError> {
        let output = self.run_git(repo, &["rev-parse", "--verify", dest]);
        match output {
            Ok(value) => {
                let id = value.stdout.trim().to_owned();
                if id.len() != 40 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(provider_error(
                        "Git returned an invalid destination-ref object id",
                    ));
                }
                Ok(id.to_ascii_lowercase())
            }
            Err(error) => {
                if error.message.contains("needed a single revision")
                    || error.message.contains("unknown revision")
                    || error.message.contains("bad revision")
                {
                    return Ok(PRIOR_ABSENT.to_owned());
                }
                let probe = self.run_git(repo, &["show-ref", "--verify", dest]);
                match probe {
                    Ok(value) => {
                        let line = value.stdout.trim();
                        let id = line.split_whitespace().next().unwrap_or("");
                        if id.len() == 40 && id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                            return Ok(id.to_ascii_lowercase());
                        }
                        Ok(PRIOR_ABSENT.to_owned())
                    }
                    Err(_) => Ok(PRIOR_ABSENT.to_owned()),
                }
            }
        }
    }

    pub fn fetch_approved(
        &self,
        args: &ApprovedFetch<'_>,
        resolver: &impl DnsResolver,
    ) -> Result<Value, GitProviderError> {
        let relative = args.relative;
        let destination = args.destination;
        let policy_id = args.policy_id;
        let branch = args.branch;
        let expected_head = args.expected_head;
        let expected_prior = args.expected_prior;
        let pinned = args.pinned;
        validate_policy_id(policy_id)?;
        if policy_id != destination.id {
            return Err(invalid(
                "Git fetch policy id does not match the configured destination",
            ));
        }
        validate_branch(branch)?;
        validate_expected_head(expected_head)?;
        validate_expected_prior(expected_prior)?;
        if !is_public_address(pinned) {
            return Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                "pinned destination address is not public; fetch is denied",
            ));
        }
        let repo = self.repository_root(relative)?;
        self.reject_unsafe_local_network_config(&repo)?;
        self.ensure_supported_fetch_state(&repo)?;
        let preview = self.fetch_preview(relative, policy_id, branch, destination)?;
        if preview.head != expected_head {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "Git HEAD changed after fetch preview; fetch is denied",
            ));
        }
        if preview.prior != expected_prior {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "destination-ref state changed after fetch preview; fetch is denied",
            ));
        }
        let fresh = resolver.resolve(&destination.hostname).map_err(|error| {
            GitProviderError::new(
                error.code,
                format!("re-resolve destination after approval: {}", error.message),
            )
        })?;
        if !fresh.contains(pinned) {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "destination addresses changed after approval; fetch is denied",
            ));
        }
        let pinned_now = select_pinned_address(&fresh)?;
        if pinned_now != *pinned {
            return Err(GitProviderError::new(
                FailureCode::TargetStale,
                "pinned destination address drifted after approval; fetch is denied",
            ));
        }
        let before_head = preview.head.clone();
        let before_branch = self.preview_branch(&repo)?;
        let before_status = self.worktree_status(&repo)?;
        let source = source_ref(branch);
        let dest = destination_ref(policy_id, branch);
        self.run_hardened_fetch(&repo, destination, &source, &dest, pinned)?;
        let after_head = self.preview_head(&repo)?;
        let after_branch = self.preview_branch(&repo)?;
        let after_status = self.worktree_status(&repo)?;
        if after_head != before_head {
            return Err(postcondition("Git fetch changed the checked-out HEAD"));
        }
        if after_branch != before_branch {
            return Err(postcondition("Git fetch changed the current branch"));
        }
        if after_status != before_status {
            return Err(postcondition(
                "Git fetch changed index or worktree material state",
            ));
        }
        let resulting = self.destination_prior(&repo, &dest)?;
        if resulting == PRIOR_ABSENT {
            return Err(postcondition(
                "Git fetch did not create the expected destination ref",
            ));
        }
        if expected_prior != PRIOR_ABSENT && resulting == expected_prior {
            let _ = resulting;
        }
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "policy_id": destination.id,
            "canonical_url": destination.canonical_url,
            "hostname": destination.hostname,
            "port": destination.port,
            "pinned_address": pinned.to_string(),
            "source_ref": source,
            "destination_ref": dest,
            "prior": expected_prior,
            "result": resulting,
            "head": after_head,
            "branch": after_branch,
        }))
    }

    fn worktree_status(&self, repo: &Path) -> Result<String, GitProviderError> {
        let status = self.run_git(
            repo,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all",
            ],
        )?;
        if status.stdout_truncated {
            return Err(provider_error("Git status evidence exceeded its bound"));
        }
        let index = self.run_git(repo, &["ls-files", "--stage", "-z"])?;
        if index.stdout_truncated {
            return Err(provider_error("Git index evidence exceeded its bound"));
        }
        Ok(format!(
            "STATUS\0{}\0INDEX\0{}",
            status.stdout, index.stdout
        ))
    }

    fn reject_unsafe_local_network_config(&self, repo: &Path) -> Result<(), GitProviderError> {
        let output = self.run_git(repo, &["config", "--local", "--list"])?;
        for line in output.stdout.lines() {
            let key = line
                .split_once('=')
                .map(|(key, _)| key.trim().to_ascii_lowercase())
                .unwrap_or_default();
            if key.starts_with("url.")
                && (key.contains("insteadof") || key.contains("pushinsteadof"))
            {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local URL rewrite widens the approved destination; fetch is denied",
                ));
            }
            if key.starts_with("http.")
                && (key.contains("proxy")
                    || key.contains("extraheader")
                    || key.contains("cookie")
                    || key.contains("sslverify")
                    || key.contains("followredirects")
                    || key == "http.proxy")
            {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local HTTP transport configuration widens fetch authority; fetch is denied",
                ));
            }
            if key.starts_with("credential.") || key == "credential.helper" {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local credential configuration is denied for anonymous fetch",
                ));
            }
            if key == "core.askpass" || key == "core.sshcommand" {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    "repository-local helper configuration is denied for fetch",
                ));
            }
        }
        Ok(())
    }

    fn ensure_supported_fetch_state(&self, repo: &Path) -> Result<(), GitProviderError> {
        for marker in [
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "BISECT_LOG",
            "rebase-merge",
            "rebase-apply",
            "sequencer",
        ] {
            let output = self.run_git(repo, &["rev-parse", "--git-path", marker])?;
            let reported = output.stdout.trim().to_owned();
            let path = Path::new(&reported);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo.join(path)
            };
            if path.exists() {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    format!("Git fetch is unavailable while repository state {marker} exists"),
                ));
            }
        }
        Ok(())
    }

    fn run_hardened_fetch(
        &self,
        repo: &Path,
        destination: &GitFetchDestination,
        source: &str,
        dest: &str,
        pinned: &IpAddr,
    ) -> Result<(), GitProviderError> {
        let resolve_value = format!("+{}:{}:{}", destination.hostname, destination.port, pinned);
        let refspec = format!("{source}:{dest}");
        // libcurl opens this path itself and has no `/dev/null` mapping.
        let cookie_file = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let args = vec![
            "-c".to_owned(),
            "protocol.https.allow=always".to_owned(),
            "-c".to_owned(),
            "protocol.http.allow=never".to_owned(),
            "-c".to_owned(),
            "protocol.ssh.allow=never".to_owned(),
            "-c".to_owned(),
            "protocol.git.allow=never".to_owned(),
            "-c".to_owned(),
            "protocol.file.allow=never".to_owned(),
            "-c".to_owned(),
            "protocol.ext.allow=never".to_owned(),
            "-c".to_owned(),
            "http.followRedirects=false".to_owned(),
            "-c".to_owned(),
            "http.sslVerify=true".to_owned(),
            "-c".to_owned(),
            "http.proxy=".to_owned(),
            "-c".to_owned(),
            "https.proxy=".to_owned(),
            "-c".to_owned(),
            format!("http.cookieFile={cookie_file}"),
            "-c".to_owned(),
            "http.saveCookies=false".to_owned(),
            "-c".to_owned(),
            "credential.helper=".to_owned(),
            "-c".to_owned(),
            "core.askPass=".to_owned(),
            "-c".to_owned(),
            format!("http.curloptResolve={resolve_value}"),
            "fetch".to_owned(),
            "--no-tags".to_owned(),
            "--no-recurse-submodules".to_owned(),
            "--no-write-fetch-head".to_owned(),
            destination.canonical_url.clone(),
            refspec,
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run_fetch_raw(repo, &refs).map(|_| ())
    }

    fn run_fetch_raw(&self, repo: &Path, args: &[&str]) -> Result<String, GitProviderError> {
        use std::process::{Command, Stdio};
        use std::thread;
        use std::time::{Duration, Instant};

        let neutral = crate::neutralizing_args(repo)?;
        let mut command = Command::new("git");
        command
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.pager=cat",
                // Repository config must not make a read run a program.
                "-c",
                "log.showSignature=false",
            ])
            .args(&neutral)
            .args(args)
            .current_dir(repo)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        copy_fetch_env(&mut command);
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", crate::NULL_GIT_CONFIG)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_EDITOR", null_fetch_device())
            .env("GIT_SEQUENCE_EDITOR", null_fetch_device())
            .env("GIT_ALLOW_PROTOCOL", "https")
            .env("GCM_INTERACTIVE", "Never")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_SSH_COMMAND", null_fetch_device())
            .env("GIT_SSL_NO_VERIFY", "0");

        let mut child = command.spawn().map_err(|error| {
            GitProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("start hardened git fetch: {error}"),
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            GitProviderError::new(
                FailureCode::ProviderUnavailable,
                "git fetch stdout unavailable",
            )
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            GitProviderError::new(
                FailureCode::ProviderUnavailable,
                "git fetch stderr unavailable",
            )
        })?;
        let stdout_thread = thread::spawn(move || super::read_bounded_for_fetch(stdout));
        let stderr_thread = thread::spawn(move || super::read_bounded_for_fetch(stderr));
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(GitProviderError::new(
                        FailureCode::ProviderUnavailable,
                        "hardened git fetch exceeded 60 second timeout",
                    ));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(GitProviderError::new(
                        FailureCode::ProviderUnavailable,
                        format!("wait for hardened git fetch: {error}"),
                    ));
                }
            }
        };
        let (stdout_bytes, _) = stdout_thread.join().map_err(|_| {
            GitProviderError::new(
                FailureCode::InternalError,
                "git fetch stdout reader panicked",
            )
        })??;
        let (stderr_bytes, _) = stderr_thread.join().map_err(|_| {
            GitProviderError::new(
                FailureCode::InternalError,
                "git fetch stderr reader panicked",
            )
        })??;
        let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
        if !status.success() {
            return Err(GitProviderError::new(
                FailureCode::ProviderUnavailable,
                format!(
                    "hardened git fetch failed: {}",
                    stderr.trim().chars().take(500).collect::<String>()
                ),
            ));
        }
        Ok(String::from_utf8_lossy(&stdout_bytes).into_owned())
    }

    pub fn destination_map_for_tests() -> BTreeMap<String, GitFetchDestination> {
        BTreeMap::new()
    }
}

fn copy_fetch_env(command: &mut std::process::Command) {
    for name in [
        "PATH",
        "Path",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("NO_PROXY", "*");
    command.env("no_proxy", "*");
}

#[cfg(windows)]
fn null_fetch_device() -> std::ffi::OsString {
    std::ffi::OsString::from("NUL")
}

#[cfg(not(windows))]
fn null_fetch_device() -> std::ffi::OsString {
    std::ffi::OsString::from("/dev/null")
}

fn invalid(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::InvalidRequest, message)
}

fn provider_error(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::ProviderUnavailable, message)
}

fn postcondition(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::PostconditionFailed, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn destination_policy_accepts_only_canonical_https_443() {
        let destination =
            parse_destination("github-main", "https://github.com/TheHalfMoon/Orcel.git")
                .expect("valid");
        assert_eq!(destination.hostname, "github.com");
        assert_eq!(destination.port, 443);
        assert_eq!(
            destination.canonical_url,
            "https://github.com/TheHalfMoon/Orcel.git"
        );
        let explicit =
            parse_destination("test", "https://example.com:443/repo.git").expect("explicit 443");
        assert_eq!(explicit.port, 443);
        for bad in [
            "http://example.com/repo.git",
            "https://user@example.com/repo.git",
            "https://example.com/repo.git?x=1",
            "https://example.com/repo.git#frag",
            "https://example.com:80/repo.git",
            "https://example.com:8443/repo.git",
            "git@github.com:TheHalfMoon/Orcel.git",
            "ssh://git@example.com/repo.git",
            "git://example.com/repo.git",
            "file:///tmp/repo.git",
            "ext::sh -c echo",
            "https://192.0.2.1/repo.git",
            "https:///repo.git",
            "https://example/repo.git",
        ] {
            assert!(
                parse_destination("ok-id", bad).is_err(),
                "must reject {bad}"
            );
        }
        for bad_id in [
            "",
            "UPPER",
            "has space",
            "-lead",
            "trail-",
            "double--hyphen",
            "under_score",
            "a:b",
        ] {
            assert!(
                parse_destination(bad_id, "https://example.com/repo.git").is_err(),
                "must reject id {bad_id}"
            );
        }
        let first = parse_destination("dup", "https://example.com/a.git").expect("first");
        let second = parse_destination("dup", "https://example.com/b.git").expect("second");
        assert_ne!(first.canonical_url, second.canonical_url);
        assert_eq!(first.id, second.id);
    }

    #[test]
    fn branch_validation_rejects_arbitrary_refspecs() {
        for good in ["main", "feature/fetch", "release-1"] {
            validate_branch(good).expect("valid branch");
            assert_eq!(source_ref(good), format!("refs/heads/{good}"));
            assert_eq!(
                destination_ref("policy", good),
                format!("refs/remotes/orcel/policy/{good}")
            );
        }
        for bad in [
            "",
            "-lead",
            "refs/heads/main",
            "main:other",
            "../escape",
            "main..other",
            "main@{1}",
            "has space",
            "star*",
            "question?",
            "colon:name",
            "back\\slash",
            ".leading-dot",
            "trailing-dot.",
            "double//slash",
            "a/.b",
            "a.lock",
            "a.lock/b",
            "@",
        ] {
            assert!(validate_branch(bad).is_err(), "must reject branch {bad}");
        }
    }

    #[test]
    fn address_classification_rejects_non_public() {
        for loopback in ["127.0.0.1", "::1"] {
            assert!(
                !is_public_address(&loopback.parse().unwrap()),
                "loopback {loopback}"
            );
        }
        for private in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "fc00::1",
            "fd00::1",
        ] {
            assert!(
                !is_public_address(&private.parse().unwrap()),
                "private {private}"
            );
        }
        for link_local in ["169.254.10.20", "fe80::1"] {
            assert!(
                !is_public_address(&link_local.parse().unwrap()),
                "link-local {link_local}"
            );
        }
        for multicast in ["224.0.0.1", "ff02::1"] {
            assert!(
                !is_public_address(&multicast.parse().unwrap()),
                "multicast {multicast}"
            );
        }
        for unspecified in ["0.0.0.0", "::"] {
            assert!(
                !is_public_address(&unspecified.parse().unwrap()),
                "unspecified {unspecified}"
            );
        }
        for documentation in ["192.0.2.1", "198.51.100.2", "203.0.113.3", "2001:db8::1"] {
            assert!(
                !is_public_address(&documentation.parse().unwrap()),
                "documentation {documentation}"
            );
        }
        for special in [
            "100.64.0.1",
            "198.18.0.1",
            "192.0.0.1",
            "192.88.99.1",
            "240.0.0.1",
        ] {
            assert!(
                !is_public_address(&special.parse().unwrap()),
                "special {special}"
            );
        }
        let _ = (
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        );
    }

    #[test]
    fn pinned_selection_requires_public_and_is_deterministic() {
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(select_pinned_address(&[]).is_err());
        assert!(select_pinned_address(&[private]).is_err());
        let public_two: IpAddr = "1.1.1.1".parse().unwrap();
        let public_one: IpAddr = "8.8.8.8".parse().unwrap();
        let pinned = select_pinned_address(&[public_one, public_two, private]).expect("pinned");
        assert_eq!(pinned, public_two);
        assert_eq!(
            select_pinned_address(&[public_one, public_two]).unwrap(),
            pinned
        );
    }
}
