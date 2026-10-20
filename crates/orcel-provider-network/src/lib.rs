use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

pub const MAX_URL_CHARS: usize = 2048;
pub const MAX_BODY_BYTES: usize = 1_048_576;
pub const MAX_REDIRECTS: usize = 5;

#[derive(Debug, Clone)]
pub struct NetworkError {
    pub code: FailureCode,
    pub message: String,
}

impl NetworkError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchTarget {
    pub canonical_url: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub path_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFetch {
    pub target: FetchTarget,
    pub addresses: Vec<IpAddr>,
    pub address_set_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub peer: IpAddr,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResult {
    pub target: FetchTarget,
    pub status: u16,
    pub body: Vec<u8>,
    pub body_digest: String,
    pub hop_count: usize,
}

impl FetchResult {
    pub fn to_json(&self, workspace: &str, policy_revision: &str) -> Value {
        json!({
            "scheme": self.target.scheme,
            "host": self.target.host,
            "port": self.target.port,
            "path_digest": self.target.path_digest,
            "status": self.status,
            "byte_length": self.body.len(),
            "body_digest": self.body_digest,
            "hop_count": self.hop_count,
            "truncated": false,
            "workspace": workspace,
            "policy_revision": policy_revision,
            "body": self.body,
        })
    }
}

pub trait DnsResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, NetworkError> {
        let candidates = (host, 443)
            .to_socket_addrs()
            .map_err(|error| unavailable(format!("resolve destination hostname: {error}")))?;
        let addresses = candidates
            .map(|candidate| candidate.ip())
            .collect::<Vec<_>>();
        normalize_public_set(addresses)
    }
}

pub trait Transport {
    fn get(
        &self,
        target: &FetchTarget,
        allowed: &[IpAddr],
    ) -> Result<TransportResponse, NetworkError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTransport;

impl Transport for SystemTransport {
    fn get(
        &self,
        target: &FetchTarget,
        allowed: &[IpAddr],
    ) -> Result<TransportResponse, NetworkError> {
        native_get(target, allowed)
    }
}

/// WI-06 HTTP method of one fixed-origin provider API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiMethod {
    Get,
    Post,
}

impl ApiMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            ApiMethod::Get => "GET",
            ApiMethod::Post => "POST",
        }
    }
}

/// WI-06: one request to a provider API at a fixed HTTPS origin. Header
/// names are fixed by the adapter; values may hold an API key, so this type
/// has no `Debug` and transports never put a header into an error.
pub struct ApiRequest<'a> {
    pub method: ApiMethod,
    pub target: &'a FetchTarget,
    pub headers: &'a [(&'static str, &'a [u8])],
    pub body: &'a [u8],
    /// The transport stops reading and fails `OutputLimit` past this many
    /// body bytes.
    pub max_body: usize,
}

/// WI-06 transport for provider API calls: no redirects are followed, no
/// proxy, cookies or ambient authentication are used, and the connection
/// is pinned to the first validated address in `allowed`.
pub trait ApiTransport {
    fn send(
        &self,
        request: &ApiRequest<'_>,
        allowed: &[IpAddr],
    ) -> Result<TransportResponse, NetworkError>;
}

impl ApiTransport for SystemTransport {
    fn send(
        &self,
        request: &ApiRequest<'_>,
        allowed: &[IpAddr],
    ) -> Result<TransportResponse, NetworkError> {
        native_send(request, allowed)
    }
}

/// Whether this build has a native HTTPS transport (`SystemTransport`).
pub const NATIVE_TRANSPORT_AVAILABLE: bool = cfg!(windows);

pub fn is_network_fetch_shape(capability: &str, operation: &str) -> bool {
    capability == "network" && operation == "fetch"
}

pub fn is_denied_network_shape(capability: &str, operation: &str) -> bool {
    capability == "network" && !is_network_fetch_shape(capability, operation)
}

pub fn parse_target(url: &str) -> Result<FetchTarget, NetworkError> {
    if url.is_empty() || url.chars().count() > MAX_URL_CHARS {
        return Err(invalid(
            "network fetch URL must contain 1..=2048 characters",
        ));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) || url.contains('\\') {
        return Err(invalid(
            "network fetch URL contains unsafe whitespace, control data, or backslash",
        ));
    }
    if url.contains('#') {
        return Err(invalid("network fetch URL fragments are denied"));
    }
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| invalid("network fetch URL must use lowercase https scheme"))?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let suffix = &rest[authority_end..];
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid(
            "network fetch URL must contain a hostname and no userinfo",
        ));
    }
    let (host_raw, port) = if let Some((host, port_text)) = authority.rsplit_once(':') {
        if host.contains(':')
            || port_text.is_empty()
            || !port_text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("network fetch URL authority or port is invalid"));
        }
        let parsed = port_text
            .parse::<u16>()
            .map_err(|_| invalid("network fetch URL port is invalid"))?;
        if parsed != 443 {
            return Err(invalid("network fetch URL must use port 443 only"));
        }
        (host, parsed)
    } else {
        (authority, 443)
    };
    validate_dns_hostname(host_raw)?;
    let host = host_raw.to_ascii_lowercase();
    let path_and_query = if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_owned()
    };
    if !path_and_query.starts_with('/') {
        return Err(invalid("network fetch URL path is invalid"));
    }
    let canonical_url = format!("https://{host}{path_and_query}");
    let path_digest = digest_bytes(path_and_query.as_bytes());
    Ok(FetchTarget {
        canonical_url,
        scheme: "https".to_owned(),
        host,
        port,
        path_and_query,
        path_digest,
    })
}

fn validate_dns_hostname(host: &str) -> Result<(), NetworkError> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.starts_with('-')
        || host.ends_with('-')
        || host.contains("..")
        || host.contains('%')
    {
        return Err(invalid("network fetch hostname is malformed"));
    }
    if host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || !host.bytes().any(|b| b.is_ascii_alphabetic())
    {
        return Err(invalid(
            "network fetch hostname must be a dotted DNS name, not a literal or numeric form",
        ));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid(
                "network fetch hostname contains an unsafe DNS label",
            ));
        }
    }
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err(denied("localhost destinations are denied"));
    }
    Ok(())
}

pub fn prepare(url: &str, resolver: &impl DnsResolver) -> Result<PreparedFetch, NetworkError> {
    let target = parse_target(url)?;
    let addresses = normalize_public_set(resolver.resolve(&target.host)?)?;
    let address_set_digest = address_set_digest(&addresses);
    Ok(PreparedFetch {
        target,
        addresses,
        address_set_digest,
    })
}

pub fn normalize_public_set(mut addresses: Vec<IpAddr>) -> Result<Vec<IpAddr>, NetworkError> {
    if addresses.is_empty() {
        return Err(unavailable("destination hostname resolved to no addresses"));
    }
    addresses.sort_by_key(|address| address.to_string());
    addresses.dedup();
    if addresses.iter().any(|address| !is_public_address(address)) {
        return Err(denied(
            "destination resolution contains a non-public address",
        ));
    }
    Ok(addresses)
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
        || value.is_broadcast()
        || value.is_documentation()
    {
        return false;
    }
    if octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        || (octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2))
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
    {
        return false;
    }
    true
}

fn is_public_ipv6(value: &Ipv6Addr) -> bool {
    if value.is_loopback() || value.is_unspecified() || value.is_multicast() {
        return false;
    }
    if let Some(mapped) = value.to_ipv4_mapped() {
        return is_public_ipv4(&mapped);
    }
    if value.to_ipv4().is_some() {
        return false;
    }

    let segments = value.segments();
    // IANA currently allocates native IPv6 global unicast from 2000::/3.
    // Everything outside that allocation ceiling fails closed. Within it,
    // deny special-purpose and reserved blocks relevant to this authority.
    if (segments[0] & 0xe000) != 0x2000 {
        return false;
    }
    if (segments[0] == 0x2001 && segments[1] == 0x0000)
        || (segments[0] == 0x2001 && segments[1] == 0x0001)
        || (segments[0] == 0x2001 && segments[1] == 0x0002)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] & 0xff00) == 0x3f00
    {
        return false;
    }
    true
}

pub fn address_set_digest(addresses: &[IpAddr]) -> String {
    let mut normalized = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    normalized.sort();
    digest_bytes(normalized.join("\n").as_bytes())
}

pub fn execute_prepared(
    prepared: &PreparedFetch,
    resolver: &impl DnsResolver,
    transport: &impl Transport,
) -> Result<FetchResult, NetworkError> {
    let approved = prepared.addresses.clone();
    let post_approval = normalize_public_set(resolver.resolve(&prepared.target.host)?)?;
    if post_approval != approved {
        return Err(stale("destination address set changed after approval"));
    }

    let mut current = prepared.target.clone();
    let mut visited = HashSet::new();
    visited.insert(current.canonical_url.clone());

    for hop in 0..=MAX_REDIRECTS {
        let current_set = normalize_public_set(resolver.resolve(&current.host)?)?;
        if current_set != approved {
            return Err(stale("destination address set changed during fetch"));
        }
        let response = transport.get(&current, &current_set)?;
        if !current_set.contains(&response.peer) {
            return Err(stale(
                "connected peer is not a member of the validated address set",
            ));
        }
        if response.body.len() > MAX_BODY_BYTES {
            return Err(NetworkError::new(
                FailureCode::OutputLimit,
                "network response exceeded 1048576-byte bound",
            ));
        }
        if (200..300).contains(&response.status) {
            return Ok(FetchResult {
                target: current,
                status: response.status,
                body_digest: digest_bytes(&response.body),
                body: response.body,
                hop_count: hop,
            });
        }
        if (300..400).contains(&response.status) {
            if hop == MAX_REDIRECTS {
                return Err(denied("network redirect chain exceeded 5 hops"));
            }
            let location = response.location.as_deref().ok_or_else(|| {
                NetworkError::new(
                    FailureCode::PostconditionFailed,
                    "redirect response omitted Location",
                )
            })?;
            let next = redirect_target(&current, location)?;
            if next.scheme != prepared.target.scheme
                || next.host != prepared.target.host
                || next.port != prepared.target.port
            {
                return Err(denied("cross-origin or scheme-widening redirect is denied"));
            }
            if !visited.insert(next.canonical_url.clone()) {
                return Err(denied("network redirect loop detected"));
            }
            current = next;
            continue;
        }
        Err(NetworkError::new(
            FailureCode::PostconditionFailed,
            format!("network fetch returned HTTP status {}", response.status),
        ))?
    }
    Err(denied("network redirect chain exceeded bound"))
}

fn redirect_target(current: &FetchTarget, location: &str) -> Result<FetchTarget, NetworkError> {
    if location.starts_with("https://") {
        return parse_target(location);
    }
    if location.starts_with('/') {
        return parse_target(&format!("https://{}{}", current.host, location));
    }
    Err(denied("relative redirect form is not authorized"))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn invalid(message: impl Into<String>) -> NetworkError {
    NetworkError::new(FailureCode::InvalidRequest, message)
}
fn denied(message: impl Into<String>) -> NetworkError {
    NetworkError::new(FailureCode::CapabilityDenied, message)
}
fn stale(message: impl Into<String>) -> NetworkError {
    NetworkError::new(FailureCode::TargetStale, message)
}
fn unavailable(message: impl Into<String>) -> NetworkError {
    NetworkError::new(FailureCode::ProviderUnavailable, message)
}
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(not(windows))]
fn native_get(
    _target: &FetchTarget,
    _allowed: &[IpAddr],
) -> Result<TransportResponse, NetworkError> {
    Err(unavailable(
        "native SG-000040 transport is available only on Windows",
    ))
}

#[cfg(not(windows))]
fn native_send(
    _request: &ApiRequest<'_>,
    _allowed: &[IpAddr],
) -> Result<TransportResponse, NetworkError> {
    Err(unavailable(
        "native HTTPS transport is available only on Windows in this build",
    ))
}

#[cfg(windows)]
fn native_get(target: &FetchTarget, allowed: &[IpAddr]) -> Result<TransportResponse, NetworkError> {
    native_send(
        &ApiRequest {
            method: ApiMethod::Get,
            target,
            headers: &[],
            body: &[],
            max_body: MAX_BODY_BYTES,
        },
        allowed,
    )
}

/// One WinHTTP request. Redirects, cookies, ambient authentication,
/// keep-alive and proxies are off; the connection is pinned to the first
/// validated address. Header values (WI-06 API keys) are copied only into a
/// buffer that is wiped when this function returns, and no error carries
/// a header.
#[cfg(windows)]
fn native_send(
    request: &ApiRequest<'_>,
    allowed: &[IpAddr],
) -> Result<TransportResponse, NetworkError> {
    use core::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
        WinHttpQueryDataAvailable, WinHttpQueryHeaders, WinHttpQueryOption, WinHttpReadData,
        WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_CONNECTION_INFO, WINHTTP_DISABLE_AUTHENTICATION,
        WINHTTP_DISABLE_COOKIES, WINHTTP_DISABLE_KEEP_ALIVE, WINHTTP_DISABLE_REDIRECTS,
        WINHTTP_FLAG_SECURE, WINHTTP_OPTION_CONNECTION_INFO, WINHTTP_OPTION_DISABLE_FEATURE,
        WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE,
    };
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_STORAGE,
    };

    struct Handle(*mut c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    WinHttpCloseHandle(self.0);
                }
            }
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn winerr(context: &str) -> NetworkError {
        unavailable(format!("{context}: {}", std::io::Error::last_os_error()))
    }
    unsafe fn peer_from_storage(storage: &SOCKADDR_STORAGE) -> Result<IpAddr, NetworkError> {
        if storage.ss_family == AF_INET {
            let sin = &*(storage as *const _ as *const SOCKADDR_IN);
            let raw = sin.sin_addr.S_un.S_addr;
            return Ok(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())));
        }
        if storage.ss_family == AF_INET6 {
            let sin6 = &*(storage as *const _ as *const SOCKADDR_IN6);
            let bytes = sin6.sin6_addr.u.Byte;
            return Ok(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
        Err(unavailable(
            "WinHTTP returned an unsupported peer address family",
        ))
    }

    let agent = wide("Orcel/SG-000040");
    let session = Handle(unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            null(),
            null(),
            0,
        )
    });
    if session.0.is_null() {
        return Err(winerr("WinHttpOpen"));
    }
    if unsafe { WinHttpSetTimeouts(session.0, 5_000, 5_000, 5_000, 10_000) } == 0 {
        return Err(winerr("WinHttpSetTimeouts"));
    }

    /// Wipes the wide header block on every return path.
    struct Wiped(Vec<u16>);
    impl Drop for Wiped {
        fn drop(&mut self) {
            self.0.fill(0);
            std::hint::black_box(&self.0);
        }
    }

    let target = request.target;
    let host = wide(&target.host);
    let connect = Handle(unsafe { WinHttpConnect(session.0, host.as_ptr(), 443, 0) });
    if connect.0.is_null() {
        return Err(winerr("WinHttpConnect"));
    }

    let method = wide(request.method.as_str());
    let path = wide(&target.path_and_query);
    let http = Handle(unsafe {
        WinHttpOpenRequest(
            connect.0,
            method.as_ptr(),
            path.as_ptr(),
            null(),
            null(),
            null(),
            WINHTTP_FLAG_SECURE,
        )
    });
    if http.0.is_null() {
        return Err(winerr("WinHttpOpenRequest"));
    }

    let disabled: u32 = WINHTTP_DISABLE_COOKIES
        | WINHTTP_DISABLE_AUTHENTICATION
        | WINHTTP_DISABLE_KEEP_ALIVE
        | WINHTTP_DISABLE_REDIRECTS;
    if unsafe {
        WinHttpSetOption(
            http.0,
            WINHTTP_OPTION_DISABLE_FEATURE,
            &disabled as *const _ as *mut c_void,
            size_of::<u32>() as u32,
        )
    } == 0
    {
        return Err(winerr("WinHttpSetOption(disable features)"));
    }

    // WINHTTP_OPTION_RESOLUTION_HOSTNAME (165) is set before sending so WinHTTP
    // cannot perform a fresh model-unbound hostname resolution between validation and
    // connection. The connect handle keeps the authorized DNS hostname for TLS identity.
    const WINHTTP_OPTION_RESOLUTION_HOSTNAME_ORCEL: u32 = 165;
    let pinned_peer = *allowed
        .first()
        .ok_or_else(|| unavailable("validated destination address set is empty"))?;
    if !is_public_address(&pinned_peer) {
        return Err(denied("validated destination address is not public"));
    }
    let resolution_host = wide(&pinned_peer.to_string());
    if unsafe {
        WinHttpSetOption(
            http.0,
            WINHTTP_OPTION_RESOLUTION_HOSTNAME_ORCEL,
            resolution_host.as_ptr() as *mut c_void,
            (resolution_host.len() * size_of::<u16>()) as u32,
        )
    } == 0
    {
        return Err(winerr("WinHttpSetOption(resolution hostname)"));
    }

    let mut header_block = Wiped(Vec::new());
    for (name, value) in request.headers {
        let value = std::str::from_utf8(value)
            .ok()
            .filter(|value| !value.contains(['\r', '\n']))
            .ok_or_else(|| invalid("provider request header value is not one line of text"))?;
        header_block.0.extend(name.encode_utf16());
        header_block.0.extend(": ".encode_utf16());
        header_block.0.extend(value.encode_utf16());
        header_block.0.extend("\r\n".encode_utf16());
    }
    let body_len = u32::try_from(request.body.len())
        .map_err(|_| invalid("provider request body is too large"))?;
    let headers_len = u32::try_from(header_block.0.len())
        .map_err(|_| invalid("provider request headers are too large"))?;
    let sent = unsafe {
        WinHttpSendRequest(
            http.0,
            if header_block.0.is_empty() {
                null()
            } else {
                header_block.0.as_ptr()
            },
            headers_len,
            if request.body.is_empty() {
                null_mut()
            } else {
                request.body.as_ptr() as *mut c_void
            },
            body_len,
            body_len,
            0,
        )
    };
    drop(header_block);
    if sent == 0 {
        return Err(winerr("WinHttpSendRequest"));
    }
    if unsafe { WinHttpReceiveResponse(http.0, null_mut()) } == 0 {
        return Err(winerr("WinHttpReceiveResponse"));
    }

    let mut connection: WINHTTP_CONNECTION_INFO = unsafe { zeroed() };
    connection.cbSize = size_of::<WINHTTP_CONNECTION_INFO>() as u32;
    let mut connection_size = size_of::<WINHTTP_CONNECTION_INFO>() as u32;
    if unsafe {
        WinHttpQueryOption(
            http.0,
            WINHTTP_OPTION_CONNECTION_INFO,
            &mut connection as *mut _ as *mut c_void,
            &mut connection_size,
        )
    } == 0
    {
        return Err(winerr("WinHttpQueryOption(connection info)"));
    }
    let peer = unsafe { peer_from_storage(&connection.RemoteAddress)? };
    if peer != pinned_peer {
        return Err(stale(
            "WinHTTP connected peer did not match the pinned validated address",
        ));
    }

    let mut status: u32 = 0;
    let mut status_size = size_of::<u32>() as u32;
    if unsafe {
        WinHttpQueryHeaders(
            http.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            &mut status as *mut _ as *mut c_void,
            &mut status_size,
            null_mut(),
        )
    } == 0
    {
        return Err(winerr("WinHttpQueryHeaders(status)"));
    }

    let location = if (300..400).contains(&(status as u16)) {
        let mut buffer = vec![0u16; MAX_URL_CHARS + 1];
        let mut bytes = (buffer.len() * size_of::<u16>()) as u32;
        let ok = unsafe {
            WinHttpQueryHeaders(
                http.0,
                WINHTTP_QUERY_LOCATION,
                null(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut bytes,
                null_mut(),
            )
        };
        if ok == 0 {
            None
        } else {
            let used = (bytes as usize / size_of::<u16>()).min(buffer.len());
            let end = buffer[..used].iter().position(|v| *v == 0).unwrap_or(used);
            Some(String::from_utf16_lossy(&buffer[..end]))
        }
    } else {
        None
    };

    let mut body = Vec::new();
    loop {
        let mut available: u32 = 0;
        if unsafe { WinHttpQueryDataAvailable(http.0, &mut available) } == 0 {
            return Err(winerr("WinHttpQueryDataAvailable"));
        }
        if available == 0 {
            break;
        }
        if body.len().saturating_add(available as usize) > request.max_body {
            return Err(NetworkError::new(
                FailureCode::OutputLimit,
                format!("network response exceeded {}-byte bound", request.max_body),
            ));
        }
        let start = body.len();
        body.resize(start + available as usize, 0);
        let mut read: u32 = 0;
        if unsafe {
            WinHttpReadData(
                http.0,
                body[start..].as_mut_ptr() as *mut c_void,
                available,
                &mut read,
            )
        } == 0
        {
            return Err(winerr("WinHttpReadData"));
        }
        body.truncate(start + read as usize);
        if read == 0 {
            break;
        }
    }

    Ok(TransportResponse {
        status: status as u16,
        peer,
        location,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct SequenceResolver {
        answers: Mutex<VecDeque<Vec<IpAddr>>>,
    }
    impl SequenceResolver {
        fn new(answers: Vec<Vec<IpAddr>>) -> Self {
            Self {
                answers: Mutex::new(answers.into()),
            }
        }
    }
    impl DnsResolver for SequenceResolver {
        fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, NetworkError> {
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| unavailable("no resolver answer"))
        }
    }

    struct FakeTransport {
        responses: Mutex<VecDeque<TransportResponse>>,
    }
    impl FakeTransport {
        fn new(responses: Vec<TransportResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
            }
        }
    }
    impl Transport for FakeTransport {
        fn get(
            &self,
            _target: &FetchTarget,
            _allowed: &[IpAddr],
        ) -> Result<TransportResponse, NetworkError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| unavailable("no transport response"))
        }
    }

    fn public() -> IpAddr {
        "8.8.8.8".parse().unwrap()
    }

    #[test]
    fn parser_enforces_https_get_destination_ceiling() {
        let target = parse_target("https://Example.COM/path?q=1").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.path_and_query, "/path?q=1");
        for bad in [
            "http://example.com/",
            "https://user@example.com/",
            "https://example.com:444/",
            "https://127.0.0.1/",
            "https://localhost/",
            "https://example.com/#frag",
        ] {
            assert!(parse_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dangerous_address_catalog_is_denied() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "0.0.0.0",
            "::1",
            "::",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "fec0::1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "3fff::1",
            "5f00::1",
            "4000::1",
            "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = value.parse().unwrap();
            assert!(!is_public_address(&ip), "{value}");
        }
        assert!(is_public_address(&public()));
        assert!(is_public_address(&"2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn mixed_public_private_resolution_fails_closed() {
        let error = normalize_public_set(vec![public(), "127.0.0.1".parse().unwrap()]).unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
    }

    #[test]
    fn post_approval_rebinding_fails_stale() {
        let resolver =
            SequenceResolver::new(vec![vec![public()], vec!["1.1.1.1".parse().unwrap()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![]);
        let error = execute_prepared(&prepared, &resolver, &transport).unwrap_err();
        assert_eq!(error.code, FailureCode::TargetStale);
    }

    #[test]
    fn peer_mismatch_fails_closed() {
        let resolver = SequenceResolver::new(vec![vec![public()], vec![public()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![TransportResponse {
            status: 200,
            peer: "1.1.1.1".parse().unwrap(),
            location: None,
            body: b"ok".to_vec(),
        }]);
        let error = execute_prepared(&prepared, &resolver, &transport).unwrap_err();
        assert_eq!(error.code, FailureCode::TargetStale);
    }

    #[test]
    fn bounded_success_returns_digest_and_body() {
        let resolver = SequenceResolver::new(vec![vec![public()], vec![public()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/data").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![TransportResponse {
            status: 200,
            peer: public(),
            location: None,
            body: b"hello".to_vec(),
        }]);
        let result = execute_prepared(&prepared, &resolver, &transport).unwrap();
        assert_eq!(result.body, b"hello");
        assert_eq!(result.hop_count, 0);
        assert_eq!(result.body_digest, digest_bytes(b"hello"));
    }

    #[test]
    fn redirect_is_same_origin_only_and_bounded() {
        let resolver = SequenceResolver::new(vec![vec![public()], vec![public()], vec![public()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/start").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![
            TransportResponse {
                status: 302,
                peer: public(),
                location: Some("/next".into()),
                body: Vec::new(),
            },
            TransportResponse {
                status: 200,
                peer: public(),
                location: None,
                body: b"done".to_vec(),
            },
        ]);
        let result = execute_prepared(&prepared, &resolver, &transport).unwrap();
        assert_eq!(result.hop_count, 1);

        let other = redirect_target(&prepared.target, "https://other.example/path").unwrap();
        assert_ne!(other.host, prepared.target.host);
    }

    #[test]
    fn oversized_response_fails_output_limit() {
        let resolver = SequenceResolver::new(vec![vec![public()], vec![public()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![TransportResponse {
            status: 200,
            peer: public(),
            location: None,
            body: vec![0; MAX_BODY_BYTES + 1],
        }]);
        let error = execute_prepared(&prepared, &resolver, &transport).unwrap_err();
        assert_eq!(error.code, FailureCode::OutputLimit);
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_https_transport_pins_validated_peer() {
        let target = parse_target("https://example.com/").unwrap();
        let addresses = SystemResolver.resolve(&target.host).unwrap();
        let expected_peer = addresses[0];
        let response = native_get(&target, &addresses).unwrap();
        assert_eq!(response.peer, expected_peer);
        assert!((200..300).contains(&response.status));
        assert!(response.body.len() <= MAX_BODY_BYTES);
    }

    #[test]
    fn error_status_never_returns_body() {
        let resolver = SequenceResolver::new(vec![vec![public()], vec![public()]]);
        let prepared = PreparedFetch {
            target: parse_target("https://example.com/").unwrap(),
            addresses: vec![public()],
            address_set_digest: address_set_digest(&[public()]),
        };
        let transport = FakeTransport::new(vec![TransportResponse {
            status: 500,
            peer: public(),
            location: None,
            body: b"secret remote error".to_vec(),
        }]);
        let error = execute_prepared(&prepared, &resolver, &transport).unwrap_err();
        assert_eq!(error.code, FailureCode::PostconditionFailed);
        assert!(!error.message.contains("secret"));
    }
}
