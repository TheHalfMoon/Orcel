//! Test fixture standing in for the official OpenAI tunnel client in
//! lifecycle qualification. It accepts the same arguments as the closed
//! launch plan, reads the runtime key through its `file:` reference,
//! publishes a loopback health URL, runs the MCP command over stdio, performs
//! an MCP `initialize`, `tools/list`, and `tools/call system_status`
//! exchange, and reports what it observed on stdout (which the supervisor
//! logs). Since #395 the call reaches `orceld` as a remote request and is
//! refused by the remote-session lease gate, which the report records. It
//! proves Orcel's supervision, launch, and MCP-to-orceld path only;
//! it does not prove the OpenAI service.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn value(args: &[String], name: &str) -> String {
    let index = args
        .iter()
        .position(|arg| arg == name)
        .unwrap_or_else(|| panic!("missing {name}"));
    args[index + 1].clone()
}

/// Waits up to 60 seconds for the JSON-RPC response with `id`. A missing
/// response fails the fixture immediately with a diagnostic, so a broken
/// exchange is reported instead of hanging qualification.
fn read_response(lines: &mpsc::Receiver<String>, id: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(remaining) {
            Ok(line) => {
                if let Ok(message) = serde_json::from_str::<Value>(line.trim()) {
                    if message.get("id").and_then(Value::as_u64) == Some(id) {
                        return message;
                    }
                }
            }
            Err(_) => {
                println!("fake-tunnel: no response for id {id}");
                eprintln!("fake-tunnel: no response for id {id}");
                std::process::exit(1);
            }
        }
    }
}

fn short(value: &Value) -> String {
    let text = value.to_string();
    text.chars().take(300).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(args.first().map(String::as_str), Some("run"));
    let key_ref = value(&args, "--control-plane.api-key");
    let key_path = key_ref.strip_prefix("file:").expect("file: reference");
    let key = std::fs::read_to_string(key_path).expect("read runtime key");
    println!("fake-tunnel: key-file-read={}", !key.trim().is_empty());
    // Deliberately emit the key so the supervisor's redaction is exercised.
    println!("fake-tunnel: debug api_key={}", key.trim());
    let leaked = std::env::vars()
        .filter(|(name, value)| {
            let upper = name.to_ascii_uppercase();
            ["KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"]
                .iter()
                .any(|needle| upper.contains(needle))
                || value.contains(key.trim())
        })
        .map(|(name, _)| name)
        .collect::<Vec<_>>();
    println!("fake-tunnel: env-clean={}", leaked.is_empty());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind health");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    let health_file = value(&args, "--health.url-file");
    std::fs::write(&health_file, format!("http://127.0.0.1:{port}/healthz\n")).unwrap();

    let binding = value(&args, "--mcp.command");
    let quoted = binding
        .strip_prefix("channel=main,command=\"")
        .and_then(|rest| rest.strip_suffix('"'))
        .expect("mcp command binding");
    let command = quoted.replace("\\\"", "\"").replace("\\\\", "\\");
    let mut child = Command::new(&command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start MCP command");
    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let (line_sender, lines) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line_sender.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut send = |message: Value| {
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    };

    send(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "fake-tunnel", "version": "0"}
        }
    }));
    let initialize = read_response(&lines, 1);
    println!(
        "fake-tunnel: mcp-initialize server={} raw={}",
        initialize
            .pointer("/result/serverInfo/name")
            .and_then(Value::as_str)
            .unwrap_or("?"),
        short(&initialize)
    );
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    send(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = read_response(&lines, 2);
    let names = tools
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool.get("name").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    println!("fake-tunnel: mcp-tools [{names}]");

    send(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "system_status", "arguments": {}}
    }));
    let call = read_response(&lines, 3);
    let text = call.to_string();
    println!(
        "fake-tunnel: mcp-call is_error={} orceld_answered={} remote_session_inactive={} raw={}",
        call.pointer("/result/isError")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        text.contains("internal_protocol_version") || text.contains(r#""orceld_ok":true"#),
        text.contains("REMOTE_SESSION_INACTIVE"),
        short(&call)
    );

    // Keep the MCP session open, like the real client, until the supervisor's
    // job terminates this process tree.
    let _session_input = stdin;
    let _ = child.wait();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
