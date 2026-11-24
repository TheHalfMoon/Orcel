use orcel_tunnel::{status, TunnelConfig, RUN_REFUSED};

fn main() {
    let command = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    if command == "run" {
        exit_error(RUN_REFUSED);
    }
    let config = match TunnelConfig::from_env() {
        Ok(config) => config,
        Err(error) => exit_error(&error),
    };

    match command.as_str() {
        "status" => println!("{}", status(&config)),
        "doctor" => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "tunnel_id": config.tunnel_id,
                "credential_source": "file",
                "runtime_key_in_environment": false,
                "health_listen": "127.0.0.1:0"
            })
        ),
        _ => exit_error("usage: orcel-tunnel [status|doctor]"),
    }
}

fn exit_error(message: &str) -> ! {
    eprintln!("orcel-tunnel: {message}");
    std::process::exit(2)
}
