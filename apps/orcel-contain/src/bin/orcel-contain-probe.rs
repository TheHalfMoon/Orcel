//! Test fixture for `tests/contain.rs`, never packaged: it attempts one
//! operation the contained tier must allow or deny and reports the result in
//! its exit code, so each test can run it contained and uncontained (the
//! positive control).
//!
//! Exit codes: 0 the operation succeeded; 10 write failed; 11 read failed;
//! 12 network failed; 13 process creation failed; 14 hard link failed;
//! 2 usage.

use std::io::Write as _;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |index: usize| args.get(index).map(String::as_str).unwrap_or_default();
    let code = match arg(0) {
        "noop" => 0,
        "exit" => arg(1).parse().unwrap_or(2),
        "print" => {
            let count: usize = arg(1).parse().unwrap_or(0);
            let _ = std::io::stdout().write_all(&vec![b'o'; count]);
            0
        }
        "eprint" => {
            let count: usize = arg(1).parse().unwrap_or(0);
            let _ = std::io::stderr().write_all(&vec![b'e'; count]);
            0
        }
        // Print the whole environment the child received, one NAME=value per
        // line.
        "env" => {
            for (name, value) in std::env::vars_os() {
                println!("{}={}", name.to_string_lossy(), value.to_string_lossy());
            }
            0
        }
        "write" => match std::fs::write(arg(1), b"contained write") {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("write: {error}");
                10
            }
        },
        "read" => match std::fs::read(arg(1)) {
            Ok(bytes) => {
                let _ = std::io::stdout().write_all(&bytes);
                0
            }
            Err(error) => {
                eprintln!("read: {error}");
                11
            }
        },
        // Give the existing file arg(1) a second name, arg(2).
        "link" => match std::fs::hard_link(arg(1), arg(2)) {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("link: {error}");
                14
            }
        },
        "connect" => match arg(1).parse() {
            Ok(address) => {
                match std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
                    Ok(_) => 0,
                    Err(error) => {
                        eprintln!("connect: {error}");
                        12
                    }
                }
            }
            Err(_) => 2,
        },
        // Create a process: this binary again, running `noop`.
        "spawn" => match std::env::current_exe()
            .and_then(|path| std::process::Command::new(path).arg("noop").status())
        {
            Ok(status) if status.success() => 0,
            Ok(_) => 13,
            Err(error) => {
                eprintln!("spawn: {error}");
                13
            }
        },
        // Write this process's id to a file, then wait to be killed.
        "hold" => {
            if std::fs::write(arg(1), std::process::id().to_string()).is_err() {
                10
            } else {
                std::thread::sleep(Duration::from_secs(120));
                0
            }
        }
        "sleep" => {
            std::thread::sleep(Duration::from_millis(arg(1).parse().unwrap_or(0)));
            0
        }
        "spin" => loop {
            std::hint::spin_loop();
        },
        _ => 2,
    };
    std::process::exit(code);
}
