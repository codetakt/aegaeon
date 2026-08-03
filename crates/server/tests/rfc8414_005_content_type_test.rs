use std::collections::HashMap;
use std::fmt::Display;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[path = "support/server_process_env.rs"]
mod server_process_env;

type TestResult = Result<(), String>;

trait TestContext<T> {
    fn test_context(self, context: &str) -> Result<T, String>;
}

impl<T, E: Display> TestContext<T> for Result<T, E> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.map_err(|err| format!("{context}: {err}"))
    }
}

impl<T> TestContext<T> for Option<T> {
    fn test_context(self, context: &str) -> Result<T, String> {
        self.ok_or_else(|| context.to_string())
    }
}

struct ServerGuard(Option<Child>);

impl ServerGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn pick_free_port() -> std::io::Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

fn start_server(port: u16) -> std::io::Result<Child> {
    let bin = env!("CARGO_BIN_EXE_aegaeon-server");
    let mut cmd = Command::new(bin);
    cmd.arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .env("RUST_LOG", "off")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in server_process_env::shared_runtime_store_env(&[]) {
        cmd.env(key, value);
    }
    cmd.spawn()
}

fn wait_until_ready(child: &mut Child, port: u16, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_status)) => return false,
            Ok(None) => {}
            Err(_) => return false,
        }
        if let Ok((status, _, _)) = http_get(port, "/health") {
            if status == 200 {
                return true;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn http_get(port: u16, path: &str) -> Result<(u16, HashMap<String, String>, String), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nForwarded: for=127.0.0.1;proto=https\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    // Parse status line and headers
    let resp = String::from_utf8_lossy(&buf);
    let mut parts = resp.split("\r\n\r\n");
    let header = parts.next().ok_or("no header")?;
    let body = parts.next().unwrap_or("").to_string();
    let mut lines = header.split("\r\n");
    let status_line = lines.next().ok_or("no status line")?;
    let mut sp = status_line.split_whitespace();
    let _http = sp.next().ok_or("bad status line")?;
    let code: u16 = sp
        .next()
        .ok_or("no code")?
        .parse()
        .map_err(|_| "bad code")?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    Ok((code, headers, body))
}

fn spawn_metadata_server() -> Result<Option<(ServerGuard, u16)>, String> {
    const MAX_ATTEMPTS: usize = 8;
    if server_process_env::skip_without_server_process_runtime(
        "RFC 8414 metadata content-type test",
    ) {
        return Ok(None);
    }
    for attempt in 0..MAX_ATTEMPTS {
        let port = match pick_free_port() {
            Ok(port) => port,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping RFC 8414-005 test: unable to bind port ({e})");
                return Ok(None);
            }
            Err(e) => return Err(format!("failed to pick free port: {e}")),
        };
        let mut child = match start_server(port) {
            Ok(child) => child,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                eprintln!("skipping RFC 8414-005 test: unable to spawn server ({e})");
                return Ok(None);
            }
            Err(e) => return Err(format!("failed to spawn server: {e}")),
        };
        if wait_until_ready(&mut child, port, 10) {
            return Ok(Some((ServerGuard::new(child), port)));
        }
        let _ = child.kill();
        let _ = child.wait();
        if attempt + 1 < MAX_ATTEMPTS {
            thread::sleep(Duration::from_millis(200));
        }
    }
    Err(format!(
        "Server failed to start after {MAX_ATTEMPTS} attempts"
    ))
}

/// Test RFC 8414-005: Authorization server metadata MUST use "application/json" Content-Type
///
/// RFC 8414 Section 3 states:
/// "The response is a set of authorization server metadata values.
/// ...
/// The response MUST use the 'application/json' media type."
#[test]
fn rfc8414_005_metadata_content_type_is_application_json() -> TestResult {
    let Some((_server, port)) = spawn_metadata_server()? else {
        return Ok(());
    };

    let (status, headers, body) = http_get(port, "/.well-known/oauth-authorization-server")?;

    // Verify HTTP 200 OK
    assert_eq!(status, 200, "Expected 200 OK for metadata endpoint");

    // Verify Content-Type header is present and set to application/json
    let content_type = headers
        .get("content-type")
        .test_context("Content-Type header must be present in metadata response")?;

    // RFC 8414-005: MUST use "application/json" media type
    // Allow for charset parameter (e.g., "application/json; charset=utf-8")
    assert!(
        content_type.starts_with("application/json"),
        "RFC 8414-005 violation: Content-Type must be 'application/json', got: {content_type}"
    );

    // Verify the body is valid JSON (sanity check)
    let _: serde_json::Value =
        serde_json::from_str(&body).test_context("Metadata response body must be valid JSON")?;

    Ok(())
}
