//! Thread-local capture for current-thread runtime regression tests.
use std::io::{self, Write};
use std::sync::{Arc, Mutex};

/// Run a log assertion with its own tracing callsite registry. A thread-local
/// subscriber alone still shares cached callsite interest with parallel tests.
pub(crate) fn isolated(
    full_test_name: &str,
    check: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    const CHILD: &str = "AEGAEON_TEST_ISOLATED_LOG_CAPTURE";
    let (_, test) = full_test_name
        .split_once("::")
        .ok_or("test module lacks crate prefix")?;
    if let Some(marker) = std::env::var_os(CHILD) {
        assert_eq!(marker, test, "unexpected logging child marker");
        return check();
    }

    let executable = std::env::current_exe().map_err(|err| err.to_string())?;
    let output = std::process::Command::new(executable)
        .args([
            test,
            "--exact",
            "--nocapture",
            "--format=pretty",
            "--color=never",
        ])
        .env(CHILD, test)
        .output()
        .map_err(|err| format!("logging child execution failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success()
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && stdout.contains(&format!("test {test} ... ok")),
        "logging child failed or did not run exactly one test: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    Ok(())
}

#[derive(Clone, Default)]
pub(crate) struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    pub(crate) fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish()
    }
}

impl Write for Capture {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
