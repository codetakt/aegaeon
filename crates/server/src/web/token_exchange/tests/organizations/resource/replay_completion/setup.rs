//! Preserve actual store observations before injecting acknowledgement loss.
use std::io::Write;

pub(in super::super) fn forward_setup(
    arguments: &[redis::Value],
    socket: &mut std::net::TcpStream,
    actual: &mut redis::Connection,
) -> anyhow::Result<()> {
    let values: Vec<String> = redis::from_redis_value(&redis::Value::Array(arguments.to_vec()))?;
    anyhow::ensure!(
        values.len() <= 4 && values.iter().all(|value| value.len() <= 256),
        "setup command budget"
    );
    let words: Vec<&str> = values.iter().map(String::as_str).collect();
    anyhow::ensure!(
        matches!(
            words.as_slice(),
            ["PING"]
                | ["INFO", "server", "replication"]
                | ["CLIENT", "INFO"]
                | ["CLIENT", "SETNAME", _]
                | ["CLIENT", "SETINFO", _, _]
        ),
        "unexpected setup command"
    );
    let mut command = redis::cmd(words[0]);
    for argument in &words[1..] {
        command.arg(argument);
    }
    // INFO and CLIENT INFO must describe the same actual Redis connection that
    // subsequently commits SET or returns GET; do not fabricate incarnation/db.
    match command.query::<redis::Value>(actual)? {
        redis::Value::Okay => socket.write_all(b"+OK\r\n")?,
        redis::Value::SimpleString(value) => write!(socket, "+{value}\r\n")?,
        redis::Value::BulkString(value) => {
            anyhow::ensure!(value.len() <= 32768, "setup reply budget");
            write!(socket, "${}\r\n", value.len())?;
            socket.write_all(&value)?;
            socket.write_all(b"\r\n")?;
        }
        _ => anyhow::bail!("unexpected setup response"),
    }
    Ok(())
}
