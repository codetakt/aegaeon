use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

struct SocketDirectory(PathBuf);

impl Drop for SocketDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(reader: &mut BufReader<UnixStream>) -> Vec<Vec<u8>> {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let count: usize = line.strip_prefix('*').unwrap().trim().parse().unwrap();
    assert!(count <= 16);
    (0..count)
        .map(|_| {
            line.clear();
            reader.read_line(&mut line).unwrap();
            let size: usize = line.strip_prefix('$').unwrap().trim().parse().unwrap();
            assert!(size <= 4096);
            let mut value = vec![0; size + 2];
            reader.read_exact(&mut value).unwrap();
            assert_eq!(&value[size..], b"\r\n");
            value.truncate(size);
            value
        })
        .collect()
}

fn invoke_with_reply(reply: &'static [u8]) -> Result<bool, JwksSharedStateError> {
    let directory = SocketDirectory(
        std::env::temp_dir().join(format!("aegaeon-ledger-reply-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let socket = directory.0.join("reply.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut caller = loop {
            match listener.accept() {
                Ok((caller, _)) => break caller,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Redis client did not connect");
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        };
        caller
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        caller
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut requests = BufReader::new(caller.try_clone().unwrap());
        // The pinned RESP2 client sends two CLIENT SETINFO commands on connect.
        for _ in 0..2 {
            let setup = request(&mut requests);
            assert_eq!(setup[0], b"CLIENT");
            assert_eq!(setup[1], b"SETINFO");
            caller.write_all(b"+OK\r\n").unwrap();
        }
        let invocation = request(&mut requests);
        assert_eq!(invocation[0], b"EVALSHA");
        assert_eq!(invocation[2], b"1");
        caller.write_all(reply).unwrap();
    });
    let state = RedisJwksRuntimeState::new_for_tests(&format!("redis+unix://{}", socket.display()))
        .unwrap();
    let result = state.record_kid_fingerprints(
        &JwksRuntimePolicy::default(),
        "https://example.com/keys.json",
        &HashMap::from([("kid".to_owned(), "fingerprint".to_owned())]),
    );
    server.join().unwrap();
    result
}

#[test]
fn noninteger_success_reply_is_rejected() {
    for reply in [b"+0\r\n".as_slice(), b"$1\r\n1\r\n"] {
        assert!(matches!(
            invoke_with_reply(reply),
            Err(JwksSharedStateError::BackendUnavailable(_))
        ));
    }
}

#[test]
fn only_zero_and_one_integer_replies_are_accepted() {
    assert!(!invoke_with_reply(b":0\r\n").unwrap());
    assert!(invoke_with_reply(b":1\r\n").unwrap());
    for reply in [
        b":2\r\n".as_slice(),
        b":-1\r\n",
        b":4294967296\r\n",
        b"$-1\r\n",
    ] {
        assert!(matches!(
            invoke_with_reply(reply),
            Err(JwksSharedStateError::BackendUnavailable(_))
        ));
    }
}
