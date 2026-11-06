use super::*;
use std::{path::PathBuf, sync::mpsc, time::Duration};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("aegaeon-ca-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn organization_ca_read_preserves_regular_file_links_and_byte_bounds() {
    let fixture = Fixture::new();
    let file = fixture.0.join("ca.pem");
    let link = fixture.0.join("current.pem");
    std::fs::write(&file, b"retained CA bytes").unwrap();
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_eq!(certificate(&link).unwrap(), b"retained CA bytes");
    assert_eq!(certificate(&file).unwrap(), b"retained CA bytes");
    std::fs::write(&file, vec![b'x'; 1_048_576]).unwrap();
    assert_eq!(certificate(&link).unwrap().len(), 1_048_576);
    std::fs::write(&file, vec![b'x'; 1_048_577]).unwrap();
    assert!(certificate(&link).is_err());
    std::fs::write(&file, []).unwrap();
    assert!(certificate(&link).is_err());
}

#[test]
fn organization_ca_read_refuses_fifo_without_waiting_for_a_writer() {
    let fixture = Fixture::new();
    assert!(certificate(&fixture.0).is_err());
    assert!(certificate(Path::new("/dev/null")).is_err());
    let fifo = fixture.0.join("fifo");
    fs::mkfifoat(fs::CWD, &fifo, Mode::RUSR | Mode::WUSR).unwrap();
    let input = fifo.clone();
    let (send, receive) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ = send.send(certificate(&input).is_err());
    });
    let initial = receive.recv_timeout(Duration::from_secs(1));
    let returned_without_writer = initial.is_ok();
    let refused = match initial {
        Ok(refused) => refused,
        Err(_) => {
            // Unblock the old implementation before reporting the regression.
            // RDWR/NONBLOCK cannot itself wait for the reader to start.
            let release = fs::open(&fifo, OFlags::RDWR | OFlags::NONBLOCK, Mode::empty()).unwrap();
            let refused = receive.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(release);
            refused
        }
    };
    worker.join().unwrap();
    assert!(refused, "a FIFO must never supply CA bytes");
    assert!(returned_without_writer, "CA open waited for a FIFO writer");
}
