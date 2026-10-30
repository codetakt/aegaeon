use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

fn wait_released(owners: &Semaphore) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while owners.available_permits() == 0 {
        assert!(
            Instant::now() < deadline,
            "actual connection owner must finish"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn redis_io_stalled_setup_has_deadline_and_releases_actual_owner() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).unwrap() > 0);
        // Never answer setup. Timeout must close the transport, not merely
        // stop the caller waiting while leaving its owner alive.
        while socket.read(&mut bytes).unwrap() != 0 {}
    });
    let owners = Arc::new(Semaphore::new(1));
    let result = connect_with(
        &client,
        owners.clone(),
        Duration::from_millis(200),
        Duration::from_secs(2),
    );
    assert!(result.is_err());
    peer.join().unwrap();
    wait_released(&owners);
}

#[test]
fn redis_io_stalled_mutation_is_not_retried_and_connection_is_poisoned() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let (observed, receipt) = mpsc::sync_channel(1);
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut parser = redis::Parser::new();
        let mut mutations = 0;
        while let Ok(Value::Array(arguments)) = parser.parse_value(&mut socket) {
            match arguments.first() {
                Some(Value::BulkString(command)) if command == b"SET" => {
                    mutations += 1;
                    observed.send(()).unwrap();
                    // Mutation happened, but its acknowledgement is lost.
                }
                _ => socket.write_all(b"+OK\r\n").unwrap(),
            }
        }
        mutations
    });
    let owners = Arc::new(Semaphore::new(1));
    let mut connection = connect_with(
        &client,
        owners.clone(),
        Duration::from_millis(200),
        Duration::from_secs(2),
    )
    .unwrap();
    let error = redis::cmd("SET")
        .arg("key")
        .arg("value")
        .query::<()>(&mut connection)
        .unwrap_err();
    assert!(error.is_io_error());
    receipt.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(!connection.is_open());
    assert!(redis::cmd("SET")
        .arg("key")
        .arg("value")
        .query::<()>(&mut connection)
        .is_err());
    assert_eq!(peer.join().unwrap(), 1);
    wait_released(&owners);
}

#[test]
fn redis_io_exhausted_capacity_refuses_before_network() {
    let client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
    assert!(connect_with(&client, Arc::new(Semaphore::new(0)), OPERATION, LIFETIME).is_err());
}

#[test]
fn redis_io_reconstructs_binary_and_atomic_pipeline_without_changing_wire() {
    for atomic in [false, true] {
        let mut original = redis::pipe();
        if atomic {
            original.atomic();
        }
        original
            .cmd("SET")
            .arg(b"key\0\xff")
            .arg(b"value\r\n\0")
            .ignore();
        original.cmd("GET").arg(b"key\0\xff");
        let bytes = original.get_packed_pipeline();
        let reconstructed = packed::pipeline(&bytes).unwrap();
        assert_eq!(reconstructed.get_packed_pipeline(), bytes);
        assert!(packed::single(&bytes).is_err());
    }
    for invalid in [
        b"*1\r\n+PING\r\n".as_slice(),
        b"*0\r\n",
        b"*1\r\n$4\r\nPING\r\ntrailing",
    ] {
        assert!(packed::pipeline(invalid).is_err());
    }
}

#[test]
#[ignore = "requires AEGAEON_TEST_REDIS_URL"]
fn redis_io_actual_atomic_pipeline_scripts_and_database_selection() {
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL").unwrap()).unwrap();
    let mut connection = connect(&client).unwrap();
    let key = format!("bounded-redis:{}", uuid::Uuid::new_v4());
    let mut pipeline = redis::pipe();
    pipeline
        .atomic()
        .cmd("SET")
        .arg(&key)
        .arg(b"\0\xff\r\n")
        .ignore();
    pipeline.cmd("GET").arg(&key);
    let (value,): (Vec<u8>,) = pipeline.query(&mut connection).unwrap();
    assert_eq!(value, b"\0\xff\r\n");
    let deleted: i64 = redis::Script::new("return redis.call('DEL', KEYS[1])")
        .key(&key)
        .invoke(&mut connection)
        .unwrap();
    assert_eq!(deleted, 1);
    assert!(connection.check_connection());
    assert_eq!(connection.get_db(), client.get_connection_info().redis.db);
}

fn accept(listener: &TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((socket, _)) => return socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "owned peer accept deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("owned peer: {error}"),
        }
    }
}

#[test]
fn redis_io_idle_lifetime_closes_transport_before_releasing_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        redis::Client::open(format!("redis://{}/", listener.local_addr().unwrap())).unwrap();
    let peer = std::thread::spawn(move || {
        let mut socket = accept(&listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut parser = redis::Parser::new();
        while parser.parse_value(&mut socket).is_ok() {
            socket.write_all(b"+OK\r\n").unwrap();
        }
    });
    let owners = Arc::new(Semaphore::new(1));
    let mut connection = connect_with(
        &client,
        owners.clone(),
        Duration::from_secs(1),
        Duration::from_millis(300),
    )
    .unwrap();
    assert!(connect_with(&client, owners.clone(), OPERATION, LIFETIME).is_err());
    wait_released(&owners);
    assert!(!connection.is_open());
    assert!(!connection.check_connection());
    peer.join().unwrap();
}
