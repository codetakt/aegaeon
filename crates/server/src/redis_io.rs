//! Synchronous store facade over an owned, deadline-bounded asynchronous driver.
use redis::{Cmd, ConnectionLike, Pipeline, RedisResult, Value};
use std::sync::{mpsc, Arc, LazyLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc as channel, Semaphore};

mod driver;
pub(crate) mod organization;
mod packed;
#[cfg(test)]
mod tests;

const OPERATION: Duration = Duration::from_secs(5);
const LIFETIME: Duration = Duration::from_secs(30);
static OWNERS: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(32)));

enum Request {
    Single(Cmd),
    Pipeline(Pipeline, usize, usize),
}

struct Message {
    request: Request,
    deadline: Instant,
    reply: mpsc::SyncSender<RedisResult<Value>>,
}

pub(crate) struct Connection {
    sender: channel::Sender<Message>,
    deadline: Instant,
    operation: Duration,
    db: i64,
    open: bool,
    owner: organization::Owner,
}

fn unavailable(message: &'static str) -> redis::RedisError {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message).into()
}

pub(crate) fn connect(client: &redis::Client) -> RedisResult<Connection> {
    connect_with(client, OWNERS.clone(), OPERATION, LIFETIME)
}

fn connect_with(
    client: &redis::Client,
    owners: Arc<Semaphore>,
    operation: Duration,
    lifetime: Duration,
) -> RedisResult<Connection> {
    let owner = organization::Owner::capture();
    owner.ensure_open()?;
    let permit = owners
        .try_acquire_owned()
        .map_err(|_| unavailable("Redis connection capacity unavailable"))?;
    let deadline = Instant::now() + lifetime;
    let (sender, receiver) = channel::channel(1);
    let (ready, response) = mpsc::sync_channel(1);
    let client = client.clone();
    let db = client.get_connection_info().redis.db;
    let driver_owner = owner.clone();
    std::thread::Builder::new()
        .name("redis-io".into())
        .spawn(move || {
            // Drop order matters: Tokio waits for uncancellable resolver work
            // before the owner releases its capacity.
            let _permit = permit;
            driver::run(client, receiver, ready, operation, deadline, driver_owner);
        })?;
    response
        .recv_timeout(operation.min(deadline.saturating_duration_since(Instant::now())))
        .map_err(|_| unavailable("Redis connection preparation deadline"))??;
    Ok(Connection {
        sender,
        deadline,
        operation,
        db,
        open: true,
        owner,
    })
}

impl Connection {
    fn request(&mut self, request: Request) -> RedisResult<Value> {
        self.owner.ensure_open()?;
        if !self.is_open() {
            return Err(unavailable("Redis connection closed"));
        }
        let deadline = self.deadline.min(Instant::now() + self.operation);
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .try_send(Message {
                request,
                deadline,
                reply,
            })
            .map_err(|_| unavailable("Redis connection worker unavailable"))?;
        let result = response
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| unavailable("Redis operation deadline"))
            .and_then(std::convert::identity);
        if result.as_ref().is_err_and(redis::RedisError::is_io_error) {
            self.open = false;
            self.owner.close();
        }
        result
    }
}

impl ConnectionLike for Connection {
    fn req_command(&mut self, cmd: &Cmd) -> RedisResult<Value> {
        self.request(Request::Single(cmd.clone()))
    }

    fn req_packed_command(&mut self, bytes: &[u8]) -> RedisResult<Value> {
        self.req_command(&packed::single(bytes)?)
    }

    fn req_packed_commands(
        &mut self,
        bytes: &[u8],
        offset: usize,
        count: usize,
    ) -> RedisResult<Vec<Value>> {
        match self.request(Request::Pipeline(packed::pipeline(bytes)?, offset, count))? {
            Value::Array(values) => Ok(values),
            _ => Err((
                redis::ErrorKind::TypeError,
                "Invalid Redis pipeline response",
            )
                .into()),
        }
    }

    fn get_db(&self) -> i64 {
        self.db
    }

    fn check_connection(&mut self) -> bool {
        redis::cmd("PING").query::<String>(self).is_ok()
    }

    fn is_open(&self) -> bool {
        self.open && !self.sender.is_closed() && Instant::now() < self.deadline
    }
}
