use super::*;

pub(super) fn run(
    client: redis::Client,
    receiver: channel::Receiver<Message>,
    ready: mpsc::SyncSender<RedisResult<()>>,
    operation: Duration,
    deadline: Instant,
    owner: organization::Owner,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = ready.send(Err(error.into()));
            return;
        }
    };
    runtime.block_on(serve(client, receiver, ready, operation, deadline, &owner));
    // Do not use shutdown_background/timeout: unfinished DNS still owns capacity.
    drop(runtime);
    drop(owner);
}

async fn serve(
    client: redis::Client,
    mut receiver: channel::Receiver<Message>,
    ready: mpsc::SyncSender<RedisResult<()>>,
    operation: Duration,
    deadline: Instant,
    owner: &organization::Owner,
) {
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(operation)
        .set_response_timeout(operation);
    let setup = client.get_multiplexed_async_connection_with_config(&config);
    let connection = tokio::time::timeout_at(deadline.into(), setup).await;
    let mut connection = match connection {
        Ok(Ok(connection)) => connection,
        other => {
            let error = match other {
                Ok(Err(error)) => error,
                _ => unavailable("Redis connection lifetime expired"),
            };
            let _ = ready.send(Err(error));
            return;
        }
    };
    if ready.send(Ok(())).is_err() {
        return;
    }
    while let Ok(Some(message)) = tokio::time::timeout_at(deadline.into(), receiver.recv()).await {
        if Instant::now() >= message.deadline {
            break;
        }
        if owner.ensure_open().is_err() {
            break;
        }
        let mut pending = organization::Pending::new(owner);
        let operation = async {
            let result = execute(&mut connection, message.request).await;
            if owner.scoped() {
                let barrier: String = redis::cmd("PING").query_async(&mut connection).await?;
                if barrier != "PONG" {
                    return Err(unavailable("Redis completion barrier refused"));
                }
            }
            pending.confirm();
            result
        };
        let result = tokio::time::timeout_at(message.deadline.into(), operation)
            .await
            .unwrap_or_else(|_| Err(unavailable("Redis operation deadline")));
        let failed_transport = result.as_ref().is_err_and(redis::RedisError::is_io_error);
        if message.reply.send(result).is_err() || failed_transport {
            break;
        }
    }
}

async fn execute(
    connection: &mut redis::aio::MultiplexedConnection,
    request: Request,
) -> RedisResult<Value> {
    match request {
        Request::Single(command) => connection.send_packed_command(&command).await,
        Request::Pipeline(pipeline, offset, count) => connection
            .send_packed_commands(&pipeline, offset, count)
            .await
            .map(Value::Array),
    }
}
