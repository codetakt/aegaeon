use super::*;

enum DeadlineStage {
    BeforeExecution,
    DuringOperation,
}

fn deadline_error(
    request_deadline: Instant,
    lifetime_deadline: Instant,
    stage: DeadlineStage,
) -> redis::RedisError {
    // Classify the selected limit, not why the worker or transport was delayed.
    let message = match (request_deadline == lifetime_deadline, stage) {
        (false, DeadlineStage::BeforeExecution) => {
            "Redis driver request expired before execution (operation limit)"
        }
        (true, DeadlineStage::BeforeExecution) => {
            "Redis driver request expired before execution (connection lifetime limit)"
        }
        (false, DeadlineStage::DuringOperation) => {
            "Redis driver operation deadline elapsed (operation limit)"
        }
        (true, DeadlineStage::DuringOperation) => {
            "Redis driver operation deadline elapsed (connection lifetime limit)"
        }
    };
    unavailable(message)
}

fn pre_execution_error(
    request_deadline: Instant,
    lifetime_deadline: Instant,
    owner: &organization::Owner,
) -> Option<redis::RedisError> {
    if Instant::now() >= request_deadline {
        Some(deadline_error(
            request_deadline,
            lifetime_deadline,
            DeadlineStage::BeforeExecution,
        ))
    } else if owner.ensure_open().is_err() {
        Some(unavailable("Redis driver owner refused before execution"))
    } else {
        None
    }
}

pub(super) fn run(
    client: redis::Client,
    receiver: channel::Receiver<Message>,
    ready: mpsc::SyncSender<RedisResult<()>>,
    operation: Duration,
    deadline: Instant,
    preparation_deadline: Instant,
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
    runtime.block_on(serve(
        client,
        receiver,
        ready,
        operation,
        deadline,
        preparation_deadline,
        &owner,
    ));
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
    preparation_deadline: Instant,
    owner: &organization::Owner,
) {
    let setup = prepare(&client, operation, owner);
    let connection = tokio::time::timeout_at(preparation_deadline.into(), setup).await;
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
        if let Some(error) = pre_execution_error(message.deadline, deadline, owner) {
            let _ = message.reply.send(Err(error));
            break;
        }
        let mut pending = organization::Pending::new(owner);
        let operation = async {
            owner.observe(&mut connection).await?;
            let result = execute(&mut connection, message.request).await;
            if owner.scoped() {
                let barrier: String = redis::cmd("PING").query_async(&mut connection).await?;
                if barrier != "PONG" {
                    return Err(unavailable("Redis completion barrier refused"));
                }
            }
            owner.observe(&mut connection).await?;
            pending.confirm();
            result
        };
        let result = tokio::time::timeout_at(message.deadline.into(), operation)
            .await
            .unwrap_or_else(|_| {
                Err(deadline_error(
                    message.deadline,
                    deadline,
                    DeadlineStage::DuringOperation,
                ))
            });
        let failed_transport = result.as_ref().is_err_and(redis::RedisError::is_io_error);
        if message.reply.send(result).is_err() || failed_transport {
            break;
        }
    }
}

async fn prepare(
    client: &redis::Client,
    operation: Duration,
    owner: &organization::Owner,
) -> RedisResult<redis::aio::MultiplexedConnection> {
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(operation)
        .set_response_timeout(operation);
    let mut connection = client
        .get_multiplexed_async_connection_with_config(&config)
        .await?;
    if let Some(label) = owner.store_label()? {
        let mut pending = organization::Pending::new(owner);
        let response: String = redis::cmd("CLIENT")
            .arg("SETNAME")
            .arg(label)
            .query_async(&mut connection)
            .await?;
        if response != "OK" {
            return Err(unavailable("Redis work attribution refused"));
        }
        let barrier: String = redis::cmd("PING").query_async(&mut connection).await?;
        if barrier != "PONG" {
            return Err(unavailable("Redis work attribution barrier refused"));
        }
        pending.confirm();
    }
    owner.observe(&mut connection).await?;
    Ok(connection)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::organizations::request_work::Admission;

    #[test]
    fn redis_driver_pre_execution_deadline_and_owner_refusal_are_distinct() {
        let admission = Admission::isolated_for_test().unwrap();
        let owner = organization::scope(admission.clone(), organization::Owner::capture).unwrap();
        let expired = Instant::now();
        // This synthetic future is not awaited; avoid making owner refusal a
        // test of scheduling speed before a short deadline.
        let future = expired + Duration::from_secs(60);
        assert!(pre_execution_error(future, future, &owner).is_none());
        for (lifetime, expected) in [
            (
                future,
                "Redis driver request expired before execution (operation limit)",
            ),
            (
                expired,
                "Redis driver request expired before execution (connection lifetime limit)",
            ),
        ] {
            let error = pre_execution_error(expired, lifetime, &owner).unwrap();
            assert!(error.is_io_error());
            assert_eq!(error.to_string(), expected);
        }
        assert!(admission.ensure_open().is_ok());
        admission.close_until_restart();
        let error = pre_execution_error(future, future, &owner).unwrap();
        assert!(error.is_io_error());
        assert_eq!(
            error.to_string(),
            "Redis driver owner refused before execution"
        );
    }
}
