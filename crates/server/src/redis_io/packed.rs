use super::*;

fn invalid() -> redis::RedisError {
    (
        redis::ErrorKind::ClientError,
        "Noncanonical local Redis request",
    )
        .into()
}

fn commands(bytes: &[u8]) -> RedisResult<Vec<Cmd>> {
    let mut parser = redis::Parser::new();
    let mut reader = std::io::Cursor::new(bytes);
    let mut commands = Vec::new();
    let mut consumed = 0;
    while consumed < bytes.len() {
        let Value::Array(arguments) = parser.parse_value(&mut reader)? else {
            return Err(invalid());
        };
        if arguments.is_empty() {
            return Err(invalid());
        }
        let mut command = Cmd::new();
        for argument in arguments {
            let Value::BulkString(argument) = argument else {
                return Err(invalid());
            };
            command.arg(argument);
        }
        let packed = command.get_packed_command();
        if !bytes[consumed..].starts_with(&packed) {
            return Err(invalid());
        }
        consumed += packed.len();
        commands.push(command);
    }
    Ok(commands)
}

pub(super) fn single(bytes: &[u8]) -> RedisResult<Cmd> {
    let mut commands = commands(bytes)?;
    if commands.len() != 1 {
        return Err(invalid());
    }
    commands.pop().ok_or_else(invalid)
}

pub(super) fn pipeline(bytes: &[u8]) -> RedisResult<Pipeline> {
    let mut commands = commands(bytes)?;
    let transaction = commands
        .first()
        .is_some_and(|c| c.get_packed_command() == redis::cmd("MULTI").get_packed_command())
        && commands
            .last()
            .is_some_and(|c| c.get_packed_command() == redis::cmd("EXEC").get_packed_command());
    let mut pipeline = redis::pipe();
    if transaction {
        commands.remove(0);
        commands.pop();
        pipeline.atomic();
    }
    for command in commands {
        pipeline.add_command(command);
    }
    if pipeline.get_packed_pipeline() != bytes {
        return Err(invalid());
    }
    Ok(pipeline)
}
