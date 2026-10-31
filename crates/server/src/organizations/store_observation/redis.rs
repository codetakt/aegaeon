use super::{Error, Result, DEADLINE};
use ::redis::aio::MultiplexedConnection;
use std::collections::BTreeMap;

/// Actual server incarnation and actual selected database, not URL metadata.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RedisObservation {
    run_id: String,
    database: u32,
}
impl RedisObservation {
    pub fn same_incarnation(&self, other: &Self) -> bool {
        self == other
    }
}

/// The caller must own every clone and supply verified transport and ACLs.
/// The observation itself cannot establish these supplier preconditions.
pub struct Redis {
    connection: Option<MultiplexedConnection>,
    observed: RedisObservation,
}
impl Redis {
    pub async fn observe(mut connection: MultiplexedConnection) -> Result<Self> {
        let observed = tokio::time::timeout(DEADLINE, read(&mut connection))
            .await
            .map_err(|_| Error::Deadline)??;
        Ok(Self {
            connection: Some(connection),
            observed,
        })
    }
    pub fn observation(&self) -> &RedisObservation {
        &self.observed
    }
    pub async fn recheck(&mut self, expected: &RedisObservation) -> Result<()> {
        let mut connection = self.connection.take().ok_or(Error::Refused)?;
        let current = tokio::time::timeout(DEADLINE, read(&mut connection))
            .await
            .map_err(|_| Error::Deadline)??;
        if !current.same_incarnation(expected) || !current.same_incarnation(&self.observed) {
            return Err(Error::Refused);
        }
        self.observed = current;
        self.connection = Some(connection);
        Ok(())
    }
    pub fn close(mut self) {
        self.connection.take();
    }
}

async fn read(connection: &mut MultiplexedConnection) -> Result<RedisObservation> {
    let server: String = ::redis::cmd("INFO")
        .arg("server")
        .arg("replication")
        .query_async(connection)
        .await?;
    let client: String = ::redis::cmd("CLIENT")
        .arg("INFO")
        .query_async(connection)
        .await?;
    parse(&server, &client)
}

fn fields(value: &str, client: bool) -> Result<BTreeMap<&str, &str>> {
    if value.len() > 32_768 || !value.is_ascii() || value.as_bytes().contains(&0) {
        return Err(Error::Refused);
    }
    let mut result = BTreeMap::new();
    let parts: Box<dyn Iterator<Item = &str>> = if client {
        Box::new(value.split_ascii_whitespace())
    } else {
        Box::new(
            value
                .lines()
                .filter(|line| !line.is_empty() && !line.starts_with('#')),
        )
    };
    for part in parts {
        let (key, value) = part
            .split_once(if client { '=' } else { ':' })
            .ok_or(Error::Refused)?;
        if key.is_empty()
            || part.len() > 1024
            || result.insert(key, value).is_some()
            || result.len() > 256
        {
            return Err(Error::Refused);
        }
    }
    Ok(result)
}

fn parse(server: &str, client: &str) -> Result<RedisObservation> {
    let server = fields(server, false)?;
    let client = fields(client, true)?;
    let run_id = *server.get("run_id").ok_or(Error::Refused)?;
    let database = *client.get("db").ok_or(Error::Refused)?;
    if server.get("redis_mode") != Some(&"standalone")
        || server.get("role") != Some(&"master")
        || run_id.len() != 40
        || !run_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || database.is_empty()
        || !database.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Refused);
    }
    Ok(RedisObservation {
        run_id: run_id.to_owned(),
        database: database.parse().map_err(|_| Error::Refused)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn store_observation_redis_requires_unambiguous_primary_and_actual_database() {
        let server = format!(
            "# Server\r\nrun_id:{}\r\nredis_mode:standalone\r\nrole:master\r\nfuture:ignored\r\n",
            "a".repeat(40)
        );
        assert_eq!(parse(&server, "id=17 db=3 name=").unwrap().database, 3);
        for changed in [
            server.replace("master", "slave"),
            server.replace("standalone", "cluster"),
            server.replace("run_id:", "unknown:"),
            format!("{server}run_id:{}\r\n", "b".repeat(40)),
            server.replace(&"a".repeat(40), &"A".repeat(40)),
            format!("{server}invalid"),
            format!("{server}x:{}", "x".repeat(32_768)),
        ] {
            assert!(parse(&changed, "db=3").is_err());
        }
        for client in [
            "",
            "db=-1",
            "db=+1",
            "db=3 db=4",
            "db=4294967296",
            "db=3\0",
            "db=三",
        ] {
            assert!(parse(&server, client).is_err(), "{client}");
        }
    }
}
