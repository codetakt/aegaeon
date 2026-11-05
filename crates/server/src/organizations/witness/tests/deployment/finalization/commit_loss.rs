//! Bound the exact finalizer COMMIT transport boundary on one owned connection.
use super::*;
use crate::organizations::request_work::tests::proxy;
use sqlx::postgres::PgConnectOptions;
use std::{
    io,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    task::JoinHandle,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    BeforeCommit,
    AfterCommit,
}

struct CommitProxy {
    address: SocketAddr,
    armed: Arc<AtomicBool>,
    receipt: Option<oneshot::Receiver<Boundary>>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for CommitProxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn invalid_frame() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "owned COMMIT proxy frame refused",
    )
}

async fn startup<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = reader.read_u32().await?;
    if !(8..=65_536).contains(&length) {
        return Err(invalid_frame());
    }
    let mut bytes = vec![0; length as usize];
    bytes[..4].copy_from_slice(&length.to_be_bytes());
    reader.read_exact(&mut bytes[4..]).await?;
    // client_options explicitly disables TLS for this local disposable supplier.
    // Refuse SSL/GSS negotiation and protocol revisions this relay cannot frame.
    if bytes[4..8] != 196_608_u32.to_be_bytes() {
        return Err(invalid_frame());
    }
    Ok(bytes)
}

async fn frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0; 5];
    reader.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header[1..].try_into().map_err(|_| invalid_frame())?);
    // At most two frames are resident, one per direction. In particular, never
    // allocate from an unbounded peer-supplied length during authentication.
    if !(4..=8_388_608).contains(&length) {
        return Err(invalid_frame());
    }
    let mut bytes = vec![0; length as usize + 1];
    bytes[..5].copy_from_slice(&header);
    reader.read_exact(&mut bytes[5..]).await?;
    Ok(bytes)
}

fn commit_request(bytes: &[u8]) -> bool {
    let body = &bytes[5..];
    match bytes[0] {
        b'Q' => body == b"COMMIT\0",
        b'P' => {
            // This fresh SQLx control connection has never prepared COMMIT.
            // Stop before its Parse reaches the server, so no later Bind or
            // Execute can apply it. Do not search arbitrary parameter bytes.
            let mut fields = body.split(|byte| *byte == 0);
            fields.next().is_some() && fields.next() == Some(b"COMMIT".as_slice())
        }
        _ => false,
    }
}

impl CommitProxy {
    async fn start(options: PgConnectOptions, boundary: Boundary) -> io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let armed = Arc::new(AtomicBool::new(false));
        let relay_armed = armed.clone();
        let (receipt, receipt_rx) = oneshot::channel();
        let (stop, mut stop_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(45), async move {
                let (client, _) = listener.accept().await?;
                let upstream = proxy::upstream(&options).await?;
                let (mut client_read, mut client_write) = client.into_split();
                let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
                upstream_write
                    .write_all(&startup(&mut client_read).await?)
                    .await?;
                let (mut before, mut after) = match boundary {
                    Boundary::BeforeCommit => (Some(receipt), None),
                    Boundary::AfterCommit => (None, Some(receipt)),
                };
                let upload = async {
                    loop {
                        let bytes = frame(&mut client_read).await?;
                        if relay_armed.load(Ordering::Acquire) && commit_request(&bytes) {
                            if let Some(receipt) = before.take() {
                                let _ = receipt.send(Boundary::BeforeCommit);
                                return Ok::<(), io::Error>(());
                            }
                        }
                        upstream_write.write_all(&bytes).await?;
                    }
                };
                let download = async {
                    loop {
                        let bytes = frame(&mut upstream_read).await?;
                        if relay_armed.load(Ordering::Acquire)
                            && bytes[0] == b'C'
                            && &bytes[5..] == b"COMMIT\0"
                        {
                            if let Some(receipt) = after.take() {
                                let _ = receipt.send(Boundary::AfterCommit);
                                return Ok::<(), io::Error>(());
                            }
                        }
                        client_write.write_all(&bytes).await?;
                    }
                };
                // Neither direction is detached. Returning at the selected
                // boundary drops all four halves before the task completes.
                tokio::select! {
                    biased;
                    _ = &mut stop_rx => Ok(()),
                    result = upload => result,
                    result = download => result,
                }
            })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "owned COMMIT proxy deadline"))?
        });
        Ok(Self {
            address,
            armed,
            receipt: Some(receipt_rx),
            stop: Some(stop),
            task: Some(task),
        })
    }

    async fn receipt(&mut self) -> anyhow::Result<Boundary> {
        let receipt = self
            .receipt
            .take()
            .ok_or_else(|| anyhow::anyhow!("COMMIT boundary receipt already consumed"))?;
        Ok(tokio::time::timeout(Duration::from_secs(3), receipt).await??)
    }

    async fn finish(&mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let task = self
            .task
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("COMMIT relay already joined"))?;
        match tokio::time::timeout(Duration::from_secs(3), &mut *task).await {
            Ok(result) => result??,
            Err(error) => {
                task.abort();
                let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
                return Err(error.into());
            }
        }
        self.task.take();
        Ok(())
    }
}

async fn exercise(boundary: Boundary) -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (maintenance, deployment, selected, _, _) = setup(&mut f).await?;
        let direct = f
            .options
            .clone()
            .username(&f.runtime)
            .password(&f.runtime_password);
        let mut fault = CommitProxy::start(direct.clone(), boundary).await?;
        let result: TestResult = async {
            let options = proxy::client_options(&direct, fault.address)?;
            let mut connection = PgConnection::connect_with(&options).await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut connection)
                .await?;
            let control = DeploymentControl::checked(connection, Role::Runtime).await?;
            let parent = Work::begin(
                control,
                request_work::Admission::isolated_for_test()?,
                deployment,
                &selected,
                || async {
                    store_progress::links(&mut f, 0)
                        .await
                        .map_err(|_| Error::Refused)
                },
            )
            .await?;
            let before = control_snapshot(&mut f, deployment).await?;
            let old = primary_seal(&mut f, deployment).await?;
            let probe = parent.admission().closure_probe_for_test();
            // Every constructor/admission reply has arrived. Only this actual
            // finalizer's first COMMIT is eligible for the one-shot cut.
            fault.armed.store(true, Ordering::Release);
            let completed = parent.complete().await;
            let receipt = fault.receipt().await?;
            // A before-COMMIT cut must actually end the owned backend before
            // comparing its rollback state. No cleanup guesses from lost ACKs.
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND usename=$2)",
                    )
                    .bind(pid)
                    .bind(&f.runtime)
                    .fetch_one(&mut f.owner)
                    .await?;
                    if !exists {
                        return Ok::<(), sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await??;
            anyhow::ensure!(receipt == boundary && completed.is_err() && probe.is_closed());
            let primary = primary_seal(&mut f, deployment).await?;
            let admin = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
            let mut token = token_connection(&admin).await?;
            anyhow::ensure!(primary != old && token_seal(&mut token, deployment).await? == primary);
            drop(token);
            match boundary {
                Boundary::BeforeCommit => {
                    anyhow::ensure!(control_snapshot(&mut f, deployment).await? == before);
                    anyhow::ensure!(completion_counts(&mut f, deployment).await? == (1, 0, 1, 0));
                }
                Boundary::AfterCommit => {
                    anyhow::ensure!(completion_counts(&mut f, deployment).await? == (0, 1, 0, 1));
                    let consistent: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT FROM organization_witness.deployment_store_seals s \
                         JOIN organization_witness.deployment_store_checkpoints p \
                          ON (p.deployment_id,p.epoch)=(s.deployment_id,s.epoch) \
                         JOIN organization_witness.deployment_store_completions c \
                          ON (c.deployment_id,c.epoch)=(s.deployment_id,s.epoch) \
                         JOIN organization_witness.deployment_store_observations o \
                          ON (o.deployment_id,o.epoch,o.slot,o.generation,o.worker_id,o.principal) \
                           =(c.deployment_id,c.epoch,c.slot,c.generation,c.worker_id,c.principal) \
                         JOIN organization_witness.deployment_slots w \
                          ON (w.deployment_id,w.epoch,w.slot,w.generation,w.worker_id,w.principal) \
                           =(c.deployment_id,c.epoch,c.slot,c.generation,c.worker_id,c.principal) \
                         WHERE s.deployment_id=$1 AND s.epoch=$2 AND s.seal=$3 AND c.seal=s.seal \
                          AND o.finished_wal IS NOT NULL AND p.wal_position>=o.finished_wal AND NOT w.pending)",
                    )
                    .bind(deployment.uuid())
                    .bind(selected.epoch)
                    .bind(primary)
                    .fetch_one(&mut f.owner)
                    .await?;
                    anyhow::ensure!(consistent, "applied COMMIT must retain consistent completion");
                }
            }
            Ok(())
        }
        .await;
        // Join/abort the one owned relay on every ordinary failure path, before
        // removing the disposable database and roles. Drop covers cancellation.
        let relay_cleanup = fault.finish().await;
        let close = maintenance.close().await;
        result?;
        relay_cleanup?;
        close?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis AOF; exact finalizer COMMIT cuts preserve both durable outcomes"]
async fn shared_redis_organizations_deployment_finalizer_commit_reply_loss_closes_local_capacity(
) -> TestResult {
    for boundary in [Boundary::BeforeCommit, Boundary::AfterCommit] {
        exercise(boundary).await?;
    }
    Ok(())
}
