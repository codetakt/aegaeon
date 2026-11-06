use super::*;
use std::io::{BufRead, Read};

struct KillAtFirstRow {
    source: Cursor<Vec<u8>>,
    header_bytes: u64,
    signal: Option<tokio::sync::oneshot::Sender<()>>,
    killed: std::sync::mpsc::Receiver<()>,
}
impl BufRead for KillAtFirstRow {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.source.position() >= self.header_bytes {
            if let Some(signal) = self.signal.take() {
                signal
                    .send(())
                    .map_err(|()| std::io::Error::other("kill task stopped"))?;
                self.killed
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .map_err(|_| std::io::Error::other("kill was not acknowledged"))?;
            }
        }
        self.source.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.source.consume(amount);
    }
}
impl Read for KillAtFirstRow {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let count = {
            let ready = self.fill_buf()?;
            let count = out.len().min(ready.len());
            out[..count].copy_from_slice(&ready[..count]);
            count
        };
        self.consume(count);
        Ok(count)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires restricted PostgreSQL; kill actual owned staging backend and recover"]
async fn pg_organizations_import_source_store_loss_never_changes_authority_and_recovers(
) -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let bytes = export(&f).await?;
        let before: Value = sqlx::query_scalar(
            "SELECT to_jsonb(o) FROM aegaeon.application_organizations o WHERE id=$1",
        )
        .bind(f.organization.id)
        .fetch_one(&f.pool)
        .await?;
        let mut supplier = connection(&f).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut supplier)
            .await?;
        let (signal, ready) = tokio::sync::oneshot::channel();
        let (ack, killed) = std::sync::mpsc::channel();
        let killer_pool = f.pool.clone();
        let killer = tokio::spawn(async move {
            ready.await.expect("input must reach the first staged row");
            let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
                .bind(pid)
                .fetch_one(&killer_pool)
                .await
                .expect("terminate owned backend");
            assert!(killed);
            ack.send(()).expect("input must await the kill receipt");
        });
        let source = KillAtFirstRow {
            source: Cursor::new(bytes.clone()),
            header_bytes: bytes.iter().position(|b| *b == b'\n').ok_or("header")? as u64 + 1,
            signal: Some(signal),
            killed,
        };
        let input = Input::new(source, f.organization.scope, &sha256_hex(&bytes))?;
        assert!(staging::inspect_source(supplier, input).await.is_err());
        killer.await?;
        let after: Value = sqlx::query_scalar(
            "SELECT to_jsonb(o) FROM aegaeon.application_organizations o WHERE id=$1",
        )
        .bind(f.organization.id)
        .fetch_one(&f.pool)
        .await?;
        assert_eq!(before, after);
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)")
                .bind(pid)
                .fetch_one(&f.pool)
                .await?;
        assert!(!present);
        assert!(inspect(&f, &bytes).await.is_ok());
        let without_manifest = bytes.rsplitn(3, |b| *b == b'\n').last().ok_or("prefix")?;
        assert!(inspect(&f, without_manifest).await.is_err());
        assert!(inspect(&f, &bytes).await.is_ok());
        Ok(())
    }
    .await;
    f.cleanup(result).await
}
