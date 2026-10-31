use super::*;
use aegaeon_crypto::hash::Sha256Hasher;
use std::fs::File;

pub(super) async fn scan(
    control: &mut Control,
    scope: Scope,
    command: &Command,
    mut file: Option<&mut File>,
    plan: Option<&Plan>,
) -> anyhow::Result<(Progress, String)> {
    let mut page = control
        .history_read(
            scope,
            command.operation_id,
            command.expected_revision,
            0,
            BATCH_ENTRIES as u32,
        )
        .await?;
    let fixed = serde_json::to_value(&page.progress)?;
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0u64;
    write(
        &mut file,
        &mut hash,
        &mut bytes,
        &json!({"version":1,"history":fixed}),
    )?;
    let mut sequence = 0;
    let mut owners = 0;
    let mut subjects = 0;
    let mut previous = hex(&initial_digest(
        scope.environment_id,
        &page.progress.issuer_host,
    )?);
    loop {
        anyhow::ensure!(
            serde_json::to_value(&page.progress)? == fixed,
            "history changed during inspection"
        );
        for entry in &page.entries {
            anyhow::ensure!(
                entry.previous_digest == previous,
                "history page link differs"
            );
            if let Some(plan) = plan {
                let expected = plan
                    .entries
                    .get(usize::try_from(sequence)?)
                    .ok_or_else(|| anyhow::anyhow!("history exceeds plan"))?;
                let kind = match expected.kind {
                    super::super::Kind::Owner => "owner",
                    super::super::Kind::Reservation => "reservation",
                };
                anyhow::ensure!(
                    entry.kind == kind
                        && entry.owner_id == expected.owner_id
                        && entry.subject == expected.subject,
                    "history entry differs from plan"
                );
            }
            if entry.kind == "owner" {
                owners += 1;
            } else {
                subjects += 1;
            }
            sequence += 1;
            previous.clone_from(&entry.digest);
            write(&mut file, &mut hash, &mut bytes, entry)?;
        }
        if sequence == page.progress.sequence {
            break;
        }
        page = control
            .history_read(
                scope,
                command.operation_id,
                command.expected_revision,
                sequence,
                BATCH_ENTRIES as u32,
            )
            .await?;
    }
    anyhow::ensure!(
        owners == page.progress.owner_count
            && subjects == page.progress.subject_count
            && previous == page.progress.digest,
        "history counts or head differ"
    );
    Ok((page.progress, hex(&hash.finalize())))
}

fn write(
    file: &mut Option<&mut File>,
    hash: &mut Sha256Hasher,
    total: &mut u64,
    value: &impl serde::Serialize,
) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    *total = total
        .checked_add(bytes.len() as u64)
        .filter(|n| *n <= custody::history::JOURNAL_BYTES)
        .ok_or_else(|| anyhow::anyhow!("journal byte limit"))?;
    if let Some(file) = file.as_mut() {
        file.write_all(&bytes)?;
    }
    hash.update(&bytes);
    Ok(())
}
