use super::*;
use custody::history::{InputKind, Retained};
use std::{collections::BTreeMap, path::Path};

pub(super) struct Input {
    pub plan: Plan,
    files: Vec<Retained>,
}
impl Input {
    pub fn recheck(&mut self, output: &Artifacts) -> anyhow::Result<()> {
        for file in &mut self.files {
            file.recheck(output)?;
        }
        Ok(())
    }
}

pub(super) fn retain(command: &Command, output: &Artifacts) -> anyhow::Result<Option<Input>> {
    let Action::Import {
        manifest,
        expected_manifest_sha256,
        inventory,
        expected_inventory_sha256,
        sources,
    } = &command.action
    else {
        return Ok(None);
    };
    anyhow::ensure!(sources.len() <= 256, "source count limit");
    let mut manifest = output.retain_history(
        InputKind::Manifest,
        manifest,
        expected_manifest_sha256,
        None,
    )?;
    let mut inventory = output.retain_history(
        InputKind::Inventory,
        inventory,
        expected_inventory_sha256,
        None,
    )?;
    let plan = Plan::from_artifacts(
        &manifest.bytes(64 * 1024 * 1024)?,
        &inventory.bytes(256 * 1024 * 1024)?,
        expected_manifest_sha256,
        expected_inventory_sha256,
    )?;
    anyhow::ensure!(
        plan.environment_id == command.environment_id && plan.sources.len() <= 256,
        "source namespace or count"
    );
    let mut paths = BTreeMap::new();
    for source in sources {
        let (name, path) = source
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("source mapping syntax"))?;
        anyhow::ensure!(
            !path.is_empty() && !name.is_empty() && paths.insert(name, Path::new(path)).is_none(),
            "duplicate or empty source mapping"
        );
    }
    anyhow::ensure!(
        paths.len() == plan.sources.len()
            && plan
                .sources
                .iter()
                .all(|s| paths.contains_key(s.source_id.as_str())),
        "source mappings differ"
    );
    plan.sources
        .iter()
        .try_fold(0u64, |sum, s| {
            sum.checked_add(s.byte_length)
                .filter(|total| *total <= 64 * 1024 * 1024 * 1024)
        })
        .ok_or_else(|| anyhow::anyhow!("source byte budget"))?;
    let mut files = vec![manifest, inventory];
    for (index, source) in plan.sources.iter().enumerate() {
        files.push(output.retain_history(
            InputKind::Source(u8::try_from(index)?),
            paths[source.source_id.as_str()],
            &source.sha256,
            Some(source.byte_length),
        )?);
    }
    Ok(Some(Input { plan, files }))
}
