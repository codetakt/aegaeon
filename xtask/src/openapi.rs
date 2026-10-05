use std::{fs, path::Path};

pub(crate) fn run(repo_root: &Path, check: bool) -> anyhow::Result<()> {
    let out_dir = repo_root.join("generated/openapi");
    fs::create_dir_all(&out_dir)?;

    let management = aegaeon_server::openapi::management_openapi();
    let ops = aegaeon_server::openapi::ops_openapi();

    let management_path = out_dir.join("aegaeon-management-api.v1.json");
    let ops_path = out_dir.join("aegaeon-ops.v1.json");

    let management_json = format!("{}\n", serde_json::to_string_pretty(&management)?);
    let ops_json = format!("{}\n", serde_json::to_string_pretty(&ops)?);

    write_or_check(&management_path, &management_json, check)?;
    write_or_check(&ops_path, &ops_json, check)?;

    if check {
        println!("checked {}", management_path.display());
        println!("checked {}", ops_path.display());
    } else {
        println!("wrote {}", management_path.display());
        println!("wrote {}", ops_path.display());
    }
    Ok(())
}

fn write_or_check(path: &Path, contents: &str, check: bool) -> anyhow::Result<()> {
    if check {
        let existing = fs::read_to_string(path).unwrap_or_default();
        if existing != contents {
            anyhow::bail!("OpenAPI artifact is out of date: {}", path.display());
        }
        return Ok(());
    }
    fs::write(path, contents)?;
    Ok(())
}
