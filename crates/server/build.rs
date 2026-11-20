//! Extract source-bound SQL components at build time; malformed or missing
//! components prevent compilation rather than panicking during server startup.
use std::{collections::BTreeSet, env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let mut names = BTreeSet::new();
    let migrations = [
        "../../db/migrations/20261105000000_organizations.sql",
        "../../db/migrations/20261112000000_notification_outbox.sql",
        "../../db/migrations/20261120000000_organization_display.sql",
    ];
    for migration in migrations {
        println!("cargo:rerun-if-changed={migration}");
        let source = fs::read_to_string(migration)?;
        for component in source.split("-- BEGIN ORGANIZATIONS COMPONENT ").skip(1) {
            let (name, body) = component.split_once('\n').ok_or("missing component name")?;
            if name.is_empty()
                || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                || !names.insert(name.to_owned())
            {
                return Err("invalid or duplicate SQL component".into());
            }
            let end = format!("-- END ORGANIZATIONS COMPONENT {name}\n");
            let (sql, _) = body.split_once(&end).ok_or("incomplete SQL component")?;
            if sql.contains("-- END ORGANIZATIONS COMPONENT ") {
                return Err("mismatched SQL component terminator".into());
            }
            fs::write(output.join(format!("{name}.sql")), sql)?;
        }
    }
    if names.is_empty() {
        return Err("missing Organizations SQL components".into());
    }
    Ok(())
}
