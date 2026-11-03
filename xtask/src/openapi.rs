use anyhow::Context;
use std::{fs, io::Write, path::Path};

pub(crate) fn run(repo_root: &Path, check: bool) -> anyhow::Result<()> {
    let out_dir = repo_root.join("generated/openapi");
    if !check {
        fs::create_dir_all(&out_dir)?;
    }
    let management = aegaeon_server::openapi::management_openapi();
    let ops = aegaeon_server::openapi::ops_openapi();
    for (name, value) in [
        ("aegaeon-management-api.v1.json", management),
        ("aegaeon-ops.v1.json", ops),
    ] {
        let path = out_dir.join(name);
        let contents = format!("{}\n", serde_json::to_string_pretty(&value)?);
        write_or_check(&path, &contents, check)?;
        println!(
            "{} {}",
            if check { "checked" } else { "wrote" },
            path.display()
        );
    }
    Ok(())
}

fn write_or_check(path: &Path, contents: &str, check: bool) -> anyhow::Result<()> {
    if check {
        let existing = fs::read_to_string(path)
            .with_context(|| format!("Cannot read OpenAPI artifact: {}", path.display()))?;
        anyhow::ensure!(
            existing == contents,
            "OpenAPI artifact is out of date: {}",
            path.display()
        );
        return Ok(());
    }
    let parent = path
        .parent()
        .context("OpenAPI artifact has no parent directory")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = match fs::metadata(path) {
            Ok(metadata) => metadata.permissions(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::Permissions::from_mode(0o644)
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("Cannot inspect OpenAPI artifact: {}", path.display())
                });
            }
        };
        temporary.as_file().set_permissions(permissions)?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .with_context(|| format!("Cannot replace OpenAPI artifact: {}", path.display()))?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run, write_or_check};
    use std::fs;

    #[test]
    fn management_scope_paths_preserve_uuid_schema() {
        let api = serde_json::to_value(aegaeon_server::openapi::management_openapi()).unwrap();
        let mut checked = 0;
        for (path, operations) in api["paths"].as_object().unwrap() {
            for (method, operation) in operations.as_object().unwrap() {
                for parameter in operation["parameters"].as_array().into_iter().flatten() {
                    if parameter["in"] == "path"
                        && matches!(parameter["name"].as_str(), Some("teamId" | "environmentId"))
                    {
                        assert_eq!(parameter["schema"]["type"], "string", "{method} {path}");
                        assert_eq!(parameter["schema"]["format"], "uuid", "{method} {path}");
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 0, "management scope inventory is empty");
    }

    #[test]
    fn attribute_conditional_update_documents_tag_discovery() {
        let api = serde_json::to_value(aegaeon_server::openapi::management_openapi()).unwrap();
        let path = &api["paths"]
            ["/api/v1/teams/{teamId}/environments/{environmentId}/users/{userId}/attributes"];
        assert_eq!(
            path["get"]["responses"]["200"]["headers"]["ETag"]["schema"]["type"],
            "string"
        );
        assert!(path["put"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "If-Match" && p["in"] == "header"));
        assert!(path["put"]["responses"].get("412").is_some());
        let schemas = &api["components"]["schemas"];
        let replacement = &schemas["ReplaceLocalAttributesRequest"];
        assert_eq!(replacement["additionalProperties"], false);
        assert_eq!(replacement["properties"]["baseRevision"]["minimum"], 0);
        assert_eq!(replacement["properties"]["values"]["type"], "object");
        // Omitted additionalProperties permits arbitrary JSON members.
        assert!(replacement["properties"]["values"]
            .get("additionalProperties")
            .is_none_or(|value| value == &serde_json::json!(true)));
        let source = &schemas["UserAttributeSourceView"]["properties"];
        assert_eq!(source["values"]["type"], "object");
        assert_eq!(source["provenance"]["type"], "object");
        assert_eq!(source["revision"]["minimum"], 1);
    }

    #[test]
    fn generation_is_stable_and_checks_do_not_modify_artifacts() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        run(root.path(), false)?;
        run(root.path(), true)?;
        for name in ["aegaeon-management-api.v1.json", "aegaeon-ops.v1.json"] {
            let path = root.path().join("generated/openapi").join(name);
            let contents = fs::read_to_string(&path)?;
            assert!(contents.ends_with('\n') && !contents.ends_with("\n\n"));
            let _: serde_json::Value = serde_json::from_str(&contents)?;
            fs::write(&path, "stale")?;
            assert!(run(root.path(), true).is_err());
            assert_eq!(fs::read_to_string(&path)?, "stale");
            fs::write(&path, contents)?;
        }
        Ok(())
    }

    #[test]
    fn check_preserves_io_errors_and_does_not_create_directories() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        assert!(run(root.path(), true).is_err());
        assert!(!root.path().join("generated").exists());
        let error = write_or_check(root.path(), "{}\n", true)
            .err()
            .ok_or_else(|| anyhow::anyhow!("reading a directory unexpectedly succeeded"))?;
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(error.to_string().contains("Cannot read"));
        Ok(())
    }

    #[test]
    fn replacement_is_complete_and_failed_publication_cleans_temporary() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let path = root.path().join("api.json");
        fs::write(&path, "previous")?;
        write_or_check(&path, "{\"complete\":true}\n", false)?;
        assert_eq!(fs::read_to_string(&path)?, "{\"complete\":true}\n");
        let blocked = root.path().join("directory.json");
        fs::create_dir(&blocked)?;
        assert!(write_or_check(&blocked, "{}\n", false).is_err());
        assert_eq!(fs::read_dir(root.path())?.count(), 2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn generation_preserves_unix_artifact_permissions() -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir()?;
        let path = root.path().join("api.json");
        write_or_check(&path, "{}\n", false)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o644);
        for mode in [0o600, 0o640, 0o644, 0o440] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            write_or_check(&path, "{\"updated\":true}\n", false)?;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, mode);
            assert_eq!(fs::read_to_string(&path)?, "{\"updated\":true}\n");
        }
        Ok(())
    }
}
