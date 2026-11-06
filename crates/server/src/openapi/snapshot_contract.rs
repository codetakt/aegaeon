#[test]
fn snapshot_description_agrees_with_actual_wire_version_and_sections() -> anyhow::Result<()> {
    let document = serde_json::to_value(super::management_openapi())?;
    let path =
        "/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/snapshot";
    let description = document["paths"][path]["get"]["description"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("snapshot description"))?;
    let version = crate::organizations::snapshot::FORMAT_VERSION;
    let sections: Vec<_> = crate::organizations::snapshot::section_names().collect();
    assert!(
        description.contains(&format!("version {version}")),
        "published version differs from the native producer and receiver"
    );
    assert!(
        description.contains(&format!("All {} section", sections.len())),
        "published section count differs from the actual reader inventory"
    );
    for dependency in ["client_absences", "connection_dependencies"] {
        assert!(sections.contains(&dependency));
        assert!(
            description.contains(dependency),
            "required dependency disclosure absent: {dependency}"
        );
    }
    Ok(())
}
