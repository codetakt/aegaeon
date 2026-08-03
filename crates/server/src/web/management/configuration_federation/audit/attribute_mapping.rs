pub(in crate::web::management) fn federation_attribute_mapping_audit_snapshot(
    configuration_document: &serde_json::Value,
) -> serde_json::Value {
    let Some(mappings) = configuration_document
        .get("federation")
        .and_then(|value| value.get("attributeMapping"))
        .and_then(|value| value.as_array())
    else {
        return serde_json::Value::Array(Vec::new());
    };

    let normalized = mappings
        .iter()
        .filter_map(|mapping| {
            let mapping = mapping.as_object()?;
            let from = mapping.get("from")?.as_str()?.trim();
            let to = mapping.get("to")?.as_str()?.trim();
            if from.is_empty() || to.is_empty() {
                return None;
            }

            let mut normalized_mapping = serde_json::Map::new();
            normalized_mapping.insert(
                "from".to_string(),
                serde_json::Value::String(from.to_string()),
            );
            normalized_mapping.insert("to".to_string(), serde_json::Value::String(to.to_string()));

            if let Some(rule) = mapping
                .get("rule")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                normalized_mapping.insert(
                    "rule".to_string(),
                    serde_json::Value::String(rule.to_string()),
                );
            }

            Some(serde_json::Value::Object(normalized_mapping))
        })
        .collect::<Vec<_>>();

    serde_json::Value::Array(normalized)
}
