use csv::Trim;
use std::collections::HashSet;

use super::super::super::{normalize_email, normalize_subject};

#[derive(Debug, Clone)]
pub(super) struct ParsedCsvUserRow {
    pub(super) row_number: i64,
    pub(super) subject: String,
    pub(super) email: Option<String>,
}

pub(super) fn parse_import_users_csv(csv_data: &str) -> Result<Vec<ParsedCsvUserRow>, String> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(Trim::All)
        .flexible(false)
        .from_reader(csv_data.as_bytes());
    let headers = reader
        .headers()
        .map_err(|err| format!("Failed to parse CSV header: {err}"))?
        .clone();
    if headers.is_empty() {
        return Err("CSV must include a header row".to_string());
    }

    let header_names = headers
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if header_names.is_empty() || header_names[0] != "subject" {
        return Err("CSV header must start with subject".to_string());
    }
    if header_names.len() > 2 {
        return Err("CSV only supports subject,email columns".to_string());
    }
    if header_names.len() == 2 && header_names[1] != "email" {
        return Err("CSV only supports subject,email columns".to_string());
    }

    let mut seen_subjects = HashSet::new();
    let mut rows = Vec::new();
    for (idx, record) in reader.records().enumerate() {
        let record = record.map_err(|err| format!("Failed to parse CSV row {}: {err}", idx + 2))?;
        if record.iter().all(|value| value.trim().is_empty()) {
            continue;
        }
        let Some(subject) = record.get(0).and_then(normalize_subject) else {
            return Err(format!("CSV row {} has an invalid subject", idx + 2));
        };
        if !seen_subjects.insert(subject.clone()) {
            return Err(format!(
                "CSV row {} duplicates subject {}",
                idx + 2,
                subject
            ));
        }
        let email = match record
            .get(1)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(raw_email) => Some(
                normalize_email(raw_email)
                    .ok_or_else(|| format!("CSV row {} has an invalid email", idx + 2))?,
            ),
            None => None,
        };
        let row_number = i64::try_from(idx + 2)
            .map_err(|_| "CSV row number overflowed supported range".to_string())?;
        rows.push(ParsedCsvUserRow {
            row_number,
            subject,
            email,
        });
    }

    if rows.is_empty() {
        return Err("CSV must include at least one user row".to_string());
    }

    Ok(rows)
}
