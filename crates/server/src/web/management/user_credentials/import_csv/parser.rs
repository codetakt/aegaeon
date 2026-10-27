use std::collections::HashSet;

use super::super::super::{normalize_email, normalize_subject};

mod records;

#[derive(Debug, Clone)]
pub(super) struct ParsedCsvUserRow {
    pub(super) row_number: i64,
    pub(super) subject: String,
    pub(super) email: Option<String>,
}

pub(super) fn parse_import_users_csv(csv_data: &str) -> Result<Vec<ParsedCsvUserRow>, String> {
    let mut reader = records::CsvRecords::new(csv_data.as_bytes());
    let headers = reader
        .next_record()
        .map_err(|err| format!("Failed to parse CSV header: {err}"))?
        .ok_or_else(|| "CSV must include a header row".to_string())?;
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
    for (idx, record) in std::iter::from_fn(|| reader.next_record().transpose()).enumerate() {
        let record = record.map_err(|err| format!("Failed to parse CSV row {}: {err}", idx + 2))?;
        if record.iter().all(|value| value.trim().is_empty()) {
            continue;
        }
        let Some(subject) = record.first().and_then(|value| normalize_subject(value)) else {
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
            .map(|value| value.trim())
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

#[cfg(test)]
mod tests {
    use super::parse_import_users_csv;

    #[test]
    fn absent_header_and_header_only_inputs_are_distinct_refusals() {
        for input in ["", "\n\r\n", "\u{feff}"] {
            assert_eq!(
                parse_import_users_csv(input).unwrap_err(),
                "CSV must include a header row"
            );
        }
        for input in ["subject\n", "subject,email\n,\n"] {
            assert_eq!(
                parse_import_users_csv(input).unwrap_err(),
                "CSV must include at least one user row"
            );
        }
    }

    #[test]
    fn invalid_later_rows_reject_the_complete_import() {
        for (tail, error) in [
            (" owner ,second@example.test", "duplicates subject owner"),
            ("other,invalid", "invalid email"),
            ("other", "found record with 1 fields"),
            ("other,a@example.test,extra", "found record with 3 fields"),
        ] {
            let input = format!("subject,email\nowner,first@example.test\n{tail}\n");
            assert!(parse_import_users_csv(&input).unwrap_err().contains(error));
        }
        let rows = parse_import_users_csv(
            "\u{feff} SUBJECT , EMAIL \r\n\" owner \" ,\"\u{2003}OWNER@EXAMPLE.TEST\u{2003}\"\r\nother,\r\n",
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].subject, "owner");
        assert_eq!(rows[0].email.as_deref(), Some("owner@example.test"));
        assert_eq!(rows[0].row_number, 2);
        assert_eq!(rows[1].subject, "other");
        assert_eq!(rows[1].email, None);
        assert_eq!(rows[1].row_number, 3);
    }
}
