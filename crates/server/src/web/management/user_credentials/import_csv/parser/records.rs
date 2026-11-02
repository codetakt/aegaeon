//! CSV records for the user importer, with checked UTF-8 and fixed column counts.
//!
//! Keep csv-core's quoting and newline rules. Bytes under construction never
//! inhabit a string, including when parsing, allocation or a caller panics.

pub(super) struct CsvRecords<'a> {
    core: csv_core::Reader,
    input: &'a [u8],
    bytes: Vec<u8>,
    ends: Vec<usize>,
    byte: usize,
    record: usize,
    width: Option<usize>,
}

impl<'a> CsvRecords<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
        Self {
            core: csv_core::Reader::new(),
            input,
            bytes: vec![0; 1024],
            ends: vec![0; 8],
            byte: 0,
            record: 0,
            width: None,
        }
    }

    pub(super) fn next_record(&mut self) -> Result<Option<Vec<String>>, String> {
        let (start_byte, start_line) = (self.byte, self.core.line());
        let (mut written, mut fields) = (0, 0);
        loop {
            let (result, consumed, produced, ended) = self.core.read_record(
                self.input,
                &mut self.bytes[written..],
                &mut self.ends[fields..],
            );
            self.input = &self.input[consumed..];
            self.byte += consumed;
            written += produced;
            fields += ended;
            match result {
                csv_core::ReadRecordResult::InputEmpty => continue,
                csv_core::ReadRecordResult::OutputFull => {
                    let length = self
                        .bytes
                        .len()
                        .checked_mul(2)
                        .ok_or("CSV record too large")?;
                    self.bytes.resize(length, 0);
                }
                csv_core::ReadRecordResult::OutputEndsFull => {
                    let length = self
                        .ends
                        .len()
                        .checked_mul(2)
                        .ok_or("CSV record too wide")?;
                    self.ends.resize(length, 0);
                }
                csv_core::ReadRecordResult::End => return Ok(None),
                csv_core::ReadRecordResult::Record => {
                    let record = self.record;
                    self.record += 1;
                    if let Some(expected) = self.width {
                        if fields != expected {
                            return Err(format!(
                                "CSV error: record {record} (line: {start_line}, byte: {start_byte}): \
                                 found record with {fields} fields, but the previous record has {expected} fields"
                            ));
                        }
                    } else {
                        self.width = Some(fields);
                    }
                    let mut start = 0;
                    let mut values = Vec::with_capacity(fields);
                    for (field, &end) in self.ends[..fields].iter().enumerate() {
                        let value = std::str::from_utf8(&self.bytes[start..end]).map_err(|err| {
                            format!("CSV error: record {record} (line: {start_line}, byte: {start_byte}), \
                                     field {field}: invalid UTF-8: {err}")
                        })?;
                        values.push(value.trim().to_owned());
                        start = end;
                    }
                    return Ok(Some(values));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CsvRecords;

    #[test]
    fn quoted_unicode_fields_and_newlines() {
        let mut reader = CsvRecords::new(
            "\u{feff}subject,email\r\n\" A,\"\"B \" ,\"\u{2003}a@example.com\u{2003}\"\r\n"
                .as_bytes(),
        );
        assert_eq!(reader.next_record().unwrap().unwrap(), ["subject", "email"]);
        assert_eq!(
            reader.next_record().unwrap().unwrap(),
            ["A,\"B", "a@example.com"]
        );
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn invalid_utf8_returns_error_without_poisoning_following_record() {
        let mut reader = CsvRecords::new(b"subject\n\xff\nvalid\n");
        assert_eq!(reader.next_record().unwrap().unwrap(), ["subject"]);
        assert!(reader.next_record().unwrap_err().contains("invalid UTF-8"));
        assert_eq!(reader.next_record().unwrap().unwrap(), ["valid"]);
    }

    #[test]
    fn fixed_width_and_position_survive_quoted_newlines() {
        let mut reader = CsvRecords::new(b"subject,email\n\"a\nb\",c\nx\n");
        reader.next_record().unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap(), ["a\nb", "c"]);
        assert_eq!(reader.next_record().unwrap_err(), "CSV error: record 2 (line: 4, byte: 22): found record with 1 fields, but the previous record has 2 fields");
    }

    #[test]
    fn record_and_field_buffers_grow_without_losing_boundaries() {
        let input = format!("{}\n", vec!["é".repeat(1025); 20].join(","));
        let mut reader = CsvRecords::new(input.as_bytes());
        assert_eq!(
            reader.next_record().unwrap().unwrap(),
            vec!["é".repeat(1025); 20]
        );
        assert!(reader.next_record().unwrap().is_none());
    }
}
