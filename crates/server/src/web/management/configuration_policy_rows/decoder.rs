use super::super::management_internal_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, Row};

pub(super) struct PolicyRowDecoder<'a> {
    row: &'a PgRow,
    request_id: &'a str,
}

impl<'a> PolicyRowDecoder<'a> {
    pub(super) fn new(row: &'a PgRow, request_id: &'a str) -> Self {
        Self { row, request_id }
    }

    pub(super) fn bool_field(&self, column: &str) -> Result<bool, Response> {
        self.row.try_get(column).map_err(|_| self.decode_error())
    }

    pub(super) fn vec_field(&self, column: &str) -> Result<Vec<String>, Response> {
        self.row.try_get(column).map_err(|_| self.decode_error())
    }

    pub(super) fn string_field(&self, column: &str) -> Result<String, Response> {
        self.row.try_get(column).map_err(|_| self.decode_error())
    }

    pub(super) fn optional_text_field(&self, column: &str) -> Result<Option<String>, Response> {
        self.row.try_get(column).map_err(|_| self.decode_error())
    }

    pub(super) fn u32_field(&self, column: &str, minimum: i32) -> Result<u32, Response> {
        let value: i32 = self.row.try_get(column).map_err(|_| self.decode_error())?;
        if value < minimum {
            return Err(self.decode_error());
        }
        Ok(value.cast_unsigned())
    }

    pub(super) fn seconds_field(&self, column: &str, minimum: i32) -> Result<u32, Response> {
        self.u32_field(column, minimum)
    }

    pub(super) fn decode_error(&self) -> Response {
        management_internal_error(self.request_id, "Failed to decode environment policy")
    }
}
