use super::super::pagination::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};

pub(in crate::web::management) const EXPORT_DEFAULT_LIMIT: u32 = 1000;
pub(in crate::web::management) const EXPORT_MAX_LIMIT: u32 = 10000;

pub(in crate::web::management) fn audit_list_limit(page_size: Option<u32>) -> i64 {
    i64::from(
        page_size
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE),
    )
}

pub(in crate::web::management) fn audit_export_limit(limit: Option<u32>) -> i64 {
    i64::from(
        limit
            .unwrap_or(EXPORT_DEFAULT_LIMIT)
            .clamp(1, EXPORT_MAX_LIMIT),
    )
}
