use super::super::super::AccountLinkListQuery;

#[derive(Debug, Clone)]
pub(super) struct AccountLinkListFilters {
    pub(super) upstream_issuer: Option<String>,
    pub(super) upstream_subject_filter_enabled: bool,
    pub(super) upstream_subject_hashes: Vec<String>,
    pub(super) end_user_subject: Option<String>,
    pub(super) end_user_email: Option<String>,
    pub(super) connection_identifier: Option<String>,
}

pub(super) fn account_link_list_filters(
    query: &AccountLinkListQuery,
    upstream_subject_hashes: Option<Vec<String>>,
) -> AccountLinkListFilters {
    let upstream_subject_filter_enabled = upstream_subject_hashes.is_some();
    AccountLinkListFilters {
        upstream_issuer: trimmed_non_empty(query.upstream_issuer.as_deref()),
        upstream_subject_filter_enabled,
        upstream_subject_hashes: upstream_subject_hashes.unwrap_or_default(),
        end_user_subject: trimmed_non_empty(query.end_user_subject.as_deref()),
        end_user_email: trimmed_non_empty(query.end_user_email.as_deref()),
        connection_identifier: trimmed_non_empty(query.connection_identifier.as_deref()),
    }
}

fn trimmed_non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
