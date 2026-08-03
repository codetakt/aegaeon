use super::errors::account_links_reorder_failed;
use crate::management::types::AccountLinkSummary;
use axum::response::Response;
use std::collections::HashMap;

pub(in crate::web::management::account_link::relink) fn reorder_account_links(
    requested_account_link_ids: &[String],
    account_links: Vec<AccountLinkSummary>,
    request_id: &str,
) -> Result<Vec<AccountLinkSummary>, Response> {
    let mut account_links_by_id = account_links
        .into_iter()
        .map(|account_link| (account_link.id.clone(), account_link))
        .collect::<HashMap<_, _>>();
    let mut ordered_account_links = Vec::with_capacity(requested_account_link_ids.len());
    for requested_account_link_id in requested_account_link_ids {
        let Some(account_link) = account_links_by_id.remove(requested_account_link_id) else {
            return Err(account_links_reorder_failed(request_id));
        };
        ordered_account_links.push(account_link);
    }

    Ok(ordered_account_links)
}
