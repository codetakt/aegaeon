mod get;
mod list;

pub(in crate::web::management::federation) use get::get_federation_trust_anchor;
pub(in crate::web::management::federation) use list::list_federation_trust_anchors;
