//! Explicit management authority, separate from application memberships.
//!
//! Lineage validation is one input to authorization. A caller must additionally
//! check the current credential, registered action, resource selector and SQL
//! snapshot. It never turns a Team role name into installation authority.

pub(crate) mod actions;
pub(crate) mod lineage;
pub(crate) mod selectors;
