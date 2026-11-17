//! Source-bound components of Organizations and its additive migrations. The build
//! script validates and extracts these catalog/check fixtures, not migrations.
macro_rules! component {
    ($name:literal) => {
        include_str!(concat!(env!("OUT_DIR"), "/", $name, ".sql"))
    };
}
pub(crate) use component;
