//! Source-bound components of the single Organizations migration. These slices
//! support catalog checking and focused table fixtures; they are not migrations.
const SOURCE: &str = include_str!("../../../db/migrations/20261105000000_organizations.sql");

pub(crate) fn extract(begin: &str, end: &str) -> &'static str {
    SOURCE
        .split_once(begin)
        .expect("Organizations schema component is missing")
        .1
        .split_once(end)
        .expect("Organizations schema component is incomplete")
        .0
}

macro_rules! component {
    ($name:literal) => {
        $crate::organization_schema::extract(
            concat!("-- BEGIN ORGANIZATIONS COMPONENT ", $name, "\n"),
            concat!("-- END ORGANIZATIONS COMPONENT ", $name, "\n"),
        )
    };
}
pub(crate) use component;
