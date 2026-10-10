//! Runtime namespace acceptance tests. Positive permits come only from real PG validation.
//! Run ignored tests against an owned database with the restricted runtime role.
mod authorization_consumption;
mod authorization_fixture;
mod browser_consumption;
mod device_consumption;
mod direct;
mod exceptions;
mod login_consumption;
mod logout_notifications;
mod management_effects;
mod management_fixture;
mod positive_application;
mod positive_dcr;
mod positive_jwt_bearer;
mod positive_support;
mod positive_upstream;
mod positive_upstream_fixture;
mod positive_upstream_observation;
mod positive_upstream_supplier;
mod recovery_consumption;
mod support;
mod token_consumption;
mod upstream_consumption;
