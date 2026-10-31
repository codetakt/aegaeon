//! Actual product router with isolated PostgreSQL authority/claims and synthetic issuance.
//! New proofs use native EdDSA verification; legacy router suites keep the claims-only mock.
mod backend;
mod boundaries;
mod delegated_invitations;
mod effects;
mod fixture;
mod metrics;
mod namespace_recovery;
mod policy;
mod presentation;
