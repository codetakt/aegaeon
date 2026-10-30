-- Checked administrative runtime grants; default ROLLBACK.
-- Requires the complete ownership/organization migrations and checked subject
-- runtime provisioning. Feature/domain enablement remains a separate action.
\set ON_ERROR_STOP on
\if :{?runtime_role}
\else
  \echo 'runtime_role is required'
  \quit 3
\endif
\if :{?commit}
\else
  \set commit false
\endif
BEGIN;
SET LOCAL search_path = pg_catalog, pg_temp;
-- Refuse existing dangerous authority; never silently revoke operator grants.
SELECT aegaeon.subject_history_preflight(:'runtime_role');
GRANT EXECUTE ON FUNCTION aegaeon.organization_snapshot_history_v1(uuid,uuid,text,text,integer) TO :"runtime_role";
GRANT SELECT,INSERT ON aegaeon.organization_admin_access_grants TO :"runtime_role";
GRANT UPDATE(active,revision,revocation_key,revocation_digest) ON aegaeon.organization_admin_access_grants TO :"runtime_role";
GRANT SELECT,INSERT ON aegaeon.organization_identity_requests TO :"runtime_role";
GRANT UPDATE(state,result,delivery_revision,delivered_at,delivery_outcome,capability_hash)
  ON aegaeon.organization_identity_requests TO :"runtime_role";
GRANT SELECT,INSERT ON
  aegaeon.authorization_domains,
  aegaeon.organization_operator_grants,
  aegaeon.organization_client_bindings,
  aegaeon.organization_invitations,
  aegaeon.organization_invitation_challenges,
  aegaeon.authorization_domain_targets,
  aegaeon.application_organizations,
  aegaeon.organization_role_definitions,
  aegaeon.organization_memberships,
  aegaeon.organization_authority_events,
  aegaeon.organization_authority_outbox,
  aegaeon.organization_authority_receipts TO :"runtime_role";
GRANT UPDATE(state,revision,delivery_revision,delivered_at,capability_hash,accepted_challenge_id,result,delivery_outcome)
  ON aegaeon.organization_invitations TO :"runtime_role";
GRANT UPDATE(delivery_revision,delivered_at,capability_hash,delivery_outcome)
  ON aegaeon.organization_invitation_challenges TO :"runtime_role";
GRANT UPDATE(active,revision,targets)
  ON aegaeon.organization_client_bindings TO :"runtime_role";
GRANT UPDATE(active,revision,capabilities)
  ON aegaeon.organization_operator_grants TO :"runtime_role";
GRANT UPDATE(name,is_default,enabled,revision,invitation_delivery,support_policy,support_policy_revision)
  ON aegaeon.authorization_domains TO :"runtime_role";
GRANT UPDATE(domain_id,management,introspection_clients)
  ON aegaeon.authorization_domain_targets TO :"runtime_role";
GRANT UPDATE(state,revision,grant_generation)
  ON aegaeon.application_organizations TO :"runtime_role";
GRANT UPDATE(version,privileges,manages_members,assignable_roles)
  ON aegaeon.organization_role_definitions TO :"runtime_role";
GRANT UPDATE(state,revision,grant_generation,roles)
  ON aegaeon.organization_memberships TO :"runtime_role";
GRANT UPDATE(delivered_at,attempts)
  ON aegaeon.organization_authority_outbox TO :"runtime_role";
SELECT aegaeon.subject_history_preflight(:'runtime_role');
\if :commit
COMMIT;
\else
ROLLBACK;
\endif
