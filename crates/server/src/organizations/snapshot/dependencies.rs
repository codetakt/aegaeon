//! Fixed reference projections; no input supplies SQL syntax.
pub(super) const REFERENCES: &str = r#"client_refs AS (
  SELECT client_registration_id AS id FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2
  UNION SELECT (r->>'clientRegistrationId')::uuid FROM aegaeon.authorization_domain_targets t CROSS JOIN LATERAL jsonb_array_elements(t.introspection_clients) r WHERE t.environment_id=$1 AND t.domain_id=$2
  UNION SELECT (authority->'actor'->>'client_registration_id')::uuid FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2 AND authority->'actor'->>'kind'='member'
  UNION SELECT (recipient_binding->'binding'->>'client_registration_id')::uuid FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2
  UNION SELECT client_registration_id FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2
  UNION SELECT client_registration_id FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND domain_id=$2 AND actor_kind='member'
  UNION SELECT client_registration_id FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_kind='member'
), connection_refs AS (
  SELECT (p->>'connectionId')::uuid AS id FROM aegaeon.authorization_domains d CROSS JOIN LATERAL jsonb_array_elements(d.support_policy->'providers') p WHERE d.environment_id=$1 AND d.id=$2
)"#;
