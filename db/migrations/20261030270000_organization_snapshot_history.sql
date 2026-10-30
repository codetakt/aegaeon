-- ORG-R17 / ORG-G10 / ORG-P11/P13: bounded scoped permanent history reads.
-- The HTTP caller separately checks current Export authority before disclosure.
-- Direct history-table privileges and all existing identifiers remain unchanged.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_snapshot_history_v1(
  scope_environment uuid, scope_domain uuid, collection text, after_key text, page_limit integer
) RETURNS TABLE(row_key text, row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF scope_environment IS NULL OR scope_environment='00000000-0000-0000-0000-000000000000'
    OR scope_domain IS NULL OR scope_domain='00000000-0000-0000-0000-000000000000'
    OR collection IS NULL OR collection NOT IN ('owners','subject_history')
    OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 10
    OR octet_length(after_key)>4096
    OR NOT EXISTS (SELECT FROM aegaeon.authorization_domains d
      WHERE d.environment_id=scope_environment AND d.id=scope_domain) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid scoped snapshot history request';
  END IF;
  RETURN QUERY
    WITH owners AS (
      SELECT m.end_user_id AS id FROM aegaeon.organization_memberships m
        WHERE m.environment_id=scope_environment AND m.domain_id=scope_domain
      UNION SELECT r.target_user_id FROM aegaeon.organization_identity_requests r
        WHERE r.environment_id=scope_environment AND r.domain_id=scope_domain AND r.target_user_id IS NOT NULL
      UNION SELECT (r.result->>'userId')::uuid FROM aegaeon.organization_identity_requests r
        WHERE r.environment_id=scope_environment AND r.domain_id=scope_domain AND r.result IS NOT NULL
      UNION SELECT (c.recipient_binding->'binding'->>'user_id')::uuid FROM aegaeon.organization_invitation_challenges c
        WHERE c.environment_id=scope_environment AND c.domain_id=scope_domain
      UNION SELECT g.user_id FROM aegaeon.organization_admin_access_grants g
        WHERE g.environment_id=scope_environment AND g.domain_id=scope_domain
    ), rows AS (
      SELECT v.owner_id::text AS key, to_jsonb(v)::text AS data FROM (
        SELECT o.owner_id,o.environment_id,o.recorded_at FROM aegaeon.end_user_identity_owners o
        WHERE collection='owners' AND o.environment_id=scope_environment AND o.owner_id IN (SELECT id FROM owners)
      ) v
      UNION ALL SELECT v.subject, to_jsonb(v)::text FROM (
        SELECT r.environment_id,r.subject,r.owner_id,r.recorded_at FROM aegaeon.end_user_subject_reservations r
        WHERE collection='subject_history' AND r.environment_id=scope_environment AND r.owner_id IN (SELECT id FROM owners)
      ) v
    )
    SELECT r.key, CASE WHEN octet_length(r.data)<=262144 THEN r.data ELSE NULL END
    FROM rows r WHERE after_key IS NULL OR r.key COLLATE "C">after_key COLLATE "C"
    ORDER BY r.key COLLATE "C" LIMIT page_limit;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_snapshot_history_v1(uuid,uuid,text,text,integer) FROM PUBLIC;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
