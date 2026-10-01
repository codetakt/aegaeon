-- Read-only pre-upgrade inventory; run with psql -X -v ON_ERROR_STOP=1 -f ...
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH rules AS (
    SELECT e.id AS environment_id, e.active_configuration_version_id AS version,
           'tokenExchange.rules[' || (r.ordinality - 1) || ']' AS rule,
           r.value->>'clientId' AS client_id,
           r.value->>'targetAudience' AS target,
           s.value->>'targetScope' AS scope
    FROM aegaeon.environments e
    JOIN aegaeon.configuration_versions v ON v.environment_id = e.id
        AND v.id = e.active_configuration_version_id
    CROSS JOIN LATERAL jsonb_array_elements(v.configuration_document#>'{policy,tokenExchange,rules}')
        WITH ORDINALITY r(value, ordinality)
    CROSS JOIN LATERAL jsonb_array_elements(r.value->'scopes') s(value)
    UNION ALL
    SELECT e.id, e.active_configuration_version_id,
           'clientCredentials.rules[' || (r.ordinality - 1) || ']',
           r.value->>'clientId', r.value->>'targetAudience', s.value
    FROM aegaeon.environments e
    JOIN aegaeon.configuration_versions v ON v.environment_id = e.id
        AND v.id = e.active_configuration_version_id
    CROSS JOIN LATERAL jsonb_array_elements(v.configuration_document#>'{policy,clientCredentials,rules}')
        WITH ORDINALITY r(value, ordinality)
    CROSS JOIN LATERAL jsonb_array_elements_text(r.value->'scopes') s(value)
), violations AS (
    SELECT r.environment_id, r.version, r.rule, r.client_id, r.target, r.scope,
           CASE WHEN c.id IS NULL THEN 'client is not an active configuration member'
                ELSE 'scope is outside client allowedScopes' END AS reason
    FROM rules r
    LEFT JOIN aegaeon.clients c ON c.environment_id = r.environment_id
        AND c.configuration_version_id = r.version AND c.status = 'ACTIVE'
        AND c.client_identifier = r.client_id
    WHERE c.id IS NULL OR NOT (r.scope = ANY(c.allowed_scopes))
)
SELECT count(*) > 0 AS has_violations,
       jsonb_build_object('violationCount', count(*), 'scopeViolations',
           COALESCE(jsonb_agg(to_jsonb(v) ORDER BY environment_id, rule, scope), '[]'::jsonb)) AS report
FROM violations v
\gset
\echo :report
\if :has_violations
  DO $$ BEGIN RAISE EXCEPTION 'Target rule scope violations; see report above'; END $$;
\endif
COMMIT;
