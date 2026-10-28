-- Read-only; emits UUID row locations, zero-based indices, known names and counts.
-- Run before and after upgrade. A sole summary row with zero counts is clean.
WITH source AS (
    SELECT environment_id, client_id, jwks,
           jsonb_typeof(jwks) = 'object' AND jsonb_typeof(jwks -> 'keys') = 'array' AS envelope_ok
    FROM aegaeon.dynamic_client_registrations
    WHERE jwks IS NOT NULL
), members AS (
    SELECT environment_id, client_id, member, ordinal - 1 AS key_index
    FROM source
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN envelope_ok THEN jwks -> 'keys' ELSE '[]'::jsonb END
    ) WITH ORDINALITY AS keys(member, ordinal)
), findings AS (
    SELECT environment_id, client_id, NULL::bigint AS key_index,
           'malformed_envelope'::text AS issue, NULL::text AS field
    FROM source WHERE envelope_ok IS NOT TRUE
    UNION ALL
    SELECT environment_id, client_id, key_index, 'non_object_key', NULL
    FROM members WHERE jsonb_typeof(member) IS DISTINCT FROM 'object'
    UNION ALL
    SELECT environment_id, client_id, key_index, 'private_member', field
    FROM members
    CROSS JOIN unnest(ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) AS fields(field)
    WHERE jsonb_typeof(member) = 'object' AND member ? field
), totals AS (
    SELECT count(*) FILTER (WHERE issue = 'private_member') AS private_member_count,
           count(*) FILTER (WHERE issue <> 'private_member') AS blocker_count
    FROM findings
)
SELECT environment_id, client_id, key_index, issue, field, private_member_count, blocker_count
FROM findings CROSS JOIN totals
UNION ALL
SELECT NULL, NULL, NULL, 'summary', NULL, private_member_count, blocker_count FROM totals
ORDER BY issue, environment_id, client_id, key_index, field;
