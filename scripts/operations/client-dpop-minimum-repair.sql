-- OFFLINE ONLY. Supply exactly one typed row in pg_temp.client_dpop_minimum_repair_input.
-- Read the upgrade runbook. All issuers/writers must remain stopped.
-- Distributed review form ROLLS BACK; reviewed commit copy changes only the final statement.
BEGIN;
SET LOCAL TIME ZONE 'UTC';
SELECT current_setting('server_version') AS server_version,
       current_setting('server_encoding') AS server_encoding,
       current_setting('client_encoding') AS client_encoding;
DO $repair$
DECLARE
    input pg_temp.client_dpop_minimum_repair_input%ROWTYPE;
    current_client aegaeon.clients%ROWTYPE;
    tenant_id uuid;
    team_id uuid;
    actual_digest text;
    chosen boolean;
BEGIN
    IF (SELECT count(*) FROM pg_temp.client_dpop_minimum_repair_input) <> 1 THEN
        RAISE EXCEPTION 'repair requires exactly one input';
    END IF;
    SELECT * INTO STRICT input FROM pg_temp.client_dpop_minimum_repair_input;
    IF input.schema_version IS DISTINCT FROM 1
       OR input.environment_id IS NULL OR input.client_id IS NULL
       OR input.expected_row_sha256 IS NULL
       OR input.expected_row_sha256 COLLATE "C" !~ '^[0-9a-f]{64}$'
       OR input.dpop_bound_access_tokens IS NULL
       OR input.dpop_bound_access_tokens COLLATE "C" NOT IN ('true', 'false')
       OR input.operator_reference IS NULL
       OR octet_length(input.operator_reference) NOT BETWEEN 1 AND 256
       OR input.operator_reference COLLATE "C" !~ '^[!-~]+$' THEN
        RAISE EXCEPTION 'repair input is invalid';
    END IF;
    chosen := input.dpop_bound_access_tokens::boolean;
    SELECT e.tenant_id INTO tenant_id FROM aegaeon.environments e
    WHERE e.id = input.environment_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'repair environment is unavailable'; END IF;
    SELECT * INTO current_client FROM aegaeon.clients c
    WHERE c.environment_id = input.environment_id AND c.id = input.client_id FOR UPDATE;
    IF NOT FOUND OR current_client.dpop_bound_access_tokens IS NOT NULL THEN
        RAISE EXCEPTION 'repair client is unavailable or already resolved';
    END IF;
    SELECT pg_catalog.encode(
      pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(c)::text, 'UTF8')), 'hex'
    ) INTO actual_digest FROM aegaeon.clients c WHERE c.id = current_client.id;
    IF actual_digest IS DISTINCT FROM input.expected_row_sha256 THEN
        RAISE EXCEPTION 'repair client changed';
    END IF;
    SELECT t.team_id INTO STRICT team_id FROM aegaeon.tenants t WHERE t.id = tenant_id;
    UPDATE aegaeon.clients SET dpop_bound_access_tokens = chosen WHERE id = current_client.id;
    INSERT INTO aegaeon.audit_events (
        team_id, tenant_id, environment_id, event_type, category, outcome, severity,
        occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
    ) VALUES (
        team_id, tenant_id, current_client.environment_id,
        'maintenance.clientDpopMinimum.resolved.v1', 'client_configuration', 'success', 'info',
        clock_timestamp(), 'database_role', current_user, 'client', current_client.id::text,
        'maintenance:' || pg_catalog.gen_random_uuid()::text,
        jsonb_build_object(
            'schema_version', input.schema_version, 'session_user', session_user,
            'environment_id', current_client.environment_id, 'client_id', current_client.id,
            'tenant_id', tenant_id, 'team_id', team_id,
            'dpop_bound_access_tokens', chosen, 'expected_row_sha256', input.expected_row_sha256,
            'operator_reference', input.operator_reference
        )
    );
END
$repair$;
ROLLBACK;
