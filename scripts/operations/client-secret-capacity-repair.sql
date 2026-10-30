-- OFFLINE ONLY: full service maintenance and verified backup are prerequisites.
-- Supply exactly one reviewed JSON object in pg_temp.client_secret_repair_input(request jsonb).
-- Review execution rolls back. An approved copy may change the final ROLLBACK to COMMIT.
BEGIN;
DO $repair$
DECLARE
    request jsonb;
    current_client aegaeon.clients%ROWTYPE;
    current_secret aegaeon.client_secrets%ROWTYPE;
    active_version uuid;
    tenant uuid;
    team uuid;
BEGIN
    IF (SELECT count(*) FROM pg_temp.client_secret_repair_input) <> 1 THEN
        RAISE EXCEPTION 'repair requires exactly one reviewed credential selection';
    END IF;
    SELECT i.request INTO request FROM pg_temp.client_secret_repair_input i;
    IF jsonb_typeof(request) IS DISTINCT FROM 'object'
       OR NOT request ? 'expected_active_configuration_version_id'
       OR jsonb_typeof(request->'expected_active_configuration_version_id') NOT IN ('string', 'null')
       OR jsonb_typeof(request->'operator') IS DISTINCT FROM 'string'
       OR btrim(request->>'operator') = ''
       OR jsonb_typeof(request->'approval_reference') IS DISTINCT FROM 'string'
       OR btrim(request->>'approval_reference') = '' THEN
        RAISE EXCEPTION 'repair requires operator and private approval reference';
    END IF;
    SELECT active_configuration_version_id, tenant_id INTO active_version, tenant
    FROM aegaeon.environments WHERE id = (request->>'environment_id')::uuid FOR UPDATE;
    IF NOT FOUND OR active_version IS DISTINCT FROM (request->>'expected_active_configuration_version_id')::uuid THEN
        RAISE EXCEPTION 'repair environment missing or active configuration changed';
    END IF;
    SELECT team_id INTO STRICT team FROM aegaeon.tenants WHERE id = tenant;
    SELECT * INTO current_client FROM aegaeon.clients
    WHERE environment_id = (request->>'environment_id')::uuid AND id = (request->>'client_id')::uuid FOR UPDATE;
    IF NOT FOUND OR current_client.status::text IS DISTINCT FROM request->>'expected_client_status'
       OR current_client.configuration_version_id IS DISTINCT FROM (request->>'expected_client_configuration_version_id')::uuid THEN
        RAISE EXCEPTION 'repair client missing or configuration/status changed';
    END IF;
    SELECT * INTO current_secret FROM aegaeon.client_secrets
    WHERE environment_id = current_client.environment_id AND client_id = current_client.id
      AND id = (request->>'client_secret_id')::uuid FOR UPDATE;
    IF NOT FOUND OR current_secret.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'selected credential missing, outside scope or no longer ACTIVE';
    END IF;
    -- Explicit operator choice only, including deleted or inactive-configuration clients.
    UPDATE aegaeon.client_secrets SET status = 'REVOKED', revoked_at = statement_timestamp()
    WHERE id = current_secret.id;
    INSERT INTO aegaeon.audit_events (
        team_id, tenant_id, environment_id, event_type, category, outcome, severity,
        occurred_at, actor_type, actor_id, target_type, target_id, request_id, data
    ) VALUES (
        team, tenant, current_client.environment_id, 'operations.clientSecret.revoked.v1',
        'CONTROL_PLANE', 'SUCCESS', 'INFO', statement_timestamp(), 'DATABASE_OPERATOR',
        request->>'operator', 'CLIENT_SECRET', current_secret.id::text,
        request->>'approval_reference', jsonb_build_object(
            'clientId', current_client.id, 'clientSecretId', current_secret.id,
            'reason', 'active credential capacity upgrade',
            'clientStatus', current_client.status,
            'configurationVersionId', current_client.configuration_version_id
        )
    );
    -- No hash, plaintext, slot, expiration, owner token, client status or metadata changed.
END
$repair$;
ROLLBACK;
