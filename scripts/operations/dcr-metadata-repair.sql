-- OFFLINE ONLY: read the registration metadata upgrade runbook first.
-- Supply exactly one private JSON document in pg_temp.dcr_metadata_repair_input(request jsonb).
-- Database administrator authority, stopped writers and a verified backup are prerequisites.
-- This review execution ROLLS BACK. An approved copy may replace the final ROLLBACK with COMMIT.
BEGIN;
DO $repair$
DECLARE
    request jsonb;
    current_client aegaeon.clients%ROWTYPE;
    current_dcr aegaeon.dynamic_client_registrations%ROWTYPE;
    active_version uuid;
    old_metadata jsonb;
    new_grants text[];
    new_redirects text[];
    new_jwks jsonb;
    new_jwks_uri text;
BEGIN
    IF (SELECT count(*) FROM pg_temp.dcr_metadata_repair_input) <> 1 THEN
        RAISE EXCEPTION 'repair requires exactly one approved input';
    END IF;
    SELECT i.request INTO request FROM pg_temp.dcr_metadata_repair_input i;
    IF request->>'operator_approval_reference' IS NULL OR btrim(request->>'operator_approval_reference') = '' THEN
        RAISE EXCEPTION 'repair requires a private operator approval reference';
    END IF;
    SELECT active_configuration_version_id INTO active_version
    FROM aegaeon.environments WHERE id = (request->>'environment_id')::uuid FOR UPDATE;
    IF NOT FOUND OR active_version IS DISTINCT FROM (request->>'expected_active_configuration_version_id')::uuid THEN
        RAISE EXCEPTION 'repair environment membership changed or missing';
    END IF;
    SELECT * INTO current_client FROM aegaeon.clients
    WHERE environment_id = (request->>'environment_id')::uuid AND id = (request->>'client_id')::uuid
    FOR UPDATE;
    IF NOT FOUND OR current_client.configuration_version_id IS DISTINCT FROM (request->>'expected_configuration_version_id')::uuid
       OR current_client.status::text IS DISTINCT FROM request->>'expected_status'
       OR current_client.client_identifier IS DISTINCT FROM request->>'expected_client_identifier' THEN
        RAISE EXCEPTION 'repair client identity, membership or status changed or missing';
    END IF;
    SELECT * INTO current_dcr FROM aegaeon.dynamic_client_registrations
    WHERE environment_id = current_client.environment_id AND client_id = current_client.id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'repair registration missing'; END IF;
    old_metadata := jsonb_build_object(
        'redirect_uris', current_client.redirect_uris, 'grant_types', current_client.allowed_grant_types,
        'client_type', current_client.client_type, 'auth_method', current_client.token_endpoint_authentication_method,
        'scopes', current_client.allowed_scopes, 'name', current_client.name, 'oauth_profile_id', current_client.oauth_profile_id,
        'response_types', current_dcr.response_types, 'client_id_issued_at', current_dcr.client_id_issued_at,
        'post_logout_redirect_uris', current_dcr.post_logout_redirect_uris,
        'backchannel_logout_uri', current_dcr.backchannel_logout_uri,
        'backchannel_logout_session_required', current_dcr.backchannel_logout_session_required,
        'token_endpoint_auth_signing_alg', current_dcr.token_endpoint_auth_signing_alg,
        'jwks', current_dcr.jwks, 'jwks_uri', current_dcr.jwks_uri);
    IF old_metadata IS DISTINCT FROM request->'expected_metadata' THEN
        RAISE EXCEPTION 'repair old metadata changed or does not match';
    END IF;
    IF jsonb_typeof(request->'replacement'->'grant_types') IS DISTINCT FROM 'array'
       OR jsonb_typeof(request->'replacement'->'redirect_uris') IS DISTINCT FROM 'array'
       OR NOT (request->'replacement' ? 'jwks') OR NOT (request->'replacement' ? 'jwks_uri')
       OR (request->'replacement') - ARRAY['grant_types','redirect_uris','jwks','jwks_uri'] <> '{}'::jsonb THEN
        RAISE EXCEPTION 'repair replacement must specify exact grants, redirects and key sources';
    END IF;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(request->'replacement'->'grant_types') v WHERE jsonb_typeof(v) <> 'string')
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(request->'replacement'->'redirect_uris') v WHERE jsonb_typeof(v) <> 'string') THEN
        RAISE EXCEPTION 'repair arrays require strings';
    END IF;
    SELECT ARRAY(SELECT jsonb_array_elements_text(request->'replacement'->'grant_types')) INTO new_grants;
    SELECT ARRAY(SELECT jsonb_array_elements_text(request->'replacement'->'redirect_uris')) INTO new_redirects;
    IF cardinality(new_grants) = 0 OR NOT new_grants <@ current_client.allowed_grant_types THEN
        RAISE EXCEPTION 'repair grants must be a nonempty subset of existing grants';
    END IF;
    IF NOT aegaeon.text_array_is_normalized_set(new_grants, false)
       OR NOT aegaeon.text_array_is_normalized_set(new_redirects, true)
       OR EXISTS (SELECT 1 FROM unnest(new_redirects) u WHERE u COLLATE "C" ~ '[[:space:][:cntrl:]]')
       OR EXISTS (SELECT 1 FROM unnest(new_redirects) u WHERE u !~* '^(https://[^/?#@[:space:][:cntrl:]]+|http://(localhost|127(\.[0-9]{1,3}){3}|\[::1\])(:[0-9]+)?)([/?][^#[:space:][:cntrl:]]*)?$')
       OR ('refresh_token' = ANY(new_grants) AND NOT 'authorization_code' = ANY(new_grants))
       OR ('authorization_code' = ANY(new_grants) AND cardinality(new_redirects) = 0)
       OR (current_client.token_endpoint_authentication_method = 'none' AND new_grants && ARRAY['client_credentials','urn:ietf:params:oauth:grant-type:token-exchange']) THEN
        RAISE EXCEPTION 'repair replacement violates registration metadata relationships';
    END IF;
    new_jwks := NULLIF(request->'replacement'->'jwks', 'null'::jsonb);
    IF jsonb_typeof(request->'replacement'->'jwks_uri') NOT IN ('string', 'null') THEN
        RAISE EXCEPTION 'repair remote key URI must be a string or null';
    END IF;
    new_jwks_uri := request->'replacement'->>'jwks_uri';
    IF (new_jwks IS DISTINCT FROM current_dcr.jwks OR new_jwks_uri IS DISTINCT FROM current_dcr.jwks_uri)
       AND (request->>'verified_key_backup_reference' IS NULL OR btrim(request->>'verified_key_backup_reference') = '') THEN
        RAISE EXCEPTION 'key repair requires a verified intended metadata backup reference';
    END IF;
    UPDATE aegaeon.clients SET redirect_uris = new_redirects, allowed_grant_types = new_grants
    WHERE environment_id = current_client.environment_id AND id = current_client.id;
    -- Preserve predecessor response CHECK; the subsequent migration derives responses.
    UPDATE aegaeon.dynamic_client_registrations SET jwks = new_jwks, jwks_uri = new_jwks_uri
    WHERE environment_id = current_client.environment_id AND client_id = current_client.id;
    -- No credentials, status, membership, identity, scopes, audit events or timestamps rewritten.
END
$repair$;
ROLLBACK;
