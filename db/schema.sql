--
-- PostgreSQL database dump
--


-- Dumped from database version 18.1
-- Dumped by pg_dump version 18.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: aegaeon; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA aegaeon;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA aegaeon;
COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: administrator_kind; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.administrator_kind AS ENUM (
    'HUMAN',
    'SERVICE'
);


--
-- Name: administrator_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.administrator_status AS ENUM (
    'ACTIVE',
    'DISABLED'
);


--
-- Name: api_key_capability; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.api_key_capability AS ENUM (
    'READ',
    'AUDIT_READ',
    'TEAM_ADMINISTRATION'
);


--
-- Name: api_key_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.api_key_status AS ENUM (
    'ACTIVE',
    'REVOKED'
);


--
-- Name: client_secret_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.client_secret_status AS ENUM (
    'ACTIVE',
    'RETIRING',
    'REVOKED'
);


--
-- Name: client_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.client_status AS ENUM (
    'ACTIVE',
    'DELETED'
);


--
-- Name: client_type; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.client_type AS ENUM (
    'PUBLIC',
    'CONFIDENTIAL'
);


--
-- Name: configuration_version_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.configuration_version_status AS ENUM (
    'DRAFT',
    'ACTIVE',
    'ARCHIVED'
);


--
-- Name: connection_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.connection_status AS ENUM (
    'ACTIVE',
    'DISABLED',
    'DELETED'
);


--
-- Name: connection_type; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.connection_type AS ENUM (
    'OIDC'
);


--
-- Name: end_user_password_credential_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.end_user_password_credential_status AS ENUM (
    'ACTIVE',
    'REVOKED'
);


--
-- Name: end_user_recovery_token_purpose; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.end_user_recovery_token_purpose AS ENUM (
    'activation',
    'password_reset'
);


--
-- Name: end_user_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.end_user_status AS ENUM (
    'ACTIVE',
    'SUSPENDED',
    'DELETED',
    'INVITED'
);


--
-- Name: environment_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.environment_status AS ENUM (
    'ACTIVE',
    'DELETED'
);


--
-- Name: management_runtime_command_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.management_runtime_command_status AS ENUM (
    'requested',
    'executing',
    'applied',
    'failed_terminal',
    'failed_unconfirmed'
);


--
-- Name: oauth_profile_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.oauth_profile_status AS ENUM (
    'ACTIVE',
    'RETIRED'
);


--
-- Name: oauth_profile_type; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.oauth_profile_type AS ENUM (
    'DOWNSTREAM',
    'UPSTREAM'
);


--
-- Name: oauth_sender_constraint; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.oauth_sender_constraint AS ENUM (
    'NONE',
    'DPOP',
    'MTLS'
);


--
-- Name: runtime_key_provider; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.runtime_key_provider AS ENUM (
    'databaseEncrypted',
    'awsKms'
);


--
-- Name: runtime_key_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.runtime_key_status AS ENUM (
    'ACTIVE',
    'NEXT',
    'RETIRING',
    'REVOKED'
);


--
-- Name: runtime_key_usage; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.runtime_key_usage AS ENUM (
    'OIDC_ID_TOKEN_SIGNING',
    'OIDC_REQUEST_OBJECT_DECRYPTION',
    'JWT_ACCESS_TOKEN_SIGNING',
    'JWT_INTROSPECTION_SIGNING'
);


--
-- Name: team_role; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.team_role AS ENUM (
    'OWNER',
    'ADMINISTRATOR',
    'OPERATOR',
    'AUDITOR',
    'READONLY'
);


--
-- Name: team_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.team_status AS ENUM (
    'ACTIVE',
    'DELETED'
);


--
-- Name: tenant_status; Type: TYPE; Schema: aegaeon; Owner: -
--

CREATE TYPE aegaeon.tenant_status AS ENUM (
    'ACTIVE',
    'DELETED'
);


--
-- Name: adopt_subject_ownership_history_v1(bytea, bytea, text, text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.adopt_subject_ownership_history_v1(manifest_raw bytea, inventory_raw bytea, expected_manifest_sha256 text, expected_inventory_sha256 text)
RETURNS TABLE(environment_id uuid, receipt_id uuid, manifest_sha256 text, inventory_sha256 text, session_actor text, effective_actor text, definer_actor text, owner_count bigint, reservation_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD' SET intervalstyle = 'postgres' SET extra_float_digits = 3
AS $function$
DECLARE manifest jsonb; inventory jsonb; observed record; env_id uuid; receipt_uuid uuid; actor text;
  inventory_facts jsonb; inventory_findings jsonb; current_count bigint:=0; findings_count bigint:=0; collections_count integer:=0; target_count integer:=0;
  collection_names text[]:=ARRAY['environments','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','audit_events','physical_catalog'];
  actual jsonb; item jsonb; tenant uuid; team uuid; summary jsonb; previous_id text;
BEGIN
  actor := aegaeon.subject_history_maintenance_actor();
  IF manifest_raw IS NULL OR inventory_raw IS NULL OR pg_catalog.octet_length(manifest_raw)>67108864 OR pg_catalog.octet_length(inventory_raw)>268435456 THEN RAISE EXCEPTION 'unsupported history input size'; END IF;
  PERFORM aegaeon.subject_history_require_string(pg_catalog.to_jsonb(expected_manifest_sha256),'sha256');
  PERFORM aegaeon.subject_history_require_string(pg_catalog.to_jsonb(expected_inventory_sha256),'sha256');
  IF pg_catalog.encode(pg_catalog.sha256(manifest_raw),'hex')<>expected_manifest_sha256 OR pg_catalog.encode(pg_catalog.sha256(inventory_raw),'hex')<>expected_inventory_sha256 THEN RAISE EXCEPTION 'raw history digest mismatch'; END IF;
  manifest := aegaeon.subject_history_parse_document(manifest_raw,'manifest');
  inventory := aegaeon.subject_history_parse_document(inventory_raw,'inventory');
  PERFORM aegaeon.subject_history_validate_manifest(manifest);
  IF manifest->'namespace'<>inventory->'namespace' OR manifest->'target'<>inventory->'target'
    OR manifest->'inventory'->>'artifact_sha256'<>expected_inventory_sha256 OR manifest->'inventory'->>'state_sha256'<>inventory->>'state_sha256'
    OR manifest->'inventory'->>'findings_sha256'<>inventory->>'findings_sha256' THEN RAISE EXCEPTION 'manifest inventory binding mismatch'; END IF;
  env_id := (manifest->'namespace'->>'environment_id')::uuid; receipt_uuid := (manifest->>'receipt_id')::uuid;
  PERFORM aegaeon.subject_history_lock();
  IF NOT EXISTS(SELECT FROM aegaeon.subject_ownership_namespaces n WHERE n.environment_id=env_id AND n.origin='legacy' AND n.contract_version=1 AND n.issuer_host=manifest->'namespace'->>'issuer_host')
    OR EXISTS(SELECT FROM aegaeon.subject_ownership_adoptions a WHERE a.environment_id=env_id OR a.receipt_id=receipt_uuid) THEN RAISE EXCEPTION 'subject namespace is not pending legacy or receipt is reused'; END IF;
  previous_id := '';
  FOR item IN SELECT pg_catalog.jsonb_array_elements(inventory->'facts') LOOP
    IF (item->>'fact_id') COLLATE "C"<=previous_id COLLATE "C" THEN RAISE EXCEPTION 'inventory facts are duplicated or unordered'; END IF;
    previous_id := item->>'fact_id';
  END LOOP;
  previous_id := '';
  FOR item IN SELECT pg_catalog.jsonb_array_elements(inventory->'findings') LOOP
    IF (item->>'finding_id') COLLATE "C"<=previous_id COLLATE "C" THEN RAISE EXCEPTION 'inventory findings are duplicated or unordered'; END IF;
    previous_id := item->>'finding_id';
  END LOOP;
  SELECT pg_catalog.jsonb_object_agg(v->>'fact_id',v) INTO inventory_facts FROM pg_catalog.jsonb_array_elements(inventory->'facts') rows(v);
  SELECT pg_catalog.jsonb_object_agg(v->>'finding_id',v) INTO inventory_findings FROM pg_catalog.jsonb_array_elements(inventory->'findings') rows(v);
  FOR observed IN SELECT * FROM aegaeon.subject_history_inventory_stream(env_id,manifest->'target'->>'deployment_id',manifest->'target'->>'runtime_role',
      pg_catalog.jsonb_build_object('tool_sha256',manifest->'target'->'tool_sha256','source_commit',manifest->'target'->'source_commit','source_tree',manifest->'target'->'source_tree','dirty_input_sha256',manifest->'target'->'dirty_input_sha256')) LOOP
    actual := observed.payload::jsonb;
    CASE observed.record_type
    WHEN 'fact' THEN
      current_count := current_count+1;
      IF actual IS DISTINCT FROM inventory_facts->observed.row_key THEN RAISE EXCEPTION 'inventory fact differs from locked database'; END IF;
    WHEN 'finding' THEN
      findings_count := findings_count+1;
      IF actual IS DISTINCT FROM inventory_findings->observed.row_key THEN RAISE EXCEPTION 'inventory finding differs from locked database'; END IF;
    WHEN 'collection' THEN
      collections_count := collections_count+1;
      IF actual IS DISTINCT FROM inventory->'collections'->(collections_count-1) THEN RAISE EXCEPTION 'stale inventory collection'; END IF;
    WHEN 'observed_target' THEN
      target_count := target_count+1;
      IF actual->'namespace'<>manifest->'namespace' OR actual->'target'<>manifest->'target'
        OR actual->>'state_sha256'<>inventory->>'state_sha256' OR actual->>'findings_sha256'<>inventory->>'findings_sha256' THEN RAISE EXCEPTION 'stale inventory target or state'; END IF;
    ELSE
      IF observed.record_type NOT LIKE 'source:%' THEN RAISE EXCEPTION 'unexpected internal inventory record'; END IF;
    END CASE;
  END LOOP;
  IF current_count<>pg_catalog.jsonb_array_length(inventory->'facts') OR findings_count<>pg_catalog.jsonb_array_length(inventory->'findings') OR collections_count<>8 OR target_count<>1 THEN RAISE EXCEPTION 'inventory omits or adds locked records'; END IF;
  PERFORM aegaeon.subject_history_validate_union(manifest,inventory);
  FOR item IN SELECT pg_catalog.jsonb_array_elements(manifest->'owners') LOOP
    INSERT INTO aegaeon.end_user_identity_owners(owner_id,environment_id) VALUES ((item->>'owner_id')::uuid,env_id) ON CONFLICT DO NOTHING;
    IF NOT EXISTS(SELECT FROM aegaeon.end_user_identity_owners o WHERE o.owner_id=(item->>'owner_id')::uuid AND o.environment_id=env_id) THEN RAISE EXCEPTION 'historical UUID environment conflict'; END IF;
  END LOOP;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(manifest->'reservations') LOOP
    INSERT INTO aegaeon.end_user_subject_reservations(environment_id,subject,owner_id) VALUES (env_id,item->>'subject',(item->>'owner_id')::uuid) ON CONFLICT DO NOTHING;
    IF NOT EXISTS(SELECT FROM aegaeon.end_user_subject_reservations r WHERE r.environment_id=env_id AND r.subject=(item->>'subject') COLLATE "C" AND r.owner_id=(item->>'owner_id')::uuid) THEN RAISE EXCEPTION 'historical subject ownership conflict'; END IF;
  END LOOP;
  SELECT e.tenant_id,t.team_id INTO tenant,team FROM aegaeon.environments e JOIN aegaeon.tenants t ON t.id=e.tenant_id WHERE e.id=env_id;
  owner_count := pg_catalog.jsonb_array_length(manifest->'owners'); reservation_count := pg_catalog.jsonb_array_length(manifest->'reservations');
  summary := pg_catalog.jsonb_build_object('receiptId',receipt_uuid,'manifestSha256',expected_manifest_sha256,'inventorySha256',expected_inventory_sha256,
    'ownerCount',owner_count,'reservationCount',reservation_count,'invalidHistoryCount',pg_catalog.jsonb_array_length(manifest->'invalid_history'),
    'sourceCount',pg_catalog.jsonb_array_length(manifest->'sources'),'sessionActor',session_user,'effectiveActor',actor,'definerActor',current_user,
    'maintenanceReference',manifest->>'maintenance_reference','externalCompletenessPremise',true,'directSqlDoesNotVerifyLocalSourceBytes',true,'directSqlDoesNotVerifyInstallingFileBytes',true);
  INSERT INTO aegaeon.audit_events(team_id,tenant_id,environment_id,event_type,category,outcome,severity,occurred_at,actor_type,actor_id,target_type,target_id,request_id,data)
    VALUES (team,tenant,env_id,'subject_ownership.history_adopted.v1','CONTROL_PLANE','SUCCESS','INFO',pg_catalog.clock_timestamp(),'MAINTENANCE',actor,'ENVIRONMENT',env_id::text,receipt_uuid::text,summary);
  INSERT INTO aegaeon.subject_ownership_adoptions(environment_id,kind,receipt_id,session_actor,effective_actor,definer_actor,maintenance_reference,manifest_sha256,inventory_sha256,receipt_data)
    VALUES (env_id,'legacy',receipt_uuid,session_user,actor,current_user,manifest->>'maintenance_reference',expected_manifest_sha256,expected_inventory_sha256,
      summary||pg_catalog.jsonb_build_object('sources',manifest->'sources','completeness',manifest->'completeness','target',manifest->'target','inventory',manifest->'inventory'));
  environment_id:=env_id; receipt_id:=receipt_uuid; manifest_sha256:=expected_manifest_sha256; inventory_sha256:=expected_inventory_sha256;
  session_actor:=session_user; effective_actor:=actor; definer_actor:=current_user; RETURN NEXT;
END
$function$;


--
-- Name: enforce_account_link_connection_binding(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.enforce_account_link_connection_binding() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM "aegaeon"."connections" c
    WHERE c."id" = NEW."connection_id"
      AND c."environment_id" = NEW."environment_id"
      AND c."issuer_url" = NEW."upstream_issuer"
  ) THEN
    RAISE EXCEPTION 'account link connection issuer mismatch'
      USING ERRCODE = '23514',
            CONSTRAINT = 'account_links_connection_issuer_matches';
  END IF;

  IF NEW."upstream_refresh_token_connection_id" IS NOT NULL
     AND NEW."upstream_refresh_token_connection_id" <> NEW."connection_id" THEN
    RAISE EXCEPTION 'account link refresh token connection mismatch'
      USING ERRCODE = '23514',
            CONSTRAINT = 'account_links_refresh_connection_matches';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: enforce_environment_lifecycle_invariants(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.enforce_environment_lifecycle_invariants() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.status = 'ACTIVE'::"aegaeon"."environment_status" THEN
    PERFORM 1
    FROM "aegaeon"."tenants" t
    JOIN "aegaeon"."teams" team
      ON team.id = t.team_id
    WHERE t.id = NEW.tenant_id
      AND t.status = 'ACTIVE'::"aegaeon"."tenant_status"
      AND team.status = 'ACTIVE'::"aegaeon"."team_status"
    FOR UPDATE OF team, t;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'active environment requires active tenant and team'
        USING ERRCODE = '23514',
              CONSTRAINT = 'environments_parent_tenant_team_active';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: enforce_team_lifecycle_invariants(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.enforce_team_lifecycle_invariants() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.status = 'DELETED'::"aegaeon"."team_status"
     AND OLD.status IS DISTINCT FROM NEW.status
     AND EXISTS (
       SELECT 1
       FROM "aegaeon"."tenants" t
       WHERE t.team_id = NEW.id
         AND t.status = 'ACTIVE'::"aegaeon"."tenant_status"
     ) THEN
    RAISE EXCEPTION 'team has active tenants'
      USING ERRCODE = '23514',
            CONSTRAINT = 'teams_no_active_tenants_when_deleted';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: enforce_tenant_lifecycle_invariants(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.enforce_tenant_lifecycle_invariants() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.status = 'ACTIVE'::"aegaeon"."tenant_status" THEN
    PERFORM 1
    FROM "aegaeon"."teams" team
    WHERE team.id = NEW.team_id
      AND team.status = 'ACTIVE'::"aegaeon"."team_status"
    FOR UPDATE;

    IF NOT FOUND THEN
      RAISE EXCEPTION 'active tenant requires active team'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenants_parent_team_active';
    END IF;
  END IF;

  IF NEW.status = 'DELETED'::"aegaeon"."tenant_status"
     AND (TG_OP = 'INSERT' OR OLD.status IS DISTINCT FROM NEW.status)
     AND EXISTS (
       SELECT 1
       FROM "aegaeon"."environments" e
       WHERE e.tenant_id = NEW.id
         AND e.status = 'ACTIVE'::"aegaeon"."environment_status"
     ) THEN
    RAISE EXCEPTION 'tenant has active environments'
      USING ERRCODE = '23514',
            CONSTRAINT = 'tenants_no_active_environments_when_deleted';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: inventory_subject_ownership_history_v1(uuid, text, text, jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.inventory_subject_ownership_history_v1(environment_id uuid, deployment_id text, runtime_role text, tool_source_identity jsonb)
RETURNS TABLE(record_type text, row_key text, payload text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD' SET intervalstyle = 'postgres' SET extra_float_digits = 3
AS $function$
BEGIN
  PERFORM aegaeon.subject_history_maintenance_actor();
  PERFORM aegaeon.subject_history_lock();
  RETURN QUERY SELECT * FROM aegaeon.subject_history_inventory_stream(environment_id,deployment_id,runtime_role,tool_source_identity);
END
$function$;


--
-- Name: notify_runtime_authority_changed(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.notify_runtime_authority_changed() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  old_environment_id uuid;
  new_environment_id uuid;
  old_team_id uuid;
  new_team_id uuid;
  old_tenant_id uuid;
  new_tenant_id uuid;
  old_issuer_host text;
  new_issuer_host text;
  affected_environment_ids uuid[] := ARRAY[]::uuid[];
  affected_issuer_hosts text[] := ARRAY[]::text[];
BEGIN
  IF TG_TABLE_NAME = 'teams' THEN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
      old_team_id := OLD.id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
      new_team_id := NEW.id;
    END IF;

    SELECT COALESCE(array_agg(DISTINCT e.id ORDER BY e.id), ARRAY[]::uuid[])
      INTO affected_environment_ids
    FROM "aegaeon"."environments" e
    JOIN "aegaeon"."tenants" t ON t.id = e.tenant_id
    WHERE t.team_id = ANY (ARRAY_REMOVE(ARRAY[old_team_id, new_team_id], NULL));
  ELSIF TG_TABLE_NAME = 'tenants' THEN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
      old_tenant_id := OLD.id;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
      new_tenant_id := NEW.id;
    END IF;

    SELECT COALESCE(array_agg(DISTINCT e.id ORDER BY e.id), ARRAY[]::uuid[])
      INTO affected_environment_ids
    FROM "aegaeon"."environments" e
    WHERE e.tenant_id = ANY (ARRAY_REMOVE(ARRAY[old_tenant_id, new_tenant_id], NULL));
  ELSE
    IF TG_TABLE_NAME = 'environments' THEN
      IF TG_OP IN ('UPDATE', 'DELETE') THEN
        old_environment_id := OLD.id;
        old_issuer_host := OLD.issuer_host;
      END IF;
      IF TG_OP IN ('INSERT', 'UPDATE') THEN
        new_environment_id := NEW.id;
        new_issuer_host := NEW.issuer_host;
      END IF;
    ELSE
      IF TG_OP IN ('UPDATE', 'DELETE') THEN
        old_environment_id := OLD.environment_id;
      END IF;
      IF TG_OP IN ('INSERT', 'UPDATE') THEN
        new_environment_id := NEW.environment_id;
      END IF;
    END IF;

    SELECT COALESCE(array_agg(DISTINCT environment_id ORDER BY environment_id), ARRAY[]::uuid[])
      INTO affected_environment_ids
    FROM unnest(ARRAY_REMOVE(ARRAY[old_environment_id, new_environment_id], NULL))
      AS affected(environment_id);
  END IF;

  WITH issuer_hosts(host) AS (
    SELECT e.issuer_host
    FROM "aegaeon"."environments" e
    WHERE e.id = ANY (affected_environment_ids)
    UNION
    SELECT old_issuer_host
    WHERE old_issuer_host IS NOT NULL
    UNION
    SELECT new_issuer_host
    WHERE new_issuer_host IS NOT NULL
  )
  SELECT COALESCE(array_agg(DISTINCT host ORDER BY host), ARRAY[]::text[])
    INTO affected_issuer_hosts
  FROM issuer_hosts
  WHERE btrim(host) <> '';

  PERFORM pg_notify(
    'aegaeon_runtime_authority_changed',
    jsonb_build_object(
      'schema', TG_TABLE_SCHEMA,
      'table', TG_TABLE_NAME,
      'operation', TG_OP,
      'txid', txid_current(),
      'environmentIds', to_jsonb(affected_environment_ids),
      'issuerHosts', to_jsonb(affected_issuer_hosts)
    )::text
  );

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;


--
-- Name: oauth_scope_token_array_is_valid(text[]); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.oauth_scope_token_array_is_valid(p_values text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
  SELECT COALESCE(
    "p_values" IS NOT NULL
    AND cardinality("p_values") = COALESCE((
      SELECT count(DISTINCT "scope"."value")::integer
      FROM unnest("p_values") AS "scope"("value")
    ), 0)
    AND NOT EXISTS (
      SELECT 1
      FROM unnest("p_values") AS "scope"("value")
      WHERE "scope"."value" IS NULL
        OR NOT "aegaeon"."oauth_scope_token_is_valid"("scope"."value")
    ),
    false
  );
$$;


--
-- Name: oauth_scope_token_is_valid(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.oauth_scope_token_is_valid(p_value text) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
  SELECT COALESCE(
    "p_value" <> ''
    AND octet_length("p_value") = length("p_value")
    AND NOT EXISTS (
      SELECT 1
      FROM generate_series(1, length("p_value")) AS "scope_char"("position")
      WHERE NOT (
        ascii(substr("p_value", "scope_char"."position", 1)) = 33
        OR ascii(substr("p_value", "scope_char"."position", 1)) BETWEEN 35 AND 91
        OR ascii(substr("p_value", "scope_char"."position", 1)) BETWEEN 93 AND 126
      )
    ),
    false
  );
$$;


--
-- Name: prevent_connection_issuer_url_update(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.prevent_connection_issuer_url_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF OLD."issuer_url" IS DISTINCT FROM NEW."issuer_url" THEN
    RAISE EXCEPTION 'connection issuer_url is immutable'
      USING ERRCODE = '23514',
            CONSTRAINT = 'connections_issuer_url_immutable';
  END IF;

  RETURN NEW;
END;
$$;


--
-- Name: subject_history_chain_end(bytea, bigint); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_chain_end(previous bytea, row_count bigint) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT pg_catalog.encode(pg_catalog.sha256('\x02'::bytea || previous || pg_catalog.int8send(row_count)), 'hex')
$function$;


--
-- Name: subject_history_chain_row(bytea, bigint, text, text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_chain_row(previous bytea, row_position bigint, row_key text, row_text text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT pg_catalog.sha256('\x01'::bytea || previous || pg_catalog.int8send(row_position)
   || aegaeon.subject_history_frame(pg_catalog.convert_to(row_key, 'UTF8'))
   || pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to(row_text, 'UTF8'))))
$function$;


--
-- Name: subject_history_chain_start(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_chain_start(collection text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to('aegaeon-subject-inventory-v1', 'UTF8'))
   || aegaeon.subject_history_frame(pg_catalog.convert_to(collection, 'UTF8')))
$function$;


--
-- Name: subject_history_check_maintenance_role(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_check_maintenance_role(actor_name text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE actor_oid oid; reachable record; relation_row record;
BEGIN
    SELECT oid INTO actor_oid FROM pg_catalog.pg_roles WHERE rolname=actor_name;
    FOR reachable IN SELECT * FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(actor_oid,r.oid,'USAGE') OR pg_catalog.pg_has_role(actor_oid,r.oid,'SET') LOOP
      IF reachable.rolsuper OR reachable.rolcreatedb OR reachable.rolcreaterole OR reachable.rolreplication OR reachable.rolbypassrls
        OR reachable.rolname='aegaeon_subject_owner'
        OR pg_catalog.has_schema_privilege(reachable.oid,'aegaeon','CREATE')
        OR pg_catalog.has_parameter_privilege(reachable.oid,'session_replication_role','SET') THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor can bypass protected authority';
      END IF;
      FOR relation_row IN SELECT c.oid,c.relowner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
        WHERE (n.nspname='aegaeon' AND (c.relname IN ('environments','end_users','tenants','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations')
          OR c.oid IN (SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass))))
          OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
        IF reachable.oid=relation_row.relowner OR pg_catalog.has_table_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR pg_catalog.has_any_column_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
          RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor requires EXECUTE-only source authority';
        END IF;
      END LOOP;
      IF EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname IN
            ('subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert'))
          AND (pg_catalog.has_function_privilege(reachable.oid,p.oid,'EXECUTE')
            OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'USAGE') OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'SET'))) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor can execute private authority helpers';
      END IF;
    END LOOP;
END
$function$;


--
-- Name: subject_history_check_runtime_role(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_check_runtime_role(runtime_name text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE runtime_id oid; entry_id oid; reachable record; role_row record; relation_row record; schema_owner oid;
BEGIN
  SELECT * INTO role_row FROM pg_catalog.pg_roles WHERE rolname = runtime_name;
  IF NOT FOUND OR NOT role_row.rolcanlogin OR role_row.rolsuper OR role_row.rolcreatedb
     OR role_row.rolcreaterole OR role_row.rolreplication OR role_row.rolbypassrls THEN
    RAISE EXCEPTION 'subject runtime role is not a restricted login';
  END IF;
  entry_id := role_row.oid;
  FOR reachable IN SELECT oid FROM pg_catalog.pg_roles r WHERE pg_catalog.pg_has_role(entry_id,r.oid,'USAGE') OR pg_catalog.pg_has_role(entry_id,r.oid,'SET') LOOP
  runtime_id := reachable.oid;
  IF pg_catalog.has_schema_privilege(runtime_id, 'aegaeon', 'CREATE')
     OR pg_catalog.has_parameter_privilege(runtime_id, 'session_replication_role', 'SET') THEN
    RAISE EXCEPTION 'subject runtime can bypass protected schema guards';
  END IF;
  SELECT nspowner INTO schema_owner FROM pg_catalog.pg_namespace WHERE nspname = 'aegaeon';
  IF pg_catalog.pg_has_role(runtime_id, schema_owner, 'USAGE') OR pg_catalog.pg_has_role(runtime_id, schema_owner, 'SET') THEN
    RAISE EXCEPTION 'subject runtime can assume schema ownership';
  END IF;
  FOR role_row IN SELECT * FROM pg_catalog.pg_roles
      WHERE rolname IN ('aegaeon_subject_owner', 'aegaeon_subject_maintenance')
         OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls LOOP
    IF pg_catalog.pg_has_role(runtime_id, role_row.oid, 'USAGE') OR pg_catalog.pg_has_role(runtime_id, role_row.oid, 'SET') THEN
      RAISE EXCEPTION 'subject runtime can assume protected or administrative authority';
    END IF;
  END LOOP;
  FOR relation_row IN SELECT c.oid, c.relname, c.relowner FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE (n.nspname = 'aegaeon' AND c.relname IN ('environments', 'end_users',
        'subject_ownership_namespaces', 'subject_ownership_adoptions',
        'end_user_identity_owners', 'end_user_subject_reservations'))
        OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
    IF pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'USAGE')
       OR pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'SET') THEN
      RAISE EXCEPTION 'subject runtime can assume ownership of a guarded table';
    END IF;
    IF pg_catalog.has_table_privilege(runtime_id, relation_row.oid, 'TRIGGER') THEN
      RAISE EXCEPTION 'subject runtime can install competing identity triggers';
    END IF;
    IF relation_row.relname NOT IN ('environments', 'end_users')
       AND (pg_catalog.has_table_privilege(runtime_id, relation_row.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')
         OR pg_catalog.has_any_column_privilege(runtime_id, relation_row.oid, 'INSERT,UPDATE')) THEN
      RAISE EXCEPTION 'subject runtime has permanent authority mutation privileges';
    END IF;
  END LOOP;
  IF EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='aegaeon'
      AND (p.proname LIKE 'subject_history_%' OR p.proname IN
        ('subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert',
         'inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1'))
      AND (pg_catalog.has_function_privilege(runtime_id, p.oid, 'EXECUTE')
        OR pg_catalog.pg_has_role(runtime_id,p.proowner,'USAGE') OR pg_catalog.pg_has_role(runtime_id,p.proowner,'SET'))) THEN
    RAISE EXCEPTION 'subject runtime can execute or own protected maintenance helpers';
  END IF;
  END LOOP;
END
$function$;


--
-- Name: subject_history_classify(text, text, text, uuid); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_classify(collection_name text, source_key text, source_text text, target_environment uuid)
RETURNS TABLE(record_type text, payload jsonb)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE value jsonb := source_text::jsonb; source_hash text;
  env_id uuid; identity_id uuid; event_name text; known_environment boolean;
  target_owner text; data_owner text; field_name text; observed text; fact jsonb;
  owner_values jsonb := '[]'::jsonb; subject_values jsonb := '[]'::jsonb; fact_values jsonb := '[]'::jsonb;
  recognized boolean; malformed boolean := false; fields text[]; field_origin text;
  uuid_pattern text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
BEGIN
  source_hash := pg_catalog.encode(pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to(source_text,'UTF8'))),'hex');
  IF collection_name NOT IN ('end_users','end_user_identity_owners','end_user_subject_reservations','audit_events') THEN RETURN; END IF;
  env_id := (value->>'environment_id')::uuid;
  IF collection_name <> 'audit_events' THEN
    identity_id := COALESCE(value->>'owner_id',value->>'id')::uuid;
    field_origin := CASE collection_name WHEN 'end_users' THEN 'current_user' WHEN 'end_user_identity_owners' THEN 'permanent_owner' ELSE 'permanent_reservation' END;
    observed := value->>'subject';
    IF collection_name <> 'end_user_identity_owners' AND NOT COALESCE(aegaeon.subject_ownership_valid_subject(observed),false) THEN RAISE EXCEPTION 'current or permanent subject corruption'; END IF;
    record_type := 'fact'; payload := aegaeon.subject_history_fact(field_origin,source_key,source_hash,env_id,identity_id,observed); RETURN NEXT; RETURN;
  END IF;
  event_name := value->>'event_type';
  known_environment := env_id IS NOT NULL AND EXISTS(SELECT FROM aegaeon.environments WHERE id=env_id);
  target_owner := value->>'target_id'; data_owner := value->'data'->>'userId';
  IF pg_catalog.jsonb_typeof(value->'target_id')='string' THEN owner_values := owner_values || pg_catalog.jsonb_build_array(target_owner); END IF;
  IF pg_catalog.jsonb_typeof(value->'data'->'userId')='string' AND data_owner IS DISTINCT FROM target_owner THEN owner_values := owner_values || pg_catalog.jsonb_build_array(data_owner); END IF;
  recognized := value->>'category'='CONTROL_PLANE' AND value->>'outcome'='SUCCESS' AND value->>'target_type'='END_USER'
    AND known_environment AND target_owner ~ uuid_pattern AND data_owner=target_owner
    AND event_name IN ('management.user.created.v1','management.user.invited.v1','management.user.imported.v1',
      'management.user.updated.v1','management.user.deleted.v1','management.user.restored.v1','management.user.suspended.v1','management.user.reactivated.v1');
  fields := CASE WHEN event_name IN ('management.user.created.v1','management.user.invited.v1','management.user.imported.v1')
      THEN ARRAY['subject'] ELSE ARRAY['previous','current'] END;
  IF recognized THEN
    identity_id := target_owner::uuid;
    FOR field_name IN SELECT pg_catalog.unnest(fields) LOOP
      IF field_name='subject' THEN
        observed := CASE WHEN pg_catalog.jsonb_typeof(value->'data'->'subject')='string' THEN value->'data'->>'subject' END;
        field_origin := 'management_create_subject';
      ELSE
        observed := CASE WHEN pg_catalog.jsonb_typeof(value->'data'->field_name->'subject')='string' THEN value->'data'->field_name->>'subject' END;
        field_origin := CASE field_name WHEN 'previous' THEN 'management_previous_subject' ELSE 'management_current_subject' END;
      END IF;
      fact := aegaeon.subject_history_fact(field_origin,source_key||':'||field_name,source_hash,env_id,identity_id,observed);
      record_type := 'fact'; payload := fact; RETURN NEXT;
      fact_values := fact_values || pg_catalog.jsonb_build_array(fact->>'fact_id');
      IF observed IS NULL THEN malformed := true;
      ELSIF NOT aegaeon.subject_ownership_valid_subject(observed) THEN
        record_type := 'finding'; payload := aegaeon.subject_history_finding(CASE WHEN env_id<>target_environment THEN 'outside_target' ELSE 'invalid_history' END,event_name,source_key||':'||field_name,source_hash,env_id,
          pg_catalog.jsonb_build_array(identity_id),pg_catalog.jsonb_build_array(observed),pg_catalog.jsonb_build_array(fact->>'fact_id')); RETURN NEXT;
      END IF;
    END LOOP;
    IF malformed THEN record_type := 'finding'; payload := aegaeon.subject_history_finding(CASE WHEN env_id<>target_environment THEN 'outside_target' ELSE 'malformed_event' END,event_name,source_key||':malformed',source_hash,env_id,owner_values,subject_values,fact_values); RETURN NEXT; END IF;
    RETURN;
  END IF;
  -- Preserve each invalid disclosure's exact field location, including ambiguous
  -- management and subject-only provisioning rows. Observations are not facts.
  IF event_name='upstream.user.provision.authorized.v1' THEN owner_values := '[]'::jsonb; END IF;
  FOR field_name, observed IN
    SELECT location,s FROM (
      SELECT 'data.subject' AS location,value->'data'->>'subject' AS s WHERE pg_catalog.jsonb_typeof(value->'data'->'subject')='string'
      UNION ALL SELECT 'data.previous.subject',value->'data'->'previous'->>'subject' WHERE pg_catalog.jsonb_typeof(value->'data'->'previous'->'subject')='string'
      UNION ALL SELECT 'data.current.subject',value->'data'->'current'->>'subject' WHERE pg_catalog.jsonb_typeof(value->'data'->'current'->'subject')='string'
      UNION ALL SELECT 'actor_id',value->>'actor_id' WHERE event_name='upstream.user.provision.authorized.v1' AND pg_catalog.jsonb_typeof(value->'actor_id')='string'
      UNION ALL SELECT 'target_id',value->>'target_id' WHERE event_name='upstream.user.provision.authorized.v1' AND pg_catalog.jsonb_typeof(value->'target_id')='string'
    ) observations ORDER BY location COLLATE "C"
  LOOP
    IF NOT subject_values @> pg_catalog.jsonb_build_array(observed) THEN subject_values := subject_values || pg_catalog.jsonb_build_array(observed); END IF;
    IF NOT aegaeon.subject_ownership_valid_subject(observed) THEN
      record_type := 'finding'; payload := aegaeon.subject_history_finding(
        CASE WHEN env_id<>target_environment THEN 'outside_target' ELSE 'invalid_history' END,
        event_name,source_key||':'||field_name,source_hash,env_id,owner_values,pg_catalog.jsonb_build_array(observed),'[]'::jsonb); RETURN NEXT;
    END IF;
  END LOOP;
  record_type := 'finding';
  payload := aegaeon.subject_history_finding(CASE
    WHEN env_id IS NOT NULL AND env_id<>target_environment THEN 'outside_target'
    WHEN NOT known_environment THEN 'unscoped_event'
    WHEN pg_catalog.jsonb_array_length(subject_values)>0 AND (event_name='upstream.user.provision.authorized.v1' OR event_name LIKE 'management.user.%') THEN 'unknown_owner'
    WHEN pg_catalog.jsonb_array_length(owner_values)>0 OR event_name LIKE 'management.user.%' THEN 'malformed_event'
    ELSE 'unknown_event' END,event_name,source_key,source_hash,env_id,owner_values,subject_values,fact_values);
  RETURN NEXT;
END
$function$;


--
-- Name: subject_history_content_id(text, text[], text[]); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_content_id(domain text, tags text[], fields text[]) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE encoded bytea; i integer;
BEGIN
  IF domain IS NULL OR tags IS NULL OR fields IS NULL OR pg_catalog.cardinality(tags)<>pg_catalog.cardinality(fields) THEN RAISE EXCEPTION 'invalid content ID fields'; END IF;
  encoded := aegaeon.subject_history_frame(pg_catalog.convert_to(domain,'UTF8'));
  FOR i IN 1..pg_catalog.cardinality(fields) LOOP
    IF fields[i] IS NULL THEN encoded := encoded || '\x00'::bytea;
    ELSE encoded := encoded || '\x01'::bytea || aegaeon.subject_history_frame(pg_catalog.convert_to(tags[i],'UTF8')) || aegaeon.subject_history_frame(pg_catalog.convert_to(fields[i],'UTF8')); END IF;
  END LOOP;
  RETURN pg_catalog.encode(pg_catalog.sha256(encoded),'hex');
END
$function$;


--
-- Name: subject_history_document_schema(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_document_schema(document_kind text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF document_kind='manifest' THEN RETURN $schema${"$schema":"https://json-schema.org/draft/2020-12/schema","$comment":"Strict raw JSON parsing additionally rejects decoded duplicate keys, NUL, BOM, noncanonical integer lexical forms, excess bytes and depth. Semantic validation enforces cross references, source coverage, ordered identities and ownership preservation. JSON Schema alone does not establish adoption.","type":"object","properties":{"format":{"const":"aegaeon-subject-ownership-adoption"},"version":{"const":1},"receipt_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"namespace":{"$ref":"#/$defs/namespace"},"target":{"$ref":"#/$defs/target"},"inventory":{"type":"object","properties":{"artifact_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"state_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"findings_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["artifact_sha256","state_sha256","findings_sha256"],"additionalProperties":false},"sources":{"type":"array","items":{"$ref":"#/$defs/source"},"maxItems":256},"owners":{"type":"array","items":{"$ref":"#/$defs/owner"},"maxItems":1000000},"reservations":{"type":"array","items":{"$ref":"#/$defs/reservation"},"maxItems":1000000},"invalid_history":{"type":"array","items":{"$ref":"#/$defs/invalidHistory"},"maxItems":1000000},"resolutions":{"type":"array","items":{"$ref":"#/$defs/resolution"},"maxItems":1000000},"completeness":{"$ref":"#/$defs/completeness"},"maintenance_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024}},"required":["format","version","receipt_id","namespace","target","inventory","sources","owners","reservations","invalid_history","resolutions","completeness","maintenance_reference"],"additionalProperties":false,"$defs":{"namespace":{"type":"object","properties":{"environment_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"issuer_host":{"type":"string","minLength":1}},"required":["environment_id","issuer_host"],"additionalProperties":false},"target":{"type":"object","properties":{"deployment_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"runtime_role":{"type":"string","minLength":1,"maxLength":63},"database_name":{"type":"string","minLength":1,"maxLength":63},"database_oid":{"type":"integer","minimum":1,"maximum":4294967295},"server_version_num":{"type":"integer","minimum":1,"maximum":9223372036854775807},"server_encoding":{"const":"UTF8"},"schema_revision":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"schema_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"catalog_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"tool_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_commit":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{40}$"},{"type":"null"}]},"source_tree":{"type":"string","pattern":"^[0-9a-f]{40}$"},"dirty_input_sha256":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{64}$"},{"type":"null"}]}},"required":["deployment_id","runtime_role","database_name","database_oid","server_version_num","server_encoding","schema_revision","schema_sha256","catalog_sha256","tool_sha256","source_commit","source_tree","dirty_input_sha256"],"additionalProperties":false},"source":{"type":"object","properties":{"source_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"kind":{"enum":["current_snapshot","audit_snapshot","external_journal","retained_backup","reconstruction","invalid_history_evidence","completeness_attestation"]},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"byte_length":{"type":"integer","minimum":0,"maximum":9223372036854775807},"private_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"provenance_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"environment_ids":{"type":"array","items":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"uniqueItems":true,"minItems":1},"coverage_start_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"coverage_end_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024}},"required":["source_id","kind","sha256","byte_length","private_reference","provenance_reference","environment_ids","coverage_start_reference","coverage_end_reference"],"additionalProperties":false},"owner":{"type":"object","properties":{"owner_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"environment_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256}},"required":["owner_id","environment_id","source_refs"],"additionalProperties":false},"reservation":{"type":"object","properties":{"subject":{"type":"string","x-aegaeon-domain":"subject"},"owner_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256}},"required":["subject","owner_id","source_refs"],"additionalProperties":false},"invalidHistory":{"type":"object","properties":{"observation_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"owner_id":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},{"type":"null"}]},"evidence_source":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256}},"required":["observation_id","owner_id","evidence_source","source_refs"],"additionalProperties":false},"resolution":{"oneOf":[{"type":"object","properties":{"finding_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256},"review_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"kind":{"const":"reconstructed_ownership"},"owners":{"type":"array","items":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"uniqueItems":true},"subjects":{"type":"array","items":{"type":"object","properties":{"subject":{"type":"string","x-aegaeon-domain":"subject"},"owner_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}},"required":["subject","owner_id"],"additionalProperties":false},"uniqueItems":true}},"required":["finding_id","source_refs","review_reference","kind","owners","subjects"],"additionalProperties":false},{"type":"object","properties":{"finding_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256},"review_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"kind":{"const":"outside_target"},"environment_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"}},"required":["finding_id","source_refs","review_reference","kind","environment_id"],"additionalProperties":false},{"type":"object","properties":{"finding_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256},"review_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"kind":{"const":"no_ownership_effect"}},"required":["finding_id","source_refs","review_reference","kind"],"additionalProperties":false},{"type":"object","properties":{"finding_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_refs":{"type":"array","items":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"uniqueItems":true,"minItems":1,"maxItems":256},"review_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"kind":{"const":"invalid_disclosure_retained"},"observation_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"owner_id":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},{"type":"null"}]},"evidence_source":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}},"required":["finding_id","source_refs","review_reference","kind","observation_id","owner_id","evidence_source"],"additionalProperties":false}]},"completeness":{"type":"object","properties":{"assertion":{"const":"complete-history-for-this-namespace"},"namespace_start_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"coverage_end_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"complete_valid_subject_history":{"const":true},"complete_owner_uuid_history":{"const":true},"owner_uuid_environment_bindings_complete":{"const":true},"sources_exhaustive":{"const":true},"unresolved_findings":{"const":0},"asserted_by":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"authority_reference":{"type":"string","pattern":"^[ -~]+$","minLength":1,"maxLength":1024},"attestation_source":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}},"required":["assertion","namespace_start_reference","coverage_end_reference","complete_valid_subject_history","complete_owner_uuid_history","owner_uuid_environment_bindings_complete","sources_exhaustive","unresolved_findings","asserted_by","authority_reference","attestation_source"],"additionalProperties":false}}}$schema$::jsonb; END IF;
  IF document_kind='inventory' THEN RETURN $schema${"$schema":"https://json-schema.org/draft/2020-12/schema","$comment":"Strict raw JSON parsing additionally rejects decoded duplicate keys, NUL, BOM, noncanonical integer lexical forms, excess bytes and depth. Semantic validation enforces cross references, source coverage, ordered identities and ownership preservation. JSON Schema alone does not establish adoption.","type":"object","properties":{"format":{"const":"aegaeon-subject-ownership-inventory"},"version":{"const":1},"namespace":{"$ref":"#/$defs/namespace"},"target":{"$ref":"#/$defs/target"},"collections":{"type":"array","prefixItems":[{"type":"object","properties":{"name":{"const":"environments"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"subject_ownership_namespaces"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"subject_ownership_adoptions"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"end_user_identity_owners"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"end_user_subject_reservations"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"end_users"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"audit_events"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false},{"type":"object","properties":{"name":{"const":"physical_catalog"},"count":{"type":"integer","minimum":0,"maximum":9223372036854775807},"sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["name","count","sha256"],"additionalProperties":false}],"items":false,"minItems":8,"maxItems":8},"state_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"facts":{"type":"array","items":{"$ref":"#/$defs/fact"}},"findings":{"type":"array","items":{"$ref":"#/$defs/finding"}},"findings_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}},"required":["format","version","namespace","target","collections","state_sha256","facts","findings","findings_sha256"],"additionalProperties":false,"$defs":{"namespace":{"type":"object","properties":{"environment_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"issuer_host":{"type":"string","pattern":"^[^\\u0000]*$","minLength":1}},"required":["environment_id","issuer_host"],"additionalProperties":false},"target":{"type":"object","properties":{"deployment_id":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"runtime_role":{"type":"string","pattern":"^[^\\u0000]*$","minLength":1,"maxLength":63},"database_name":{"type":"string","pattern":"^[^\\u0000]*$","minLength":1,"maxLength":63},"database_oid":{"type":"integer","minimum":1,"maximum":4294967295},"server_version_num":{"type":"integer","minimum":1,"maximum":9223372036854775807},"server_encoding":{"const":"UTF8"},"schema_revision":{"type":"string","pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"},"schema_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"catalog_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"tool_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"source_commit":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{40}$"},{"type":"null"}]},"source_tree":{"type":"string","pattern":"^[0-9a-f]{40}$"},"dirty_input_sha256":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{64}$"},{"type":"null"}]}},"required":["deployment_id","runtime_role","database_name","database_oid","server_version_num","server_encoding","schema_revision","schema_sha256","catalog_sha256","tool_sha256","source_commit","source_tree","dirty_input_sha256"],"additionalProperties":false},"fact":{"type":"object","properties":{"fact_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"origin":{"enum":["current_user","permanent_owner","permanent_reservation","management_create_subject","management_previous_subject","management_current_subject"]},"row_key":{"type":"string","pattern":"^[^\\u0000]*$","minLength":1},"row_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"environment_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"owner_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},"subject":{"oneOf":[{"type":"string","pattern":"^[^\\u0000]*$"},{"type":"null"}]},"valid":{"type":"boolean"}},"required":["fact_id","origin","row_key","row_sha256","environment_id","owner_id","subject","valid"],"additionalProperties":false},"finding":{"type":"object","properties":{"finding_id":{"type":"string","pattern":"^[0-9a-f]{64}$"},"class":{"enum":["unknown_event","malformed_event","unknown_owner","unscoped_event","invalid_history","ownership_conflict","outside_target"]},"origin":{"type":"string","pattern":"^[^\\u0000]*$"},"row_key":{"type":"string","pattern":"^[^\\u0000]*$","minLength":1},"row_sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"},"environment_id":{"oneOf":[{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},{"type":"null"}]},"observed_owner_ids":{"type":"array","items":{"type":"string"},"uniqueItems":true},"observed_subjects":{"type":"array","items":{"type":"string","pattern":"^[^\\u0000]*$"},"uniqueItems":true},"preserved_fact_ids":{"type":"array","items":{"type":"string","pattern":"^[0-9a-f]{64}$"},"uniqueItems":true}},"required":["finding_id","class","origin","row_key","row_sha256","environment_id","observed_owner_ids","observed_subjects","preserved_fact_ids"],"additionalProperties":false}}}$schema$::jsonb; END IF;
  RAISE EXCEPTION 'unknown history document kind';
END
$function$;


--
-- Name: subject_history_fact(text, text, text, uuid, uuid, text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_fact(origin_name text, source_key text, source_hash text,
  env_id uuid, identity_id uuid, observed_subject text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE valid_subject boolean; content_hash text;
BEGIN
  valid_subject := COALESCE(aegaeon.subject_ownership_valid_subject(observed_subject),false);
  content_hash := aegaeon.subject_history_content_id('aegaeon-subject-fact-v1',
    ARRAY['origin','row_key','sha256','uuid','uuid','text','boolean'],
    ARRAY[origin_name,source_key,source_hash,env_id::text,identity_id::text,observed_subject,valid_subject::text]);
  RETURN pg_catalog.jsonb_build_object('fact_id',content_hash,'origin',origin_name,'row_key',source_key,
    'row_sha256',source_hash,'environment_id',env_id,'owner_id',identity_id,'subject',observed_subject,'valid',valid_subject);
END
$function$;


--
-- Name: subject_history_finding(text, text, text, text, uuid, jsonb, jsonb, jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_finding(class_name text, origin_name text, source_key text, source_hash text,
  env_id uuid, observed_owners jsonb, observed_subjects jsonb, preserved_facts jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT pg_catalog.jsonb_build_object('finding_id',aegaeon.subject_history_content_id('aegaeon-subject-finding-v1',
   ARRAY['class','origin','row_key','sha256'],ARRAY[class_name,origin_name,source_key,source_hash]),
   'class',class_name,'origin',origin_name,'row_key',source_key,'row_sha256',source_hash,'environment_id',env_id,
   'observed_owner_ids',observed_owners,'observed_subjects',observed_subjects,'preserved_fact_ids',preserved_facts)
$function$;


--
-- Name: subject_history_frame(bytea); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_frame(value bytea) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT pg_catalog.int8send(pg_catalog.octet_length(value)::bigint) || value
$function$;


--
-- Name: subject_history_identity_event(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_identity_event(event_name text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
 SELECT event_name IN ('management.user.created.v1','management.user.invited.v1','management.user.imported.v1',
   'management.user.updated.v1','management.user.deleted.v1','management.user.restored.v1','management.user.suspended.v1',
   'management.user.reactivated.v1','upstream.user.provision.authorized.v1')
$function$;


--
-- Name: subject_history_inventory_stream(uuid, text, text, jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_inventory_stream(target_environment uuid, deployment_name text, runtime_name text, tool_identity jsonb)
RETURNS TABLE(record_type text, row_key text, payload text)
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD' SET intervalstyle = 'postgres' SET extra_float_digits = 3
AS $function$
DECLARE names text[] := ARRAY['environments','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','audit_events','physical_catalog'];
  hashes bytea[] := ARRAY[]::bytea[]; counts bigint[] := ARRAY[0,0,0,0,0,0,0,0]::bigint[];
  source_row record; classified record; i integer; metadata jsonb; state_hash bytea; findings_hash bytea; finding_count bigint:=0;
  physical_contract_hash text; namespace_value jsonb; target_value jsonb; catalog_hash text;
BEGIN
  PERFORM aegaeon.subject_history_require_keys(tool_identity,ARRAY['tool_sha256','source_commit','source_tree','dirty_input_sha256']);
  PERFORM aegaeon.subject_history_require_string(tool_identity->'tool_sha256','sha256');
  PERFORM aegaeon.subject_history_require_string(tool_identity->'source_tree','git');
  IF tool_identity->'source_commit'<>'null'::jsonb THEN PERFORM aegaeon.subject_history_require_string(tool_identity->'source_commit','git'); END IF;
  IF tool_identity->'dirty_input_sha256'<>'null'::jsonb THEN PERFORM aegaeon.subject_history_require_string(tool_identity->'dirty_input_sha256','sha256'); END IF;
  IF tool_identity->'source_commit'='null'::jsonb AND tool_identity->'dirty_input_sha256'='null'::jsonb THEN RAISE EXCEPTION 'history tool source identity is incomplete'; END IF;
  PERFORM aegaeon.subject_history_require_string(pg_catalog.to_jsonb(deployment_name),'identifier');
  PERFORM aegaeon.subject_history_require_string(pg_catalog.to_jsonb(runtime_name),'role');
  physical_contract_hash := aegaeon.subject_history_preflight(runtime_name);
  SELECT pg_catalog.jsonb_build_object('environment_id',n.environment_id,'issuer_host',n.issuer_host) INTO namespace_value
    FROM aegaeon.subject_ownership_namespaces n JOIN aegaeon.environments e ON e.id=n.environment_id AND e.issuer_host=n.issuer_host
    WHERE n.environment_id=target_environment;
  IF namespace_value IS NULL THEN RAISE EXCEPTION 'subject history target namespace is missing or inconsistent'; END IF;
  FOR i IN 1..8 LOOP hashes[i] := aegaeon.subject_history_chain_start(names[i]); END LOOP;
  FOR source_row IN SELECT * FROM aegaeon.subject_history_source_rows(runtime_name) LOOP
    i := pg_catalog.array_position(names,source_row.collection_name);
    counts[i] := counts[i]+1;
    hashes[i] := aegaeon.subject_history_chain_row(hashes[i],counts[i],source_row.row_key,source_row.row_text);
    record_type := 'source:'||source_row.collection_name; row_key := source_row.row_key; payload := source_row.row_text; RETURN NEXT;
    FOR classified IN SELECT * FROM aegaeon.subject_history_classify(source_row.collection_name,source_row.row_key,source_row.row_text,target_environment) LOOP
      record_type := classified.record_type;
      row_key := CASE record_type WHEN 'fact' THEN classified.payload->>'fact_id' ELSE classified.payload->>'finding_id' END;
      payload := classified.payload::text; RETURN NEXT;
    END LOOP;
  END LOOP;
  state_hash := aegaeon.subject_history_chain_start('state');
  FOR i IN 1..8 LOOP
    metadata := pg_catalog.jsonb_build_object('name',names[i],'count',counts[i],'sha256',aegaeon.subject_history_chain_end(hashes[i],counts[i]));
    state_hash := aegaeon.subject_history_chain_row(state_hash,i,names[i],metadata::text);
    record_type := 'collection'; row_key := names[i]; payload := metadata::text; RETURN NEXT;
  END LOOP;
  catalog_hash := aegaeon.subject_history_chain_end(hashes[8],counts[8]);
  target_value := pg_catalog.jsonb_build_object('deployment_id',deployment_name,'runtime_role',runtime_name,
    'database_name',pg_catalog.current_database(),'database_oid',(SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),
    'server_version_num',pg_catalog.current_setting('server_version_num')::bigint,'server_encoding',pg_catalog.current_setting('server_encoding'),
    'schema_revision','20261002130000','schema_sha256',physical_contract_hash,'catalog_sha256',catalog_hash)||tool_identity;
  -- Repeat the fixed read under the same physical locks to sort finding IDs. The
  -- executor may spill its sort; no database-wide bytea concatenation occurs.
  findings_hash := aegaeon.subject_history_chain_start('findings');
  FOR classified IN SELECT c.payload FROM aegaeon.subject_history_source_rows(runtime_name) r
      CROSS JOIN LATERAL aegaeon.subject_history_classify(r.collection_name,r.row_key,r.row_text,target_environment) c
      WHERE c.record_type='finding' ORDER BY (c.payload->>'finding_id') COLLATE "C" LOOP
    finding_count := finding_count+1;
    findings_hash := aegaeon.subject_history_chain_row(findings_hash,finding_count,classified.payload->>'finding_id',classified.payload::text);
  END LOOP;
  record_type := 'observed_target'; row_key := target_environment::text;
  payload := pg_catalog.jsonb_build_object('namespace',namespace_value,'target',target_value,
    'state_sha256',aegaeon.subject_history_chain_end(state_hash,8),
    'findings_sha256',aegaeon.subject_history_chain_end(findings_hash,finding_count))::text; RETURN NEXT;
END
$function$;


--
-- Name: subject_history_key(text[]); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_key(parts text[]) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE part text; encoded bytea := ''::bytea;
BEGIN
  FOREACH part IN ARRAY parts LOOP
    IF part IS NULL THEN RAISE EXCEPTION 'null inventory key component'; END IF;
    encoded := encoded || aegaeon.subject_history_frame(pg_catalog.convert_to(part,'UTF8'));
  END LOOP;
  RETURN pg_catalog.encode(encoded,'hex');
END
$function$;


--
-- Name: subject_history_lock(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_lock() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE partition_row record;
BEGIN
  PERFORM pg_catalog.pg_advisory_xact_lock(1095059265, 1398096433);
  LOCK TABLE aegaeon.environments IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_ownership_namespaces IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_ownership_adoptions IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_user_identity_owners IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_user_subject_reservations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.end_users IN SHARE ROW EXCLUSIVE MODE;
  -- Parent ACCESS EXCLUSIVE excludes DML and ATTACH/DETACH before enumeration.
  LOCK TABLE ONLY aegaeon.audit_events IN ACCESS EXCLUSIVE MODE;
  FOR partition_row IN SELECT c.oid, n.nspname, c.relname
      FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE t.level > 0 ORDER BY c.oid LOOP
    -- Identifiers originate only in the locked physical catalog, never manifest input.
    EXECUTE pg_catalog.format('LOCK TABLE ONLY %I.%I IN ACCESS EXCLUSIVE MODE', partition_row.nspname, partition_row.relname);
  END LOOP;
  PERFORM aegaeon.subject_history_lock_revisions();
END
$function$;


--
-- Name: subject_history_lock_revisions(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_lock_revisions() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE relation_name regclass := aegaeon.subject_history_revision_relation();
BEGIN
  EXECUTE pg_catalog.format('LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE',relation_name);
END
$function$;


--
-- Name: subject_history_maintenance_actor(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_maintenance_actor() RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE entry_role text := pg_catalog.current_setting('role');
BEGIN
  IF entry_role = 'none' THEN entry_role := session_user; END IF;
  IF NOT pg_catalog.pg_has_role(session_user,'aegaeon_subject_maintenance','MEMBER')
    OR NOT pg_catalog.pg_has_role(entry_role,'aegaeon_subject_maintenance','USAGE') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='subject history maintenance authority required';
  END IF;
  PERFORM aegaeon.subject_history_check_maintenance_role(session_user);
  PERFORM aegaeon.subject_history_check_maintenance_role(entry_role);
  RETURN entry_role;
END
$function$;


--
-- Name: subject_history_observed_physical(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_observed_physical() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
SELECT pg_catalog.jsonb_build_object(
'columns',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'collation',co.collname,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname COLLATE "C",a.attnum) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','environments') AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',con.conname,'definition',pg_catalog.pg_get_constraintdef(con.oid,false),'validated',con.convalidated,'deferrable',con.condeferrable,'deferred',con.condeferred) ORDER BY c.relname COLLATE "C",con.conname COLLATE "C") FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid=con.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','environments')),
'triggers',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',t.tgname,'type',t.tgtype,'function',p.proname,'enabled',t.tgenabled,'arguments',pg_catalog.encode(t.tgargs,'hex'),'qualifier',pg_catalog.pg_get_expr(t.tgqual,t.tgrelid)) ORDER BY c.relname COLLATE "C",t.tgname COLLATE "C") FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','environments') AND NOT t.tgisinternal)
);
$function$;


--
-- Name: subject_history_parse_document(bytea, text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_parse_document(raw bytea, document_kind text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE parsed json; value jsonb; shape jsonb; max_bytes bigint; combined bigint;
BEGIN
  max_bytes := CASE document_kind WHEN 'manifest' THEN 67108864 WHEN 'inventory' THEN 268435456 ELSE NULL END;
  IF raw IS NULL OR max_bytes IS NULL OR pg_catalog.octet_length(raw)>max_bytes THEN RAISE EXCEPTION 'unsupported history document size or kind'; END IF;
  parsed := pg_catalog.convert_from(raw,'UTF8')::json;
  PERFORM aegaeon.subject_history_strict_json(parsed);
  -- This count precedes conversion to the materialized JSONB document.
  IF document_kind='manifest' THEN
    SELECT sum(pg_catalog.json_array_length(val)) INTO combined FROM pg_catalog.json_each(parsed) fields(key,val)
      WHERE key IN ('owners','reservations','invalid_history','resolutions');
    IF combined>1000000 THEN RAISE EXCEPTION 'combined history entry limit exceeded'; END IF;
  END IF;
  value := parsed::jsonb;
  shape := aegaeon.subject_history_document_schema(document_kind);
  PERFORM aegaeon.subject_history_validate_shape(value,shape,shape->'$defs');
  IF (value->'target'->>'source_commit') IS NULL AND (value->'target'->>'dirty_input_sha256') IS NULL THEN RAISE EXCEPTION 'history build provenance is incomplete'; END IF;
  IF pg_catalog.octet_length(value->'target'->>'runtime_role')>63 OR pg_catalog.octet_length(value->'target'->>'database_name')>63 THEN RAISE EXCEPTION 'database identifier byte limit exceeded'; END IF;
  RETURN value;
END
$function$;


--
-- Name: subject_history_physical_catalog(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_physical_catalog(runtime_name text)
RETURNS TABLE(row_key text, row_text text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
 WITH protected_relations AS (
   SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','audit_events',
      'subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations')
   UNION SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass)
   UNION SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')
 ), rows(kind, key, value) AS (
   SELECT 'namespace', n.oid::text, pg_catalog.to_jsonb(n) FROM pg_catalog.pg_namespace n WHERE n.nspname='aegaeon'
   UNION ALL SELECT 'relation',c.oid::text,pg_catalog.jsonb_build_object(
      'oid',c.oid,'relname',c.relname,'relnamespace',c.relnamespace,'reltype',c.reltype,
      'relowner',c.relowner,'relkind',c.relkind,'relpersistence',c.relpersistence,
      'relispartition',c.relispartition,'relpartbound',c.relpartbound::text,
      'relrowsecurity',c.relrowsecurity,'relforcerowsecurity',c.relforcerowsecurity,
      'relreplident',c.relreplident,'relacl',c.relacl,'reloptions',c.reloptions)
      FROM pg_catalog.pg_class c WHERE c.oid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'column',a.attrelid::text||':'||a.attnum::text,pg_catalog.to_jsonb(a) FROM pg_catalog.pg_attribute a WHERE a.attrelid IN (SELECT oid FROM protected_relations) AND a.attnum>0
   UNION ALL SELECT 'default',d.oid::text,pg_catalog.to_jsonb(d)||pg_catalog.jsonb_build_object('expression',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) FROM pg_catalog.pg_attrdef d WHERE d.adrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'type',t.oid::text,pg_catalog.to_jsonb(t) FROM pg_catalog.pg_type t WHERE t.oid IN (SELECT atttypid FROM pg_catalog.pg_attribute WHERE attrelid IN (SELECT oid FROM protected_relations))
   UNION ALL SELECT 'collation',c.oid::text,pg_catalog.to_jsonb(c) FROM pg_catalog.pg_collation c WHERE c.oid IN (SELECT attcollation FROM pg_catalog.pg_attribute WHERE attrelid IN (SELECT oid FROM protected_relations))
   UNION ALL SELECT 'constraint',c.oid::text,pg_catalog.to_jsonb(c)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_constraintdef(c.oid,true)) FROM pg_catalog.pg_constraint c WHERE c.conrelid IN (SELECT oid FROM protected_relations) OR c.confrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'index',i.indexrelid::text,pg_catalog.to_jsonb(i)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_indexdef(i.indexrelid)) FROM pg_catalog.pg_index i WHERE i.indrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'trigger',t.oid::text,pg_catalog.to_jsonb(t)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_triggerdef(t.oid,true)) FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'partition',i.inhrelid::text||':'||i.inhparent::text,pg_catalog.to_jsonb(i) FROM pg_catalog.pg_inherits i WHERE i.inhrelid IN (SELECT oid FROM protected_relations)
   UNION ALL SELECT 'function',p.oid::text,pg_catalog.to_jsonb(p)||pg_catalog.jsonb_build_object('definition',pg_catalog.pg_get_functiondef(p.oid),'acl',
      (SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('grantee',COALESCE(r.rolname,'PUBLIC'),'privilege',a.privilege_type,'grantable',a.is_grantable) ORDER BY a.grantee,a.privilege_type)
       FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee)) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname LIKE 'subject_ownership_%' OR p.proname IN ('inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1','validate_subject_ownership_namespace_v1'))
   UNION ALL SELECT 'role',r.oid::text,pg_catalog.to_jsonb(r) FROM pg_catalog.pg_roles r
   UNION ALL SELECT 'membership',m.roleid::text||':'||m.member::text||':'||m.grantor::text,pg_catalog.to_jsonb(m) FROM pg_catalog.pg_auth_members m
   UNION ALL SELECT 'parameter_acl',p.oid::text,pg_catalog.to_jsonb(p) FROM pg_catalog.pg_parameter_acl p
   UNION ALL SELECT 'atlas_revision',r.row_key,r.row_text::jsonb FROM aegaeon.subject_history_revision_rows() r
   UNION ALL SELECT 'runtime_role',runtime_name,pg_catalog.jsonb_build_object('runtime_role',runtime_name)
 ) SELECT kind||':'||key, value::text FROM rows ORDER BY kind COLLATE "C",key COLLATE "C"
$function$;


--
-- Name: subject_history_preflight(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_preflight(runtime_name text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE expected jsonb := $physical${"columns":[{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":"C"},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"end_users","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_users","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_users","collation":"C"},{"name":"email","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"status","type":"aegaeon.end_user_status","default":"'INVITED'::aegaeon.end_user_status","not_null":true,"relation":"end_users","collation":null},{"name":"blocked_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"end_users","collation":null},{"name":"blocked_reason","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"environments","collation":null},{"name":"tenant_id","type":"uuid","default":null,"not_null":true,"relation":"environments","collation":null},{"name":"name","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"slug","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_url","type":"text","default":"('https://'::text || issuer_host)","not_null":false,"relation":"environments","collation":"default"},{"name":"active_configuration_version_id","type":"uuid","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"status","type":"aegaeon.environment_status","default":"'ACTIVE'::aegaeon.environment_status","not_null":true,"relation":"environments","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"deleted_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"kind","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"session_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"effective_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"definer_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"maintenance_reference","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"manifest_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"inventory_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_data","type":"jsonb","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"origin","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_namespaces","collation":null}],"triggers":[{"name":"end_user_identity_owners_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null},{"name":"end_user_identity_owners_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null},{"relation":"end_user_identity_owners","name":"end_user_identity_owners_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"end_user_subject_reservations_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null},{"name":"end_user_subject_reservations_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null},{"relation":"end_user_subject_reservations","name":"end_user_subject_reservations_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"end_users_subject_ownership","type":23,"enabled":"O","function":"subject_ownership_guard_user","relation":"end_users","arguments":"","qualifier":null},{"name":"environments_lifecycle_invariants","type":23,"enabled":"O","function":"enforce_environment_lifecycle_invariants","relation":"environments","arguments":"","qualifier":null},{"name":"environments_subject_namespace_immutable","type":19,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null},{"name":"environments_subject_namespace_initialize","type":5,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null},{"name":"runtime_authority_notify_environments","type":29,"enabled":"O","function":"notify_runtime_authority_changed","relation":"environments","arguments":"","qualifier":null},{"name":"subject_ownership_adoptions_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null},{"name":"subject_ownership_adoptions_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null},{"relation":"subject_ownership_adoptions","name":"subject_ownership_adoptions_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"subject_ownership_namespaces_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null},{"name":"subject_ownership_namespaces_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null},{"relation":"subject_ownership_namespaces","name":"subject_ownership_namespaces_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null}],"constraints":[{"name":"end_user_identity_owners_environment_id_fkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_identity_owners_environment_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_identity_owners_owner_id_environment_id_key","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"UNIQUE (owner_id, environment_id)"},{"name":"end_user_identity_owners_owner_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_identity_owners_pkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"PRIMARY KEY (owner_id)"},{"name":"end_user_identity_owners_recorded_at_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_subject_reservations_environment_id_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_subject_reservations_environment_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_subject_reservations_owner_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_subject_reservations_pkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, subject)"},{"name":"end_user_subject_reservations_recorded_at_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_subject_reservations_subject_check","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_user_subject_reservations_subject_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"subject_reservations_owner_environment_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (owner_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id) ON DELETE RESTRICT"},{"name":"end_users_created_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"end_users_email_lowercase","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (((email IS NULL) OR (email = lower(email))))"},{"name":"end_users_environment_id_fkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"end_users_environment_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_users_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"end_users_pkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"end_users_status_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"end_users_subject_format","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_users_subject_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"end_users_updated_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"environments_active_configuration_version_same_environment_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (id, active_configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT"},{"name":"environments_created_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"environments_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"environments_issuer_host_check","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((issuer_host = lower(issuer_host)) AND (POSITION(('://'::text) IN (issuer_host)) = 0) AND (POSITION(('/'::text) IN (issuer_host)) = 0) AND (POSITION(('?'::text) IN (issuer_host)) = 0) AND (POSITION(('#'::text) IN (issuer_host)) = 0)))"},{"name":"environments_issuer_host_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"environments_name_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL name"},{"name":"environments_pkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"environments_slug_dns_label","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug))))"},{"name":"environments_slug_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL slug"},{"name":"environments_status_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"environments_tenant_id_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT"},{"name":"environments_tenant_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL tenant_id"},{"name":"environments_updated_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"subject_ownership_adoptions_contract_version_check","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_adoptions_contract_version_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_adoptions_definer_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL definer_actor"},{"name":"subject_ownership_adoptions_effective_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL effective_actor"},{"name":"subject_ownership_adoptions_environment_id_kind_fkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, kind) REFERENCES aegaeon.subject_ownership_namespaces(environment_id, origin) ON DELETE RESTRICT"},{"name":"subject_ownership_adoptions_environment_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_adoptions_kind_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL kind"},{"name":"subject_ownership_adoptions_pkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_adoptions_receipt_id_key","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"UNIQUE (receipt_id)"},{"name":"subject_ownership_adoptions_receipt_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL receipt_id"},{"name":"subject_ownership_adoptions_recorded_at_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"subject_ownership_adoptions_session_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"subject_ownership_adoptions_shape","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((((kind = 'fresh'::text) AND (maintenance_reference IS NULL) AND (manifest_sha256 IS NULL) AND (inventory_sha256 IS NULL) AND (receipt_data IS NULL)) OR ((kind = 'legacy'::text) AND (maintenance_reference IS NOT NULL) AND (manifest_sha256 IS NOT NULL) AND (inventory_sha256 IS NOT NULL) AND (manifest_sha256 ~ '^[0-9a-f]{64}$'::text) AND (inventory_sha256 ~ '^[0-9a-f]{64}$'::text) AND (receipt_data IS NOT NULL))))"},{"name":"subject_ownership_namespaces_contract_version_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_namespaces_contract_version_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_namespaces_environment_id_fkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"subject_ownership_namespaces_environment_id_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_namespaces_environment_id_origin_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, origin)"},{"name":"subject_ownership_namespaces_issuer_host_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (issuer_host)"},{"name":"subject_ownership_namespaces_issuer_host_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"subject_ownership_namespaces_origin_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((origin = ANY (ARRAY['legacy'::text, 'fresh'::text])))"},{"name":"subject_ownership_namespaces_origin_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL origin"},{"name":"subject_ownership_namespaces_pkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_namespaces_recorded_at_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"}]}$physical$::jsonb;
  expected_functions jsonb := $functions$[{"signature":"aegaeon.subject_ownership_valid_subject(text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"fc9882541afc9a780cb6caf80c97d96fe8be21e62568205f8e7ef7be2b349eb6","settings":["search_path=pg_catalog, pg_temp"],"result":"boolean","defaults":null},{"signature":"aegaeon.subject_ownership_guard_insert()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"52b9475146e50d85310a14c71ead5c119d0b6b202f8bb521928c36c46739497f","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_immutable()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"c365d747fb17ea03ac06aa4612a993663f3dbf74c6fb47240fcdc856d159d9d2","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_guard_environment()","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"6406ec1158669d7225bb0c5e09595ab2517e849df4cbf892c652628e46cb2d58","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_guard_user()","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"9614948221b7e5aa281211f40a79a7536c465ba5d5fa6dd091eb4fb29668c34d","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_history_frame(bytea)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"73af3455a9d9ed6d84a6b2d177850c382d37cc03538db945d99ed4e50c6536c5","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_start(text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"6a89cf6cfeaf7b67228160c980a685d2340106c53c81d5d282cc68f7a8d30444","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_row(bytea,bigint,text,text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"995e91e793b4bb0b8441035c374ae62c48afd83b1fc79f4731b976377d441599","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_end(bytea,bigint)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"00c46633113a05cbd996b6bc36d9fb55874d2c964a4ca1675188756bc5067290","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_strict_json(json,integer)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"de16f880ea0c9ff4ef15676b05d2cb42b1fd86ef1c760563de9cbf323f0b38bd","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":"0"},{"signature":"aegaeon.subject_history_require_keys(jsonb,text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"5b3e7a080c1ad342fc617a2d11632708df22395107c024a631b22775ab998324","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_require_string(jsonb,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"d51baf6bfdfe6c472679c279e366dd8bbba63140694a9a8f7e7e8d39483d61d6","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_check_maintenance_role(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"d3b883c26eceb4192fd1fe9b88d2b73948f4cbfa25757bb8710b8b9e01377988","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_maintenance_actor()","language":"plpgsql","security_definer":true,"volatility":"s","strict":false,"body_sha256":"8d62d6f1ac5189b60e6a0553e4e361109776468f33a8de1c6064e3bfe0e981ee","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_check_runtime_role(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"789fe6e645490247957e59769567a73fac51b2d4d02977a6dd8cf0c5b46f62f8","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_lock()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"627ee964ca9d785f28708042e3aee5f60f08e702b30be583eb16d17c98460786","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_revision_relation()","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"d64c499c2301b4ba5c0d25a375434dbd0a4d6321e8db419d8ca7773e5f5575c4","settings":["search_path=pg_catalog, pg_temp"],"result":"regclass","defaults":null},{"signature":"aegaeon.subject_history_revision_rows()","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"1674cf69df8522d842fb678547ea047d64db68293a702421e42d44610a3bf73d","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_lock_revisions()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"4504247c9f8d02f60f728d5a13778bc37c0f065e1949f8ee1cf24e4a1d3e28b3","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_physical_catalog(text)","language":"sql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"dab1b87fa17049d8d9cf2360ddc85e31743c43b117ddab3a574bace7b015e342","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_key(text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"8ae3364074e7f5b84b1f36e23fc893d5c55b64fb9db00d8ebce3fceb467dce39","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_source_rows(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"a0625351b63ad3180f2b0898f847ef5b30e4653548273174c2272f452c2f2567","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(collection_name text, row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_content_id(text,text[],text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"f857b4ccabedc2c61d12ab699db33a8d7bd24cb5c46c15a57e5fe75d731c9250","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_fact(text,text,text,uuid,uuid,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"50c81e2960f390c6395fe4ff7c1eafd9e70d1a8c06703f52dc3e5d7c2963b072","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_finding(text,text,text,text,uuid,jsonb,jsonb,jsonb)","language":"sql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"5e48222af63e3b68f8c9889789b307ca9898ad44a34b3dd0f9521d457e24b42e","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_classify(text,text,text,uuid)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"4234db1e406f61682c13c52bd27c5809d261a08fe19a92656f7d35ea6a421314","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(record_type text, payload jsonb)","defaults":null},{"signature":"aegaeon.subject_history_document_schema(text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"39cd34d015032e888a7ae344126f163f624b415bed7e1aa11107af3396d6f875","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_validate_shape(jsonb,jsonb,jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"1d4453458e87bed963c4d3519234082e48e4ba3a657b8a249a0e53306cb67a09","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_parse_document(bytea,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"b18bc5ce79110960ba66a2e5aca7f6c1707c82bb2c1bdbaa9cfb53c523884b16","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_source_refs(jsonb,jsonb,text,boolean)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"f67403f7dbc56971dbac94e03f488a3c480a43e9c17d1be31c614b7b514f357b","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_validate_manifest(jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"091c069b1d18676295e2f107c96512ed006e2f985886798bf6a62888e4dba071","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_observed_physical()","language":"sql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"3c4962a3121741e8da7f4b7346622ce78d0d7095ac5b9da4c5144c5c007d067d","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_inventory_stream(uuid,text,text,jsonb)","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"f69b9ea02f5329bf7fe4a13882f1ba2a1eb05ba78ff2a6bef8e9f72be13b6e35","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null},{"signature":"aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb)","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"163a5a4186fb6931bfe5ad36b37b8b2009442665ad37700c43140e4a28aca6ed","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null},{"signature":"aegaeon.subject_history_identity_event(text)","language":"sql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"6089a7cc7506b6b595b0cc0dd16e9973b8207fe3bc98d325c61e2c9dcb2cf7ef","settings":["search_path=pg_catalog, pg_temp"],"result":"boolean","defaults":null},{"signature":"aegaeon.subject_history_validate_union(jsonb,jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"8483684ad930becb24f663ea50086cfc7c6249dc6d109ff0ac8858906d11d6f4","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text)","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"403dd259b7863e50b410efbcabf3baade2321926d6e64ae535bc20966dc642f0","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(environment_id uuid, receipt_id uuid, manifest_sha256 text, inventory_sha256 text, session_actor text, effective_actor text, definer_actor text, owner_count bigint, reservation_count bigint)","defaults":null},{"signature":"aegaeon.validate_subject_ownership_namespace_v1(uuid)","language":"plpgsql","security_definer":true,"volatility":"s","strict":false,"body_sha256":"6edd9f6fe332c899235ccf1f8be4f8af146796ceb17719386d27252b99753c06","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null}]$functions$::jsonb;
  expected_revisions jsonb := $revisions$[{"version":"20260803140000","description":"baseline","sha256_base64":"MiEiQpBNweRvDKhVVt17w7Td1YklwRIaQ6GXfRwCmjE="},{"version":"20260909070000","description":"authorization_consents","sha256_base64":"PEdKG9v67t73TfECEz8BkuHoh0DaH7/pS57dHwGWEWY="},{"version":"20260909090000","description":"authorization_logins","sha256_base64":"z9IBFYQfQuCGGm08Ndc50Q461gDjhRzOu3YJUQ98ij8="},{"version":"20260909120000","description":"token_exchange_policy","sha256_base64":"r6cY8qHe7i1SBvcCYCy5KX2WY/YHAQr3p04fLN7SZyo="},{"version":"20260911090000","description":"application_authorizations","sha256_base64":"X4s7SL8Qx+0r+dZtKEg3rSOsFikvh0zoyFuZsAE4Vn4="},{"version":"20260913090000","description":"application_authorization_identities","sha256_base64":"EVIREfQ3EgynjVT8qwujTqVIvaNzLfAUvyPYIxUBaL0="},{"version":"20260930090000","description":"client_credentials_policy","sha256_base64":"7hvvi5YVMmIdeLRyVJ4DZodwsU41SzCBxvBBybrguVg="},{"version":"20261002130000","description":"subject_ownership","sha256_base64":null}]$revisions$::jsonb;
  actual jsonb; item jsonb; observed record; identity regprocedure; seen text[]:=ARRAY[]::text[]; revision_id text; digest_value text;
BEGIN
  IF pg_catalog.current_setting('server_encoding')<>'UTF8' OR pg_catalog.current_setting('server_version_num')::integer/10000<>18 THEN RAISE EXCEPTION 'unsupported subject history PostgreSQL supplier'; END IF;
  PERFORM aegaeon.subject_history_check_runtime_role(runtime_name);
  IF (SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('aegaeon_subject_owner','aegaeon_subject_maintenance')
      AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))<>2
    OR EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE member IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole))
    OR pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE')
    OR pg_catalog.has_schema_privilege('aegaeon_subject_maintenance','aegaeon','CREATE') THEN RAISE EXCEPTION 'subject authority role shape is incompatible'; END IF;
  -- Validate every explicitly enrolled maintenance member, not just this caller.
  -- pg_has_role(superuser,...) is deliberately not a membership enumeration.
  FOR observed IN WITH RECURSIVE members(oid) AS (
      SELECT 'aegaeon_subject_maintenance'::regrole::oid
      UNION SELECT a.member FROM pg_catalog.pg_auth_members a JOIN members m ON a.roleid=m.oid
    ) SELECT r.rolname FROM members m JOIN pg_catalog.pg_roles r ON r.oid=m.oid LOOP
    PERFORM aegaeon.subject_history_check_maintenance_role(observed.rolname);
  END LOOP;
  actual := aegaeon.subject_history_observed_physical();
  IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'subject physical schema or trigger definition mismatch'; END IF;
  IF EXISTS(SELECT FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations')
      AND (c.relkind<>'r' OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity
        OR (c.relname NOT IN ('environments','end_users') AND c.relowner<>'aegaeon_subject_owner'::regrole))) THEN RAISE EXCEPTION 'subject relation authority mismatch'; END IF;
  -- The complete audit corpus is an input, including every attached partition.
  -- Never let owner/bypass differences turn an inventory into a filtered view.
  IF EXISTS(SELECT FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid
      WHERE c.relrowsecurity OR c.relforcerowsecurity) THEN
    RAISE EXCEPTION 'subject audit corpus row security is unsupported';
  END IF;
  IF EXISTS(SELECT FROM pg_catalog.pg_constraint con
      JOIN pg_catalog.pg_class c ON c.oid=con.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_catalog.pg_index i ON i.indexrelid=con.conindid
      WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations')
        AND con.contype IN ('p','u') AND (i.indexrelid IS NULL OR NOT i.indisunique
          OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate
          OR i.indpred IS NOT NULL OR i.indexprs IS NOT NULL)) THEN
    RAISE EXCEPTION 'subject ownership key index is not a valid immediate unique authority';
  END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(expected->'triggers') LOOP
    IF NOT EXISTS(SELECT FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname=item->>'relation' AND t.tgname=item->>'name'
        AND t.tgfoid=pg_catalog.to_regprocedure('aegaeon.'||(item->>'function')||'()') AND t.tgconstraint=0) THEN RAISE EXCEPTION 'subject trigger function binding mismatch'; END IF;
  END LOOP;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(expected_functions) LOOP
    identity := pg_catalog.to_regprocedure(item->>'signature');
    IF identity IS NULL THEN RAISE EXCEPTION 'subject protected function is missing'; END IF;
    SELECT p.*,l.lanname INTO observed FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_language l ON l.oid=p.prolang WHERE p.oid=identity;
    IF observed.proowner<>'aegaeon_subject_owner'::regrole
       OR observed.prosecdef IS DISTINCT FROM (item->>'security_definer')::boolean
       OR observed.provolatile::text<>item->>'volatility' OR observed.lanname<>item->>'language'
       OR observed.proisstrict IS DISTINCT FROM (item->>'strict')::boolean
       OR pg_catalog.pg_get_function_result(identity) IS DISTINCT FROM item->>'result'
       OR pg_catalog.pg_get_expr(observed.proargdefaults,0) IS DISTINCT FROM item->>'defaults'
       OR pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(observed.prosrc,'UTF8')),'hex')<>item->>'body_sha256'
       OR (SELECT pg_catalog.jsonb_agg(pg_catalog.lower(v) ORDER BY pg_catalog.lower(v) COLLATE "C") FROM pg_catalog.unnest(observed.proconfig) settings(v)) IS DISTINCT FROM item->'settings'
    THEN RAISE EXCEPTION 'subject protected function definition mismatch'; END IF;
  END LOOP;
  FOR observed IN SELECT * FROM aegaeon.subject_history_revision_rows() LOOP
    actual := observed.row_text::jsonb; revision_id := actual->>'version';
    SELECT value INTO item FROM pg_catalog.jsonb_array_elements(expected_revisions) fields(value)
      WHERE revision_id=value->>'version' OR revision_id=(value->>'version')||'_'||(value->>'description');
    IF item IS NULL OR (item->>'version')=ANY(seen) THEN RAISE EXCEPTION 'unexpected or duplicate Atlas revision'; END IF;
    seen := pg_catalog.array_append(seen,item->>'version');
    IF actual->>'description' IS DISTINCT FROM item->>'description'
      OR (actual->>'applied') IS NULL OR (actual->>'total') IS NULL OR (actual->>'total')::bigint<=0
      OR (actual->>'applied')::bigint<>(actual->>'total')::bigint OR COALESCE(actual->>'error','')<>'' THEN RAISE EXCEPTION 'incomplete Atlas revision state'; END IF;
    digest_value := pg_catalog.regexp_replace(actual->>'hash','^h1:','');
    IF digest_value IS NULL OR digest_value !~ '^[A-Za-z0-9+/]{43}=$' THEN RAISE EXCEPTION 'invalid Atlas revision hash'; END IF;
    IF item->>'sha256_base64' IS NOT NULL AND digest_value<>item->>'sha256_base64' THEN RAISE EXCEPTION 'predecessor Atlas revision hash mismatch'; END IF;
  END LOOP;
  IF pg_catalog.cardinality(seen)<>pg_catalog.jsonb_array_length(expected_revisions) THEN RAISE EXCEPTION 'missing Atlas revision'; END IF;
  -- This version identifies the expected physical contract, not this file's hash.
  RETURN pg_catalog.encode(pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to('aegaeon-subject-physical-v1','UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected::text,'UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected_functions::text,'UTF8'))
    ||aegaeon.subject_history_frame(pg_catalog.convert_to(expected_revisions::text,'UTF8'))),'hex');
END
$function$;


--
-- Name: subject_history_require_keys(jsonb, text[]); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_require_keys(value jsonb, required_keys text[]) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE actual_keys text[];
BEGIN
  IF pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history object required'; END IF;
  SELECT pg_catalog.array_agg(key ORDER BY key COLLATE "C") INTO actual_keys FROM pg_catalog.jsonb_object_keys(value) AS keys(key);
  IF COALESCE(actual_keys, ARRAY[]::text[]) IS DISTINCT FROM
     ARRAY(SELECT key FROM pg_catalog.unnest(required_keys) AS keys(key) ORDER BY key COLLATE "C") THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history object has unknown or missing members';
  END IF;
END
$function$;


--
-- Name: subject_history_require_string(jsonb, text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_require_string(value jsonb, kind text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE result text; valid boolean := false;
BEGIN
  IF pg_catalog.jsonb_typeof(value) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'history string required'; END IF;
  result := value #>> ARRAY[]::text[];
  CASE kind
  WHEN 'uuid' THEN valid := result ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
  WHEN 'sha256' THEN valid := result ~ '^[0-9a-f]{64}$';
  WHEN 'git' THEN valid := result ~ '^[0-9a-f]{40}$';
  WHEN 'identifier' THEN valid := result COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$';
  WHEN 'reference' THEN valid := pg_catalog.octet_length(result) BETWEEN 1 AND 1024 AND result COLLATE "C" ~ '^[ -~]+$';
  WHEN 'subject' THEN valid := aegaeon.subject_ownership_valid_subject(result);
  WHEN 'database_name' THEN valid := pg_catalog.octet_length(result) BETWEEN 1 AND 63;
  WHEN 'role' THEN valid := pg_catalog.octet_length(result) BETWEEN 1 AND 63;
  ELSE RAISE EXCEPTION 'unknown fixed history string domain';
  END CASE;
  IF NOT valid THEN RAISE EXCEPTION 'history string does not satisfy required domain'; END IF;
  RETURN result;
END
$function$;


--
-- Name: subject_history_revision_relation(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_revision_relation() RETURNS regclass
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE relation_id oid; relation_count bigint;
BEGIN
  SELECT count(*),min(c.oid) INTO relation_count,relation_id FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon') AND c.relkind='r';
  IF relation_count<>1 THEN RAISE EXCEPTION 'one fixed-schema Atlas revision relation required'; END IF;
  RETURN relation_id::regclass;
END
$function$;


--
-- Name: subject_history_revision_rows(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_revision_rows() RETURNS TABLE(row_key text,row_text text)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD' SET intervalstyle = 'postgres' SET extra_float_digits = 3
AS $function$
DECLARE relation_name regclass := aegaeon.subject_history_revision_relation();
BEGIN
  RETURN QUERY EXECUTE pg_catalog.format('SELECT r.version::text,pg_catalog.to_jsonb(r)::text FROM %s r ORDER BY r.version COLLATE "C"',relation_name);
END
$function$;


--
-- Name: subject_history_source_refs(jsonb, jsonb, text, boolean); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_source_refs(refs jsonb, sources jsonb, env_id text, reconstruction boolean) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE source_id text; source_value jsonb; external_evidence boolean := false;
BEGIN
  FOR source_id IN SELECT pg_catalog.jsonb_array_elements_text(refs) LOOP
    source_value := sources->source_id;
    IF source_value IS NULL OR NOT (source_value->'environment_ids') @> pg_catalog.jsonb_build_array(env_id) THEN RAISE EXCEPTION 'history source missing or outside asserted environment'; END IF;
    external_evidence := external_evidence OR ((source_value->>'kind') IN ('external_journal','retained_backup','reconstruction') AND (source_value->>'byte_length')::bigint>0);
  END LOOP;
  IF reconstruction AND NOT external_evidence THEN RAISE EXCEPTION 'external reconstruction evidence required'; END IF;
END
$function$;


--
-- Name: subject_history_source_rows(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_source_rows(runtime_name text)
RETURNS TABLE(collection_name text, row_key text, row_text text)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD' SET intervalstyle = 'postgres' SET extra_float_digits = 3
AS $function$
BEGIN
  IF pg_catalog.current_setting('server_encoding') <> 'UTF8' THEN RAISE EXCEPTION 'subject history requires UTF8 database'; END IF;
  RETURN QUERY SELECT 'environments'::text,e.id::text,pg_catalog.to_jsonb(e)::text FROM aegaeon.environments e ORDER BY e.id;
  RETURN QUERY SELECT 'subject_ownership_namespaces'::text,n.environment_id::text,pg_catalog.to_jsonb(n)::text FROM aegaeon.subject_ownership_namespaces n ORDER BY n.environment_id;
  RETURN QUERY SELECT 'subject_ownership_adoptions'::text,a.environment_id::text,pg_catalog.to_jsonb(a)::text FROM aegaeon.subject_ownership_adoptions a ORDER BY a.environment_id;
  RETURN QUERY SELECT 'end_user_identity_owners'::text,o.owner_id::text,pg_catalog.to_jsonb(o)::text FROM aegaeon.end_user_identity_owners o ORDER BY o.owner_id;
  RETURN QUERY SELECT 'end_user_subject_reservations'::text,aegaeon.subject_history_key(ARRAY[r.environment_id::text,r.subject]),pg_catalog.to_jsonb(r)::text FROM aegaeon.end_user_subject_reservations r ORDER BY r.environment_id,r.subject COLLATE "C";
  RETURN QUERY SELECT 'end_users'::text,u.id::text,pg_catalog.to_jsonb(u)::text FROM aegaeon.end_users u ORDER BY u.id;
  RETURN QUERY SELECT 'audit_events'::text,aegaeon.subject_history_key(ARRAY[a.occurred_at::text,a.id::text,a.tableoid::text]),pg_catalog.to_jsonb(a)::text FROM aegaeon.audit_events a ORDER BY a.occurred_at,a.id,a.tableoid;
  RETURN QUERY SELECT 'physical_catalog'::text,c.row_key,c.row_text FROM aegaeon.subject_history_physical_catalog(runtime_name) c;
END
$function$;


--
-- Name: subject_history_strict_json(json, integer); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_strict_json(value json, depth integer DEFAULT 0) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE item record; text_value text;
BEGIN
  IF depth > 32 THEN RAISE EXCEPTION 'history JSON exceeds nesting limit'; END IF;
  CASE pg_catalog.json_typeof(value)
  WHEN 'object' THEN
    IF EXISTS (SELECT FROM pg_catalog.json_each(value) AS member(key, val)
               GROUP BY key COLLATE "C" HAVING count(*) > 1) THEN
      RAISE EXCEPTION 'duplicate decoded history JSON member';
    END IF;
    IF depth=0 AND (SELECT COALESCE(sum(pg_catalog.json_array_length(val)),0) FROM pg_catalog.json_each(value) fields(key,val)
        WHERE key IN ('owners','reservations','invalid_history','resolutions') AND pg_catalog.json_typeof(val)='array')>1000000 THEN
      RAISE EXCEPTION 'combined history entry limit exceeded';
    END IF;
    FOR item IN SELECT key, val FROM pg_catalog.json_each(value) AS member(key, val) LOOP
      IF item.key IN ('sources','source_refs','fact_refs') AND pg_catalog.json_typeof(item.val)='array' AND pg_catalog.json_array_length(item.val)>256 THEN
        RAISE EXCEPTION 'history source/reference array limit exceeded';
      END IF;
      PERFORM aegaeon.subject_history_strict_json(item.val, depth + 1);
    END LOOP;
  WHEN 'array' THEN
    FOR item IN SELECT val FROM pg_catalog.json_array_elements(value) AS member(val) LOOP
      PERFORM aegaeon.subject_history_strict_json(item.val, depth + 1);
    END LOOP;
  WHEN 'number' THEN
    text_value := value::text;
    IF text_value !~ '^(0|[1-9][0-9]*)$' OR text_value::numeric > 9223372036854775807 THEN
      RAISE EXCEPTION 'history JSON requires nonnegative canonical bigint syntax';
    END IF;
  WHEN 'string' THEN
    -- Decoding as text/jsonb also refuses PostgreSQL-unrepresentable NUL.
    text_value := value #>> ARRAY[]::text[];
  WHEN 'boolean' THEN NULL;
  WHEN 'null' THEN NULL;
  ELSE RAISE EXCEPTION 'invalid history JSON value';
  END CASE;
END
$function$;


--
-- Name: subject_history_validate_manifest(jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_validate_manifest(value jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE sources jsonb; owners jsonb; reservations jsonb; invalids jsonb; item jsonb; part jsonb;
  env_id text := value->'namespace'->>'environment_id'; source_value jsonb; reconstruction_env text; count_rows bigint;
BEGIN
  SELECT count(*),pg_catalog.jsonb_object_agg(s->>'source_id',s) INTO count_rows,sources FROM pg_catalog.jsonb_array_elements(value->'sources') fields(s);
  IF count_rows<>(SELECT count(DISTINCT s->>'source_id') FROM pg_catalog.jsonb_array_elements(value->'sources') fields(s)) THEN RAISE EXCEPTION 'duplicate source ID'; END IF;
  IF (SELECT count(*) FROM pg_catalog.jsonb_array_elements(value->'sources') fields(s) WHERE s->>'kind'='completeness_attestation')<>1 THEN RAISE EXCEPTION 'one completeness attestation required'; END IF;
  source_value := sources->(value->'completeness'->>'attestation_source');
  IF source_value IS NULL OR source_value->>'kind'<>'completeness_attestation' OR (source_value->>'byte_length')::bigint=0
      OR NOT (source_value->'environment_ids') @> pg_catalog.jsonb_build_array(env_id) THEN RAISE EXCEPTION 'retained target completeness attestation required'; END IF;
  SELECT count(*),pg_catalog.jsonb_object_agg(s->>'owner_id',s) INTO count_rows,owners FROM pg_catalog.jsonb_array_elements(value->'owners') fields(s);
  IF count_rows<>(SELECT count(DISTINCT s->>'owner_id') FROM pg_catalog.jsonb_array_elements(value->'owners') fields(s)) THEN RAISE EXCEPTION 'duplicate owner ID'; END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(value->'owners') LOOP
    IF item->>'environment_id'<>env_id THEN RAISE EXCEPTION 'manifest owner is outside target'; END IF;
    PERFORM aegaeon.subject_history_source_refs(item->'source_refs',sources,env_id,false);
  END LOOP;
  SELECT count(*),pg_catalog.jsonb_object_agg(s->>'subject',s) INTO count_rows,reservations FROM pg_catalog.jsonb_array_elements(value->'reservations') fields(s);
  IF count_rows<>(SELECT count(DISTINCT (s->>'subject') COLLATE "C") FROM pg_catalog.jsonb_array_elements(value->'reservations') fields(s)) THEN RAISE EXCEPTION 'duplicate exact subject'; END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(value->'reservations') LOOP
    IF NOT COALESCE(owners ? (item->>'owner_id'),false) THEN RAISE EXCEPTION 'reservation owner is missing'; END IF;
    PERFORM aegaeon.subject_history_source_refs(item->'source_refs',sources,env_id,false);
  END LOOP;
  SELECT count(*),pg_catalog.jsonb_object_agg(s->>'observation_id',s) INTO count_rows,invalids FROM pg_catalog.jsonb_array_elements(value->'invalid_history') fields(s);
  IF count_rows<>(SELECT count(DISTINCT s->>'observation_id') FROM pg_catalog.jsonb_array_elements(value->'invalid_history') fields(s)) THEN RAISE EXCEPTION 'duplicate invalid history observation'; END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(value->'invalid_history') LOOP
    IF item->>'owner_id' IS NULL OR NOT COALESCE(owners ? (item->>'owner_id'),false) THEN RAISE EXCEPTION 'invalid history owner remains unresolved'; END IF;
    PERFORM aegaeon.subject_history_source_refs(item->'source_refs',sources,env_id,false);
    source_value := sources->(item->>'evidence_source');
    IF source_value->>'kind' IS DISTINCT FROM 'invalid_history_evidence' OR (source_value->>'byte_length')::bigint=0
      OR NOT (item->'source_refs') @> pg_catalog.jsonb_build_array(item->>'evidence_source') THEN RAISE EXCEPTION 'invalid disclosure evidence required'; END IF;
  END LOOP;
  IF pg_catalog.jsonb_array_length(value->'resolutions')<>(SELECT count(DISTINCT s->>'finding_id') FROM pg_catalog.jsonb_array_elements(value->'resolutions') fields(s)) THEN RAISE EXCEPTION 'duplicate finding resolution'; END IF;
  FOR item IN SELECT pg_catalog.jsonb_array_elements(value->'resolutions') LOOP
    reconstruction_env := CASE item->>'kind' WHEN 'outside_target' THEN item->>'environment_id' ELSE env_id END;
    PERFORM aegaeon.subject_history_source_refs(item->'source_refs',sources,reconstruction_env,true);
    CASE item->>'kind'
    WHEN 'outside_target' THEN
      IF item->>'environment_id'=env_id THEN RAISE EXCEPTION 'outside target resolution names target'; END IF;
    WHEN 'reconstructed_ownership' THEN
      IF pg_catalog.jsonb_array_length(item->'owners')+pg_catalog.jsonb_array_length(item->'subjects')=0 THEN RAISE EXCEPTION 'empty reconstruction'; END IF;
      FOR part IN SELECT pg_catalog.jsonb_array_elements(item->'owners') LOOP
        IF NOT COALESCE(owners ? (part #>> ARRAY[]::text[]),false) THEN RAISE EXCEPTION 'reconstructed owner missing from union'; END IF;
      END LOOP;
      FOR part IN SELECT pg_catalog.jsonb_array_elements(item->'subjects') LOOP
        IF reservations->(part->>'subject')->>'owner_id' IS DISTINCT FROM part->>'owner_id' THEN RAISE EXCEPTION 'reconstructed subject missing from union'; END IF;
      END LOOP;
    WHEN 'invalid_disclosure_retained' THEN
      part := invalids->(item->>'observation_id');
      IF part IS NULL OR part->>'owner_id' IS DISTINCT FROM item->>'owner_id' OR part->>'evidence_source' IS DISTINCT FROM item->>'evidence_source'
        OR NOT (item->'source_refs') @> pg_catalog.jsonb_build_array(item->>'evidence_source') THEN RAISE EXCEPTION 'invalid disclosure retention mismatch'; END IF;
    WHEN 'no_ownership_effect' THEN NULL;
    ELSE RAISE EXCEPTION 'invalid resolution tag';
    END CASE;
  END LOOP;
END
$function$;


--
-- Name: subject_history_validate_shape(jsonb, jsonb, jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_validate_shape(value jsonb, shape jsonb, definitions jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE item record; alternatives integer := 0; subtype text; bound numeric; row_index bigint; expected jsonb; actual text; key_name text;
BEGIN
  IF shape ? '$ref' THEN
    key_name := pg_catalog.substr(shape->>'$ref',9);
    IF shape->>'$ref' NOT LIKE '#/$defs/%' OR NOT definitions ? key_name THEN RAISE EXCEPTION 'invalid embedded schema reference'; END IF;
    PERFORM aegaeon.subject_history_validate_shape(value,definitions->key_name,definitions); RETURN;
  END IF;
  IF shape ? 'oneOf' THEN
    FOR item IN SELECT val FROM pg_catalog.jsonb_array_elements(shape->'oneOf') alternatives(val) LOOP
      BEGIN PERFORM aegaeon.subject_history_validate_shape(value,item.val,definitions); alternatives := alternatives+1;
      EXCEPTION WHEN check_violation THEN NULL; END;
    END LOOP;
    IF alternatives<>1 THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history tagged union mismatch'; END IF;
    RETURN;
  END IF;
  IF shape ? 'const' AND value IS DISTINCT FROM shape->'const' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history constant mismatch'; END IF;
  IF shape ? 'enum' AND NOT (shape->'enum') @> pg_catalog.jsonb_build_array(value) THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history enumeration mismatch'; END IF;
  subtype := shape->>'type';
  IF subtype IS NOT NULL AND ((subtype='integer' AND (pg_catalog.jsonb_typeof(value)<>'number' OR value::text !~ '^(0|[1-9][0-9]*)$'))
      OR (subtype<>'integer' AND pg_catalog.jsonb_typeof(value) IS DISTINCT FROM subtype)) THEN
    RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history field type mismatch';
  END IF;
  IF subtype='object' THEN
    PERFORM aegaeon.subject_history_require_keys(value,ARRAY(SELECT pg_catalog.jsonb_array_elements_text(shape->'required')));
    FOR item IN SELECT key,val FROM pg_catalog.jsonb_each(value) fields(key,val) LOOP
      PERFORM aegaeon.subject_history_validate_shape(item.val,shape->'properties'->item.key,definitions);
    END LOOP;
  ELSIF subtype='array' THEN
    bound := pg_catalog.jsonb_array_length(value);
    IF (shape ? 'minItems' AND bound<(shape->>'minItems')::numeric) OR (shape ? 'maxItems' AND bound>(shape->>'maxItems')::numeric) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history array size mismatch';
    END IF;
    IF shape->>'uniqueItems'='true' AND EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(value) fields(val) GROUP BY val HAVING count(*)>1) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history duplicate array entry';
    END IF;
    FOR item IN SELECT val,ordinality FROM pg_catalog.jsonb_array_elements(value) WITH ORDINALITY fields(val,ordinality) LOOP
      row_index := item.ordinality-1;
      expected := CASE WHEN shape ? 'prefixItems' THEN shape->'prefixItems'->row_index::integer ELSE shape->'items' END;
      IF expected IS NULL OR expected='false'::jsonb THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history unexpected array entry'; END IF;
      PERFORM aegaeon.subject_history_validate_shape(item.val,expected,definitions);
    END LOOP;
  ELSIF subtype='integer' THEN
    bound := value::text::numeric;
    IF (shape ? 'minimum' AND bound<(shape->>'minimum')::numeric) OR (shape ? 'maximum' AND bound>(shape->>'maximum')::numeric) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history integer outside domain';
    END IF;
  ELSIF subtype='string' THEN
    actual := value #>> ARRAY[]::text[];
    bound := pg_catalog.char_length(actual);
    IF (shape ? 'minLength' AND bound<(shape->>'minLength')::numeric) OR (shape ? 'maxLength' AND bound>(shape->>'maxLength')::numeric)
       OR (shape ? 'pattern' AND NOT actual COLLATE "C" ~ (shape->>'pattern'))
       OR (shape->>'x-aegaeon-domain'='subject' AND NOT aegaeon.subject_ownership_valid_subject(actual)) THEN
      RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='history string outside domain';
    END IF;
  END IF;
END
$function$;


--
-- Name: subject_history_validate_union(jsonb, jsonb); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_history_validate_union(manifest jsonb, inventory jsonb) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE owners jsonb; reservations jsonb; facts jsonb; resolutions jsonb; fact jsonb; finding jsonb; resolution jsonb;
  known_value text; env_id text:=manifest->'namespace'->>'environment_id'; part jsonb; used_count bigint:=0; claimed_outside boolean; observes_claimed_owner boolean;
BEGIN
  SELECT pg_catalog.jsonb_object_agg(v->>'owner_id',v) INTO owners FROM pg_catalog.jsonb_array_elements(manifest->'owners') rows(v);
  SELECT pg_catalog.jsonb_object_agg(v->>'subject',v) INTO reservations FROM pg_catalog.jsonb_array_elements(manifest->'reservations') rows(v);
  SELECT pg_catalog.jsonb_object_agg(v->>'fact_id',v) INTO facts FROM pg_catalog.jsonb_array_elements(inventory->'facts') rows(v);
  SELECT pg_catalog.jsonb_object_agg(v->>'finding_id',v) INTO resolutions FROM pg_catalog.jsonb_array_elements(manifest->'resolutions') rows(v);
  IF EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(inventory->'facts') rows(v) GROUP BY v->>'owner_id' HAVING count(DISTINCT v->>'environment_id')>1)
    OR EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(inventory->'facts') rows(v) WHERE v->>'environment_id'=env_id AND v->>'valid'='true'
      GROUP BY (v->>'subject') COLLATE "C" HAVING count(DISTINCT v->>'owner_id')>1) THEN RAISE EXCEPTION 'known historical ownership conflict'; END IF;
  FOR fact IN SELECT pg_catalog.jsonb_array_elements(inventory->'facts') LOOP
    IF fact->>'environment_id'=env_id THEN
      IF NOT COALESCE(owners ? (fact->>'owner_id'),false) THEN RAISE EXCEPTION 'known target owner omitted'; END IF;
      IF fact->>'valid'='true' AND reservations->(fact->>'subject')->>'owner_id' IS DISTINCT FROM fact->>'owner_id' THEN RAISE EXCEPTION 'known target subject ownership omitted'; END IF;
    ELSIF COALESCE(owners ? (fact->>'owner_id'),false) THEN RAISE EXCEPTION 'claimed UUID is known in another environment'; END IF;
  END LOOP;
  FOR finding IN SELECT pg_catalog.jsonb_array_elements(inventory->'findings') LOOP
    IF finding->>'class'='ownership_conflict' THEN RAISE EXCEPTION 'ownership conflict cannot be waived'; END IF;
    resolution := resolutions->(finding->>'finding_id');
    observes_claimed_owner := EXISTS(SELECT FROM pg_catalog.jsonb_array_elements_text(finding->'observed_owner_ids') rows(v) WHERE COALESCE(owners ? v,false));
    claimed_outside := finding->>'class'='outside_target' AND observes_claimed_owner;
    IF finding->>'class'='outside_target' AND NOT claimed_outside THEN
      IF resolution IS NOT NULL THEN RAISE EXCEPTION 'unused outside-target resolution'; END IF;
      CONTINUE;
    END IF;
    IF resolution IS NULL THEN RAISE EXCEPTION 'unresolved inventory finding'; END IF;
    used_count := used_count+1;
    IF claimed_outside AND resolution->>'kind'<>'reconstructed_ownership' THEN RAISE EXCEPTION 'claimed outside UUID requires binding reconstruction'; END IF;
    CASE resolution->>'kind'
    WHEN 'reconstructed_ownership' THEN
      IF finding->>'class'='invalid_history' THEN RAISE EXCEPTION 'invalid disclosure requires retained evidence'; END IF;
      IF finding->>'class'='unknown_owner' THEN
        FOR known_value IN SELECT pg_catalog.jsonb_array_elements_text(finding->'observed_subjects') LOOP
          IF aegaeon.subject_ownership_valid_subject(known_value) AND NOT EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(resolution->'subjects') rows(v) WHERE v->>'subject'=known_value COLLATE "C") THEN RAISE EXCEPTION 'known subject-only observation lacks reconstructed owner'; END IF;
        END LOOP;
      END IF;
      FOR known_value IN SELECT pg_catalog.jsonb_array_elements_text(finding->'preserved_fact_ids') LOOP
        fact := facts->known_value;
        IF fact IS NULL THEN RAISE EXCEPTION 'missing preserved inventory fact'; END IF;
        IF fact->>'environment_id'=env_id THEN
          IF NOT (resolution->'owners') @> pg_catalog.jsonb_build_array(fact->>'owner_id') AND NOT EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(resolution->'subjects') rows(v) WHERE v->>'owner_id'=fact->>'owner_id') THEN RAISE EXCEPTION 'reconstruction omits preserved owner'; END IF;
          IF fact->>'valid'='true' AND NOT EXISTS(SELECT FROM pg_catalog.jsonb_array_elements(resolution->'subjects') rows(v) WHERE v->>'owner_id'=fact->>'owner_id' AND v->>'subject'=fact->>'subject' COLLATE "C") THEN RAISE EXCEPTION 'reconstruction omits preserved subject'; END IF;
        END IF;
      END LOOP;
    WHEN 'outside_target' THEN
      IF observes_claimed_owner THEN RAISE EXCEPTION 'outside classification cannot clear claimed UUID binding'; END IF;
      IF finding->>'environment_id' IS NOT NULL AND finding->>'environment_id' IS DISTINCT FROM resolution->>'environment_id' THEN RAISE EXCEPTION 'outside resolution relocates known environment'; END IF;
      FOR known_value IN SELECT pg_catalog.jsonb_array_elements_text(finding->'preserved_fact_ids') LOOP
        IF facts->known_value->>'environment_id' IS DISTINCT FROM resolution->>'environment_id' THEN RAISE EXCEPTION 'outside resolution relocates preserved fact'; END IF;
      END LOOP;
    WHEN 'no_ownership_effect' THEN
      IF pg_catalog.jsonb_array_length(finding->'preserved_fact_ids')>0 OR finding->>'class' IN ('unknown_owner','invalid_history') OR aegaeon.subject_history_identity_event(finding->>'origin') THEN RAISE EXCEPTION 'ownership-bearing finding cannot be dismissed'; END IF;
    WHEN 'invalid_disclosure_retained' THEN
      IF finding->>'class'<>'invalid_history' OR resolution->>'owner_id' IS NULL OR pg_catalog.jsonb_array_length(finding->'observed_subjects')<>1 THEN RAISE EXCEPTION 'invalid disclosure finding required'; END IF;
      known_value := finding->'observed_subjects'->>0;
      IF aegaeon.subject_ownership_valid_subject(known_value) THEN RAISE EXCEPTION 'valid subject cannot be classified invalid'; END IF;
      IF EXISTS(SELECT FROM pg_catalog.jsonb_array_elements_text(finding->'preserved_fact_ids') rows(v) WHERE facts->v IS NULL OR (facts->v->>'environment_id'=env_id AND facts->v->>'owner_id' IS DISTINCT FROM resolution->>'owner_id')) THEN RAISE EXCEPTION 'invalid disclosure owner contradicts known owner'; END IF;
      IF resolution->>'observation_id'<>aegaeon.subject_history_content_id('aegaeon-invalid-subject-v1',
          ARRAY['origin','row_key','sha256','sha256'],ARRAY[finding->>'origin',finding->>'row_key',finding->>'row_sha256',pg_catalog.encode(pg_catalog.sha256(aegaeon.subject_history_frame(pg_catalog.convert_to(known_value,'UTF8'))),'hex')]) THEN RAISE EXCEPTION 'invalid observation identity mismatch'; END IF;
    ELSE RAISE EXCEPTION 'unknown resolution kind';
    END CASE;
  END LOOP;
  IF used_count<>pg_catalog.jsonb_array_length(manifest->'resolutions') THEN RAISE EXCEPTION 'unused resolution'; END IF;
END
$function$;


--
-- Name: subject_ownership_guard_environment(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_ownership_guard_environment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE entry_role text;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.issuer_host IS DISTINCT FROM OLD.issuer_host THEN
      RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'environments_subject_namespace_immutable',
        MESSAGE = 'issuer subject namespace cannot be moved';
    END IF;
    RETURN NEW;
  END IF;
  entry_role := pg_catalog.current_setting('role');
  IF entry_role = 'none' THEN entry_role := session_user; END IF;
  INSERT INTO aegaeon.subject_ownership_namespaces(environment_id, issuer_host, origin)
  VALUES (NEW.id, NEW.issuer_host, 'fresh');
  INSERT INTO aegaeon.subject_ownership_adoptions(environment_id, kind, receipt_id, session_actor, effective_actor, definer_actor)
  VALUES (NEW.id, 'fresh', pg_catalog.gen_random_uuid(), session_user, entry_role, current_user);
  RETURN NEW;
END
$function$;


--
-- Name: subject_ownership_guard_user(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_ownership_guard_user() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE recorded_owner uuid; inserted_owner uuid;
BEGIN
  IF NOT EXISTS (SELECT FROM aegaeon.subject_ownership_adoptions a
                 JOIN aegaeon.subject_ownership_namespaces n USING (environment_id)
                 WHERE a.environment_id = NEW.environment_id AND a.kind = n.origin
                   AND a.contract_version = 1 AND n.contract_version = 1) THEN
    RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'subject_ownership_namespace_pending',
      MESSAGE = 'issuer subject history is not adopted';
  END IF;
  IF NOT aegaeon.subject_ownership_valid_subject(NEW.subject) THEN
    RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'end_users_subject_format',
      MESSAGE = 'invalid OpenID subject format';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.environment_id IS DISTINCT FROM OLD.environment_id THEN
      RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'end_users_identity_immutable',
        MESSAGE = 'end-user identity cannot be moved';
    END IF;
    IF NOT EXISTS (SELECT FROM aegaeon.end_user_identity_owners
                   WHERE owner_id = NEW.id AND environment_id = NEW.environment_id) THEN
      RAISE EXCEPTION USING ERRCODE = '23514', CONSTRAINT = 'end_users_identity_immutable',
        MESSAGE = 'end-user ownership authority is missing';
    END IF;
  ELSE
    INSERT INTO aegaeon.end_user_identity_owners(owner_id, environment_id)
    VALUES (NEW.id, NEW.environment_id) ON CONFLICT DO NOTHING RETURNING owner_id INTO inserted_owner;
    IF inserted_owner IS NULL THEN
      RAISE EXCEPTION USING ERRCODE = '23505', CONSTRAINT = 'end_users_historical_uuid_reuse',
        MESSAGE = 'end-user identity is permanently reserved';
    END IF;
  END IF;
  INSERT INTO aegaeon.end_user_subject_reservations(environment_id, subject, owner_id)
  VALUES (NEW.environment_id, NEW.subject, NEW.id) ON CONFLICT DO NOTHING;
  SELECT owner_id INTO recorded_owner FROM aegaeon.end_user_subject_reservations
  WHERE environment_id = NEW.environment_id AND subject = NEW.subject COLLATE "C";
  IF recorded_owner IS DISTINCT FROM NEW.id THEN
    RAISE EXCEPTION USING ERRCODE = '23505', CONSTRAINT = 'end_users_subject_owner_conflict',
      MESSAGE = 'subject is permanently owned';
  END IF;
  RETURN NEW;
END
$function$;


--
-- Name: subject_ownership_immutable(); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_ownership_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  RAISE EXCEPTION USING ERRCODE = '23514',
    CONSTRAINT = 'subject_ownership_immutable', MESSAGE = 'permanent subject ownership cannot be changed or erased';
END
$function$;


--
-- Name: subject_ownership_valid_subject(text); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.subject_ownership_valid_subject(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
  SELECT pg_catalog.octet_length(pg_catalog.convert_to(value, 'UTF8')) BETWEEN 1 AND 255
    AND NOT EXISTS (
      SELECT FROM pg_catalog.generate_series(0, pg_catalog.octet_length(pg_catalog.convert_to(value, 'UTF8')) - 1) AS bytes(i)
      WHERE pg_catalog.get_byte(pg_catalog.convert_to(value, 'UTF8'), bytes.i) > 127
    )
$function$;


--
-- Name: text_array_is_normalized_set(text[], boolean); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.text_array_is_normalized_set(p_values text[], p_allow_empty boolean) RETURNS boolean
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    AS $$
  SELECT COALESCE(
    "p_values" IS NOT NULL
    AND ("p_allow_empty" OR cardinality("p_values") > 0)
    AND cardinality("p_values") = COALESCE((
      SELECT count(DISTINCT "item"."value")::integer
      FROM unnest("p_values") AS "item"("value")
    ), 0)
    AND NOT EXISTS (
      SELECT 1
      FROM unnest("p_values") AS "item"("value")
      WHERE "item"."value" IS NULL
        OR "item"."value" = ''
        OR "item"."value" <> btrim("item"."value")
    ),
    false
  );
$$;


--
-- Name: validate_subject_ownership_namespace_v1(uuid); Type: FUNCTION; Schema: aegaeon; Owner: -
--

CREATE FUNCTION aegaeon.validate_subject_ownership_namespace_v1(target_environment uuid)
RETURNS TABLE(record_type text, row_key text, payload text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE entry_role text:=pg_catalog.current_setting('role'); schema_hash text;
  namespace_row record; item record;
BEGIN
  IF entry_role='none' THEN entry_role:=session_user; END IF;
  -- Inspect the login, including every inherited/SET ROLE path: RESET ROLE must
  -- never reveal a privileged identity after an apparently restricted entry.
  PERFORM aegaeon.subject_history_check_runtime_role(session_user);
  IF NOT pg_catalog.pg_has_role(session_user,entry_role,'USAGE')
     AND NOT pg_catalog.pg_has_role(session_user,entry_role,'SET') THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='subject runtime entry authority mismatch';
  END IF;
  -- This is an explicit direct login grant, not PUBLIC or a maintenance grant.
  IF NOT EXISTS(SELECT FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE p.oid='aegaeon.validate_subject_ownership_namespace_v1(uuid)'::regprocedure
        AND a.grantee=session_user::regrole AND a.privilege_type='EXECUTE' AND NOT a.is_grantable) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='explicit runtime login preflight grant required';
  END IF;
  IF EXISTS(SELECT FROM pg_catalog.pg_proc p
      CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
      WHERE p.oid='aegaeon.validate_subject_ownership_namespace_v1(uuid)'::regprocedure
        AND (a.grantee NOT IN (session_user::regrole::oid,p.proowner)
          OR a.privilege_type<>'EXECUTE' OR (a.grantee<>p.proowner AND a.is_grantable))) THEN
    RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='runtime preflight entry ACL mismatch';
  END IF;
  schema_hash:=aegaeon.subject_history_preflight(session_user);
  SELECT n.environment_id,n.issuer_host,n.origin,n.contract_version,a.receipt_id,a.kind,e.issuer_url
    INTO namespace_row FROM aegaeon.subject_ownership_namespaces n
      JOIN aegaeon.subject_ownership_adoptions a ON a.environment_id=n.environment_id AND a.kind=n.origin
      JOIN aegaeon.environments e ON e.id=n.environment_id AND e.issuer_host=n.issuer_host
    WHERE n.environment_id=target_environment AND n.contract_version=1 AND a.contract_version=1;
  IF NOT FOUND THEN
    RAISE EXCEPTION USING ERRCODE='23514',CONSTRAINT='subject_namespace_pending',MESSAGE='subject namespace unavailable';
  END IF;
  record_type:='namespace';row_key:=target_environment::text;
  payload:=(pg_catalog.to_jsonb(namespace_row)||pg_catalog.jsonb_build_object(
    'schema_sha256',schema_hash,'session_actor',session_user,'effective_actor',entry_role))::text;
  RETURN NEXT;
  -- Catalog only: no source row, owner map, subject, audit or historical receipt payload.
  FOR item IN SELECT c.* FROM aegaeon.subject_history_physical_catalog(session_user) c
      WHERE c.row_key LIKE 'function:%' OR c.row_key LIKE 'atlas_revision:%' OR c.row_key LIKE 'role:%' LOOP
    record_type:='catalog';row_key:=item.row_key;payload:=item.row_text;RETURN NEXT;
  END LOOP;
END
$function$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: account_links; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.account_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    upstream_issuer text NOT NULL,
    upstream_sub_hash text NOT NULL,
    end_user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone DEFAULT now() NOT NULL,
    upstream_refresh_token_encrypted bytea,
    upstream_refresh_token_connection_id uuid,
    upstream_refresh_token_generation bigint DEFAULT 0 NOT NULL,
    CONSTRAINT account_links_refresh_token_binding_complete CHECK ((((upstream_refresh_token_encrypted IS NULL) AND (upstream_refresh_token_connection_id IS NULL) AND (upstream_refresh_token_generation = 0)) OR ((upstream_refresh_token_encrypted IS NOT NULL) AND (upstream_refresh_token_connection_id IS NOT NULL) AND (upstream_refresh_token_generation > 0))))
);


--
-- Name: configuration_versions; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.configuration_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    version_number bigint NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    configuration_hash text NOT NULL,
    status aegaeon.configuration_version_status DEFAULT 'DRAFT'::aegaeon.configuration_version_status NOT NULL,
    base_configuration_version_id uuid,
    configuration_document jsonb NOT NULL,
    created_by_administrator_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    comment text,
    activated_at timestamp with time zone,
    archived_at timestamp with time zone,
    CONSTRAINT configuration_versions_schema_version_check CHECK ((schema_version = 1))
);


--
-- Name: environments; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    issuer_host text NOT NULL,
    issuer_url text GENERATED ALWAYS AS (('https://'::text || issuer_host)) STORED,
    active_configuration_version_id uuid,
    status aegaeon.environment_status DEFAULT 'ACTIVE'::aegaeon.environment_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT environments_issuer_host_check CHECK (((issuer_host = lower(issuer_host)) AND (POSITION(('://'::text) IN (issuer_host)) = 0) AND (POSITION(('/'::text) IN (issuer_host)) = 0) AND (POSITION(('?'::text) IN (issuer_host)) = 0) AND (POSITION(('#'::text) IN (issuer_host)) = 0))),
    CONSTRAINT environments_slug_dns_label CHECK (((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug))))
);


--
-- Name: teams; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.teams (
    id uuid DEFAULT gen_random_uuid() CONSTRAINT organizations_id_not_null NOT NULL,
    name text CONSTRAINT organizations_name_not_null NOT NULL,
    slug text,
    status aegaeon.team_status DEFAULT 'ACTIVE'::aegaeon.team_status CONSTRAINT organizations_status_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT organizations_created_at_not_null NOT NULL,
    updated_at timestamp with time zone DEFAULT now() CONSTRAINT organizations_updated_at_not_null NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT teams_slug_dns_label CHECK (((slug IS NULL) OR ((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug)))))
);


--
-- Name: tenants; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    team_id uuid CONSTRAINT tenants_organization_id_not_null NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    region text NOT NULL,
    status aegaeon.tenant_status DEFAULT 'ACTIVE'::aegaeon.tenant_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT tenants_region_label CHECK (((region ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (region = lower(region)))),
    CONSTRAINT tenants_slug_dns_label CHECK (((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug))))
);


--
-- Name: active_runtime_environments; Type: VIEW; Schema: aegaeon; Owner: -
--

CREATE VIEW aegaeon.active_runtime_environments AS
 SELECT e.id AS environment_id,
    t.team_id,
    e.tenant_id,
    e.issuer_host,
    e.issuer_url,
    e.active_configuration_version_id AS configuration_version_id,
    cv.configuration_document
   FROM (((aegaeon.environments e
     JOIN aegaeon.tenants t ON ((t.id = e.tenant_id)))
     JOIN aegaeon.teams team ON ((team.id = t.team_id)))
     JOIN aegaeon.configuration_versions cv ON (((cv.id = e.active_configuration_version_id) AND (cv.environment_id = e.id))))
  WHERE ((e.status = 'ACTIVE'::aegaeon.environment_status) AND (t.status = 'ACTIVE'::aegaeon.tenant_status) AND (team.status = 'ACTIVE'::aegaeon.team_status) AND (e.active_configuration_version_id IS NOT NULL) AND (cv.status = 'ACTIVE'::aegaeon.configuration_version_status));


--
-- Name: administrators; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.administrators (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    status aegaeon.administrator_status DEFAULT 'ACTIVE'::aegaeon.administrator_status NOT NULL,
    mfa_enabled boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    kind aegaeon.administrator_kind DEFAULT 'HUMAN'::aegaeon.administrator_kind NOT NULL,
    CONSTRAINT administrators_email_lowercase CHECK ((email = lower(email)))
);


--
-- Name: api_key_capabilities; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.api_key_capabilities (
    api_key_id uuid NOT NULL,
    capability aegaeon.api_key_capability NOT NULL
);


--
-- Name: api_keys; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    team_id uuid NOT NULL,
    service_administrator_id uuid NOT NULL,
    name text NOT NULL,
    key_prefix text NOT NULL,
    key_hash bytea NOT NULL,
    status aegaeon.api_key_status DEFAULT 'ACTIVE'::aegaeon.api_key_status NOT NULL,
    created_by_administrator_id uuid,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_administrator_id uuid,
    CONSTRAINT api_keys_expires_after_created CHECK (((expires_at IS NULL) OR (expires_at > created_at))),
    CONSTRAINT api_keys_key_hash_sha256_length CHECK ((octet_length(key_hash) = 32)),
    CONSTRAINT api_keys_key_prefix_shape CHECK ((key_prefix ~ '^aeg_[A-Za-z0-9_-]{8}$'::text)),
    CONSTRAINT api_keys_last_used_after_created CHECK (((last_used_at IS NULL) OR (last_used_at >= created_at))),
    CONSTRAINT api_keys_name_normalized CHECK (((name = btrim(name)) AND ((length(name) >= 1) AND (length(name) <= 128)))),
    CONSTRAINT api_keys_revocation_state_consistent CHECK ((((status = 'ACTIVE'::aegaeon.api_key_status) AND (revoked_at IS NULL) AND (revoked_by_administrator_id IS NULL)) OR ((status = 'REVOKED'::aegaeon.api_key_status) AND (revoked_at IS NOT NULL) AND (revoked_by_administrator_id IS NOT NULL) AND (revoked_at >= created_at))))
);


--
-- Name: application_authorizations; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.application_authorizations (
    environment_id uuid NOT NULL,
    client_id text NOT NULL,
    subject text NOT NULL,
    revision bigint NOT NULL,
    authority text NOT NULL,
    source_revision bigint NOT NULL,
    audiences jsonb NOT NULL,
    claims jsonb NOT NULL,
    enabled boolean NOT NULL,
    updated_at timestamp with time zone DEFAULT statement_timestamp() NOT NULL,
    client_record_id uuid,
    end_user_record_id uuid,
    CONSTRAINT application_authorizations_audiences_check CHECK ((jsonb_typeof(audiences) = 'array'::text)),
    CONSTRAINT application_authorizations_authority_check CHECK (((length(authority) >= 1) AND (length(authority) <= 255))),
    CONSTRAINT application_authorizations_claims_check CHECK ((jsonb_typeof(claims) = 'object'::text)),
    CONSTRAINT application_authorizations_client_id_check CHECK (((length(client_id) >= 1) AND (length(client_id) <= 255))),
    CONSTRAINT application_authorizations_revision_check CHECK ((revision > 0)),
    CONSTRAINT application_authorizations_source_revision_check CHECK ((source_revision > 0)),
    CONSTRAINT application_authorizations_subject_check CHECK (((length(subject) >= 1) AND (length(subject) <= 255)))
);


--
-- Name: audit_events; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    team_id uuid CONSTRAINT audit_events_organization_id_not_null NOT NULL,
    tenant_id uuid,
    environment_id uuid,
    event_type text NOT NULL,
    category text NOT NULL,
    outcome text NOT NULL,
    severity text NOT NULL,
    occurred_at timestamp with time zone NOT NULL,
    actor_type text NOT NULL,
    actor_id text,
    ip_address inet,
    user_agent text,
    mfa boolean,
    target_type text NOT NULL,
    target_id text,
    request_id text NOT NULL,
    trace_id text,
    span_id text,
    from_configuration_version_id uuid,
    to_configuration_version_id uuid,
    json_patch jsonb,
    data jsonb
)
PARTITION BY RANGE (occurred_at);


--
-- Name: audit_events_default; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.audit_events_default (
    id uuid DEFAULT gen_random_uuid() CONSTRAINT audit_events_id_not_null NOT NULL,
    team_id uuid CONSTRAINT audit_events_organization_id_not_null NOT NULL,
    tenant_id uuid,
    environment_id uuid,
    event_type text CONSTRAINT audit_events_event_type_not_null NOT NULL,
    category text CONSTRAINT audit_events_category_not_null NOT NULL,
    outcome text CONSTRAINT audit_events_outcome_not_null NOT NULL,
    severity text CONSTRAINT audit_events_severity_not_null NOT NULL,
    occurred_at timestamp with time zone CONSTRAINT audit_events_occurred_at_not_null NOT NULL,
    actor_type text CONSTRAINT audit_events_actor_type_not_null NOT NULL,
    actor_id text,
    ip_address inet,
    user_agent text,
    mfa boolean,
    target_type text CONSTRAINT audit_events_target_type_not_null NOT NULL,
    target_id text,
    request_id text CONSTRAINT audit_events_request_id_not_null NOT NULL,
    trace_id text,
    span_id text,
    from_configuration_version_id uuid,
    to_configuration_version_id uuid,
    json_patch jsonb,
    data jsonb
);


--
-- Name: authorization_consents; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.authorization_consents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    session_sha256 text NOT NULL,
    token_sha256 text NOT NULL,
    authorize_uri text NOT NULL,
    request_snapshot jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    decision text,
    decided_at timestamp with time zone,
    CONSTRAINT authorization_consents_check CHECK (((decision IS NULL) = (decided_at IS NULL))),
    CONSTRAINT authorization_consents_decision_check CHECK ((decision = ANY (ARRAY['approve'::text, 'deny'::text]))),
    CONSTRAINT authorization_consents_request_snapshot_check CHECK ((jsonb_typeof(request_snapshot) = 'object'::text))
);


--
-- Name: authorization_logins; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.authorization_logins (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    issuer text NOT NULL,
    client_id text NOT NULL,
    token_sha256 text NOT NULL,
    browser_sha256 text NOT NULL,
    authorize_uri text NOT NULL,
    request_snapshot jsonb NOT NULL,
    csrf_sha256 text,
    session_snapshot jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    consumed_at timestamp with time zone,
    CONSTRAINT authorization_logins_check CHECK (((session_snapshot IS NULL) = (completed_at IS NULL))),
    CONSTRAINT authorization_logins_check1 CHECK (((consumed_at IS NULL) OR (completed_at IS NOT NULL))),
    CONSTRAINT authorization_logins_request_snapshot_check CHECK ((jsonb_typeof(request_snapshot) = 'object'::text)),
    CONSTRAINT authorization_logins_session_snapshot_check CHECK ((jsonb_typeof(session_snapshot) = 'object'::text))
);


--
-- Name: client_secrets; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.client_secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    client_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    status aegaeon.client_secret_status DEFAULT 'ACTIVE'::aegaeon.client_secret_status NOT NULL,
    active_slot smallint,
    secret_hash text NOT NULL,
    secret_hash_algorithm text DEFAULT 'argon2id'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    comment text,
    CONSTRAINT client_secrets_active_slot_check CHECK (((active_slot IS NULL) OR (active_slot = ANY (ARRAY[1, 2]))))
);


--
-- Name: clients; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    client_identifier text NOT NULL,
    name text NOT NULL,
    client_type aegaeon.client_type NOT NULL,
    redirect_uris text[] NOT NULL,
    allowed_grant_types text[] NOT NULL,
    allowed_scopes text[] NOT NULL,
    token_endpoint_authentication_method text NOT NULL,
    status aegaeon.client_status DEFAULT 'ACTIVE'::aegaeon.client_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    oauth_profile_id uuid,
    CONSTRAINT clients_auth_method_matches_client_type CHECK ((((client_type = 'PUBLIC'::aegaeon.client_type) AND (token_endpoint_authentication_method = 'none'::text)) OR ((client_type = 'CONFIDENTIAL'::aegaeon.client_type) AND (token_endpoint_authentication_method <> 'none'::text)))),
    CONSTRAINT clients_modern_flow_shape CHECK ((NOT ('password'::text = ANY (allowed_grant_types)))),
    CONSTRAINT clients_policy_sets_shape CHECK ((aegaeon.text_array_is_normalized_set(redirect_uris, true) AND aegaeon.text_array_is_normalized_set(allowed_grant_types, false) AND (allowed_grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text, 'client_credentials'::text, 'urn:ietf:params:oauth:grant-type:jwt-bearer'::text, 'urn:ietf:params:oauth:grant-type:token-exchange'::text, 'urn:ietf:params:oauth:grant-type:device_code'::text]) AND aegaeon.oauth_scope_token_array_is_valid(allowed_scopes))),
    CONSTRAINT clients_token_endpoint_authentication_method_shape CHECK ((token_endpoint_authentication_method = ANY (ARRAY['client_secret_basic'::text, 'client_secret_post'::text, 'private_key_jwt'::text, 'none'::text])))
);


--
-- Name: connections; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    oauth_profile_id uuid,
    connection_identifier text NOT NULL,
    name text NOT NULL,
    connection_type aegaeon.connection_type DEFAULT 'OIDC'::aegaeon.connection_type NOT NULL,
    issuer_url text NOT NULL,
    client_id text NOT NULL,
    client_auth_method text DEFAULT 'client_secret_basic'::text NOT NULL,
    status aegaeon.connection_status DEFAULT 'ACTIVE'::aegaeon.connection_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    client_secret_encrypted bytea
);


--
-- Name: control_plane_policies; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.control_plane_policies (
    id text NOT NULL,
    management_session_ttl_seconds integer DEFAULT 28800 NOT NULL,
    management_max_sessions integer DEFAULT 10000 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    management_allowed_origins text[] DEFAULT ARRAY[]::text[] NOT NULL,
    management_issuer_base_domain text DEFAULT 'aegaeon.cloud'::text NOT NULL,
    management_api_key_default_expiration_days integer DEFAULT 90 CONSTRAINT control_plane_policies_management_api_key_default_expi_not_null NOT NULL,
    management_api_key_max_expiration_days integer DEFAULT 365 CONSTRAINT control_plane_policies_management_api_key_max_expirati_not_null NOT NULL,
    management_api_key_allow_no_expiration boolean DEFAULT false CONSTRAINT control_plane_policies_management_api_key_allow_no_exp_not_null NOT NULL,
    CONSTRAINT control_plane_policies_api_key_lifecycle_bounds CHECK (((management_api_key_default_expiration_days >= 1) AND (management_api_key_default_expiration_days <= management_api_key_max_expiration_days) AND ((management_api_key_max_expiration_days >= 1) AND (management_api_key_max_expiration_days <= 365)))),
    CONSTRAINT control_plane_policies_management_allowed_origins_no_nulls CHECK ((array_position(management_allowed_origins, NULL::text) IS NULL)),
    CONSTRAINT control_plane_policies_management_issuer_base_domain_non_empty CHECK ((btrim(management_issuer_base_domain) <> ''::text)),
    CONSTRAINT control_plane_policies_management_sessions_bounds CHECK (((management_session_ttl_seconds >= 1) AND (management_session_ttl_seconds <= 86400) AND ((management_max_sessions >= 1) AND (management_max_sessions <= 1000000)))),
    CONSTRAINT control_plane_policies_singleton_id CHECK ((id = 'default'::text))
);


--
-- Name: dynamic_client_registrations; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.dynamic_client_registrations (
    environment_id uuid NOT NULL,
    client_id uuid NOT NULL,
    client_identifier text NOT NULL,
    registration_access_token_hash text CONSTRAINT dynamic_client_registration_registration_access_token__not_null NOT NULL,
    registration_access_token_hash_algorithm text DEFAULT 'sha256'::text CONSTRAINT dynamic_client_registratio_registration_access_token__not_null1 NOT NULL,
    client_id_issued_at timestamp with time zone NOT NULL,
    response_types text[] DEFAULT ARRAY['code'::text] NOT NULL,
    post_logout_redirect_uris text[] DEFAULT ARRAY[]::text[] NOT NULL,
    backchannel_logout_uri text,
    backchannel_logout_session_required boolean DEFAULT false CONSTRAINT dynamic_client_registration_backchannel_logout_session_not_null NOT NULL,
    jwks_uri text,
    jwks jsonb,
    token_endpoint_auth_signing_alg text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dynamic_client_registrations_hash_algorithm CHECK ((registration_access_token_hash_algorithm = 'sha256'::text)),
    CONSTRAINT dynamic_client_registrations_response_types_shape CHECK ((response_types = ARRAY['code'::text])),
    CONSTRAINT dynamic_client_registrations_token_hash_shape CHECK (((length(registration_access_token_hash) = 64) AND (registration_access_token_hash = lower(registration_access_token_hash)) AND (registration_access_token_hash ~ '^[0-9a-f]{64}$'::text)))
);


--
-- Name: end_user_identity_owners; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_user_identity_owners (
    owner_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL
);


--
-- Name: end_user_password_credentials; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_user_password_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    end_user_id uuid NOT NULL,
    password_hash text NOT NULL,
    status aegaeon.end_user_password_credential_status DEFAULT 'ACTIVE'::aegaeon.end_user_password_credential_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    created_by_administrator_id uuid,
    revoked_by_administrator_id uuid,
    CONSTRAINT end_user_password_credentials_last_used_after_created CHECK (((last_used_at IS NULL) OR (last_used_at >= created_at)))
);


--
-- Name: end_user_profiles; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_user_profiles (
    end_user_id uuid NOT NULL,
    subject_policy text DEFAULT 'explicit'::text NOT NULL,
    email_verified boolean DEFAULT false NOT NULL,
    display_name text,
    custom_claims jsonb DEFAULT '{}'::jsonb NOT NULL,
    profile_version bigint DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT end_user_profiles_custom_claims_object CHECK ((jsonb_typeof(custom_claims) = 'object'::text)),
    CONSTRAINT end_user_profiles_profile_version_positive CHECK ((profile_version > 0)),
    CONSTRAINT end_user_profiles_subject_policy_valid CHECK ((subject_policy = 'explicit'::text))
);


--
-- Name: end_user_recovery_tokens; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_user_recovery_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    end_user_id uuid NOT NULL,
    token_hash text NOT NULL,
    purpose aegaeon.end_user_recovery_token_purpose NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    redeemed_at timestamp with time zone,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_administrator_id uuid,
    revoked_by_administrator_id uuid,
    CONSTRAINT end_user_recovery_tokens_expires_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT end_user_recovery_tokens_redeemed_after_created CHECK (((redeemed_at IS NULL) OR (redeemed_at >= created_at))),
    CONSTRAINT end_user_recovery_tokens_revoked_after_created CHECK (((revoked_at IS NULL) OR (revoked_at >= created_at))),
    CONSTRAINT end_user_recovery_tokens_single_terminal_state CHECK ((NOT ((redeemed_at IS NOT NULL) AND (revoked_at IS NOT NULL))))
);


--
-- Name: end_user_subject_reservations; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_user_subject_reservations (
    environment_id uuid NOT NULL,
    subject text NOT NULL COLLATE pg_catalog."C",
    owner_id uuid NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT end_user_subject_reservations_subject_check CHECK (aegaeon.subject_ownership_valid_subject(subject))
);


--
-- Name: end_users; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    subject text NOT NULL COLLATE pg_catalog."C",
    email text,
    status aegaeon.end_user_status DEFAULT 'INVITED'::aegaeon.end_user_status NOT NULL,
    blocked_at timestamp with time zone,
    blocked_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT end_users_email_lowercase CHECK (((email IS NULL) OR (email = lower(email)))),
    CONSTRAINT end_users_subject_format CHECK (aegaeon.subject_ownership_valid_subject(subject))
);


--
-- Name: environment_dcr_bearer_tokens; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environment_dcr_bearer_tokens (
    environment_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_hash_algorithm text DEFAULT 'sha256'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_dcr_bearer_tokens_hash_algorithm CHECK ((token_hash_algorithm = 'sha256'::text)),
    CONSTRAINT environment_dcr_bearer_tokens_hash_shape CHECK (((length(token_hash) = 64) AND (token_hash = lower(token_hash)) AND (token_hash ~ '^[0-9a-f]{64}$'::text)))
);


--
-- Name: environment_key_stores; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environment_key_stores (
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    type text NOT NULL,
    configuration_public jsonb NOT NULL,
    configuration_secret_encrypted bytea,
    redacted boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: environment_policies; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environment_policies (
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    pkce_required boolean NOT NULL,
    dcr_enabled boolean NOT NULL,
    require_state_parameter boolean DEFAULT false NOT NULL,
    strict_authorize_redirect boolean DEFAULT true NOT NULL,
    require_client_auth_token boolean DEFAULT true NOT NULL,
    require_client_auth_par boolean DEFAULT true NOT NULL,
    require_client_auth_introspection boolean DEFAULT true NOT NULL,
    require_client_auth_revocation boolean DEFAULT true NOT NULL,
    dpop_strict boolean DEFAULT true NOT NULL,
    dpop_iat_window_seconds integer DEFAULT 300 NOT NULL,
    par_expires_in_seconds integer DEFAULT 90 NOT NULL,
    private_key_jwt_enabled boolean DEFAULT false NOT NULL,
    client_jwt_allowed_algs text[] DEFAULT ARRAY['RS256'::text] NOT NULL,
    client_jwt_require_kid boolean DEFAULT false NOT NULL,
    jwt_leeway_seconds integer DEFAULT 60 NOT NULL,
    pkjwt_jti_window_seconds integer DEFAULT 300 NOT NULL,
    request_object_jti_ttl_seconds integer DEFAULT 600 NOT NULL,
    dcr_require_pkce_for_public boolean DEFAULT false NOT NULL,
    dcr_require_pkce_for_confidential boolean DEFAULT false NOT NULL,
    dcr_require_sender_constrained boolean DEFAULT false NOT NULL,
    dcr_allowed_sender_methods text[] DEFAULT ARRAY['dpop'::text] NOT NULL,
    ssa_jwt_pem text,
    ssa_expected_iss text,
    ssa_expected_aud text,
    ssa_leeway_seconds integer DEFAULT 120 NOT NULL,
    oidc_enabled boolean DEFAULT false NOT NULL,
    oidc_enable_discovery boolean DEFAULT true NOT NULL,
    oidc_enable_userinfo boolean DEFAULT true NOT NULL,
    oidc_enable_logout boolean DEFAULT false NOT NULL,
    oidc_enable_backchannel_logout boolean DEFAULT false NOT NULL,
    oidc_logout_session_ttl_seconds integer DEFAULT 600 NOT NULL,
    oidc_backchannel_logout_timeout_seconds integer DEFAULT 2 CONSTRAINT environment_policies_oidc_backchannel_logout_timeout_s_not_null NOT NULL,
    oidc_require_nonce boolean DEFAULT false NOT NULL,
    mtls_enabled boolean DEFAULT false NOT NULL,
    mtls_base_url text,
    mtls_alias_par_enabled boolean DEFAULT false NOT NULL,
    allowed_signing_algorithms text[] NOT NULL,
    allowed_grant_types text[] NOT NULL,
    access_token_time_to_live_seconds integer NOT NULL,
    id_token_time_to_live_seconds integer NOT NULL,
    refresh_token_time_to_live_seconds integer CONSTRAINT environment_policies_refresh_token_time_to_live_second_not_null NOT NULL,
    authorization_code_time_to_live_seconds integer CONSTRAINT environment_policies_authorization_code_time_to_live_s_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    dpop_require_nonce boolean DEFAULT true NOT NULL,
    dpop_nonce_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwt_bearer_allow_client_subject boolean DEFAULT false NOT NULL,
    jwt_bearer_jti_window_seconds integer DEFAULT 300 NOT NULL,
    auth_session_ttl_seconds integer DEFAULT 28800 NOT NULL,
    auth_max_sessions integer DEFAULT 10000 NOT NULL,
    stepup_challenge_ttl_seconds integer DEFAULT 300 NOT NULL,
    upstream_auth_ttl_seconds integer DEFAULT 300 NOT NULL,
    upstream_logout_relay_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwt_access_tokens_enabled boolean DEFAULT false NOT NULL,
    jwt_introspection_enabled boolean DEFAULT false NOT NULL,
    jwt_introspection_exp_seconds integer DEFAULT 60 NOT NULL,
    authorization_details_types_supported text[] DEFAULT ARRAY[]::text[] CONSTRAINT environment_policies_authorization_details_types_suppo_not_null NOT NULL,
    acr_values_supported text[] DEFAULT ARRAY[]::text[] NOT NULL,
    default_acr text,
    local_password_acr text,
    federation_entity_cache_ttl_seconds integer DEFAULT 1800 CONSTRAINT environment_policies_federation_entity_cache_ttl_secon_not_null NOT NULL,
    federation_trust_chain_cache_ttl_seconds integer DEFAULT 3600 CONSTRAINT environment_policies_federation_trust_chain_cache_ttl__not_null NOT NULL,
    federation_cache_max_entries integer DEFAULT 1000 NOT NULL,
    upstream_discovery_cache_ttl_seconds integer DEFAULT 300 CONSTRAINT environment_policies_upstream_discovery_cache_ttl_seco_not_null NOT NULL,
    upstream_jwks_cache_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwks_allow_kid_reuse boolean DEFAULT false NOT NULL,
    jwks_circuit_open_fails integer DEFAULT 3 NOT NULL,
    jwks_circuit_reset_seconds integer DEFAULT 30 NOT NULL,
    jwks_cache_ttl_seconds integer DEFAULT 300 NOT NULL,
    jwks_cache_gc_interval_seconds integer DEFAULT 600 NOT NULL,
    jwks_http_timeout_seconds integer DEFAULT 5 NOT NULL,
    jwks_refresh_skew_seconds integer DEFAULT 10 NOT NULL,
    jwks_shared_state_max_age_seconds integer DEFAULT 86400 NOT NULL,
    jwks_max_body_bytes integer DEFAULT 65536 NOT NULL,
    jwks_http_retries integer DEFAULT 2 NOT NULL,
    crypto_profile text DEFAULT 'verified'::text NOT NULL,
    sender_constrained aegaeon.oauth_sender_constraint DEFAULT 'DPOP'::aegaeon.oauth_sender_constraint NOT NULL,
    require_scope_subset boolean DEFAULT true NOT NULL,
    require_audience_match boolean DEFAULT true NOT NULL,
    retain_refresh_chain boolean DEFAULT true NOT NULL,
    enforce_refresh_sender_binding boolean DEFAULT true NOT NULL,
    runtime_config_monitor_interval_seconds integer DEFAULT 30 CONSTRAINT environment_policies_runtime_config_monitor_interval_s_not_null NOT NULL,
    cleanup_interval_seconds integer DEFAULT 60 NOT NULL,
    dcr_everparse_runtime_enabled boolean DEFAULT false NOT NULL,
    request_object_everparse_runtime_enabled boolean DEFAULT false CONSTRAINT environment_policies_request_object_everparse_runtime__not_null NOT NULL,
    require_pushed_authorization_requests boolean DEFAULT false CONSTRAINT environment_policies_require_pushed_authorization_requ_not_null NOT NULL,
    jose_header_max_len integer DEFAULT 4096 NOT NULL,
    federation_outbound_allowed_domains text[] DEFAULT ARRAY[]::text[] CONSTRAINT environment_policies_federation_outbound_allowed_domai_not_null NOT NULL,
    upstream_outbound_allowed_domains text[] DEFAULT ARRAY[]::text[] NOT NULL,
    jwks_local_cache_max_entries integer DEFAULT 4096 NOT NULL,
    upstream_discovery_cache_max_entries integer DEFAULT 4096 CONSTRAINT environment_policies_upstream_discovery_cache_max_entr_not_null NOT NULL,
    upstream_jwks_cache_max_entries integer DEFAULT 4096 NOT NULL,
    device_code_ttl_seconds integer DEFAULT 600 NOT NULL,
    device_code_poll_interval_seconds integer DEFAULT 5 NOT NULL,
    activation_token_default_ttl_seconds integer DEFAULT 86400 CONSTRAINT environment_policies_activation_token_default_ttl_seco_not_null NOT NULL,
    password_reset_token_default_ttl_seconds integer DEFAULT 3600 CONSTRAINT environment_policies_password_reset_token_default_ttl__not_null NOT NULL,
    recovery_token_max_ttl_seconds integer DEFAULT 604800 NOT NULL,
    client_secret_default_expiration_days integer DEFAULT 90 CONSTRAINT environment_policies_client_secret_default_expiration__not_null NOT NULL,
    client_secret_max_expiration_days integer DEFAULT 365 NOT NULL,
    token_exchange jsonb DEFAULT '{"rules": [], "targets": [], "version": 1}'::jsonb NOT NULL,
    client_credentials jsonb DEFAULT '{"rules": [], "version": 1, "resourceServers": []}'::jsonb NOT NULL,
    CONSTRAINT environment_policies_client_jwt_algs_verified_shape CHECK ((aegaeon.text_array_is_normalized_set(client_jwt_allowed_algs, false) AND (client_jwt_allowed_algs <@ ARRAY['RS256'::text]))),
    CONSTRAINT environment_policies_credential_lifecycle_bounds CHECK (((activation_token_default_ttl_seconds >= 300) AND (activation_token_default_ttl_seconds <= recovery_token_max_ttl_seconds) AND (password_reset_token_default_ttl_seconds >= 300) AND (password_reset_token_default_ttl_seconds <= recovery_token_max_ttl_seconds) AND (recovery_token_max_ttl_seconds >= 300) AND (recovery_token_max_ttl_seconds <= 604800) AND (client_secret_default_expiration_days > 0) AND (client_secret_default_expiration_days <= client_secret_max_expiration_days) AND (client_secret_max_expiration_days > 0) AND (client_secret_max_expiration_days <= 365))),
    CONSTRAINT environment_policies_crypto_profile CHECK ((crypto_profile = 'verified'::text)),
    CONSTRAINT environment_policies_dcr_sender_methods_verified_shape CHECK ((aegaeon.text_array_is_normalized_set(dcr_allowed_sender_methods, false) AND (dcr_allowed_sender_methods <@ ARRAY['dpop'::text]))),
    CONSTRAINT environment_policies_federation_outbound_domains_shape CHECK (aegaeon.text_array_is_normalized_set(federation_outbound_allowed_domains, true)),
    CONSTRAINT environment_policies_grant_sets_shape CHECK ((aegaeon.text_array_is_normalized_set(allowed_grant_types, false) AND (allowed_grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text, 'client_credentials'::text, 'urn:ietf:params:oauth:grant-type:jwt-bearer'::text, 'urn:ietf:params:oauth:grant-type:token-exchange'::text, 'urn:ietf:params:oauth:grant-type:device_code'::text]))),
    CONSTRAINT environment_policies_modern_flow_shape CHECK ((NOT ('password'::text = ANY (allowed_grant_types)))),
    CONSTRAINT environment_policies_signing_algorithms_verified_shape CHECK ((aegaeon.text_array_is_normalized_set(allowed_signing_algorithms, false) AND (allowed_signing_algorithms <@ ARRAY['RS256'::text, 'EdDSA'::text]))),
    CONSTRAINT environment_policies_token_ttls_positive CHECK (((access_token_time_to_live_seconds > 0) AND (access_token_time_to_live_seconds <= 86400) AND (id_token_time_to_live_seconds > 0) AND (id_token_time_to_live_seconds <= 86400) AND (refresh_token_time_to_live_seconds > 0) AND (refresh_token_time_to_live_seconds <= 7776000) AND (authorization_code_time_to_live_seconds > 0) AND (authorization_code_time_to_live_seconds <= 600) AND (auth_session_ttl_seconds > 0) AND (auth_session_ttl_seconds <= 86400) AND (auth_max_sessions > 0) AND (auth_max_sessions <= 1000000) AND (stepup_challenge_ttl_seconds > 0) AND (stepup_challenge_ttl_seconds <= 600) AND (upstream_auth_ttl_seconds > 0) AND (upstream_auth_ttl_seconds <= 3600) AND (upstream_logout_relay_ttl_seconds > 0) AND (upstream_logout_relay_ttl_seconds <= 86400) AND (upstream_discovery_cache_ttl_seconds > 0) AND (upstream_discovery_cache_ttl_seconds <= 86400) AND (upstream_discovery_cache_max_entries > 0) AND (upstream_discovery_cache_max_entries <= 1000000) AND (upstream_jwks_cache_ttl_seconds > 0) AND (upstream_jwks_cache_ttl_seconds <= 86400) AND (upstream_jwks_cache_max_entries > 0) AND (upstream_jwks_cache_max_entries <= 1000000) AND (cleanup_interval_seconds > 0) AND (cleanup_interval_seconds <= 3600) AND (runtime_config_monitor_interval_seconds > 0) AND (runtime_config_monitor_interval_seconds <= 3600) AND (federation_entity_cache_ttl_seconds > 0) AND (federation_entity_cache_ttl_seconds <= 86400) AND (federation_trust_chain_cache_ttl_seconds > 0) AND (federation_trust_chain_cache_ttl_seconds <= 86400) AND (federation_cache_max_entries > 0) AND (federation_cache_max_entries <= 1000000) AND (dpop_iat_window_seconds > 0) AND (dpop_iat_window_seconds <= 300) AND (dpop_nonce_ttl_seconds > 0) AND (dpop_nonce_ttl_seconds <= 3600) AND (par_expires_in_seconds > 0) AND (par_expires_in_seconds <= 600) AND (device_code_ttl_seconds > 0) AND (device_code_ttl_seconds <= 3600) AND (device_code_poll_interval_seconds >= 5) AND (device_code_poll_interval_seconds <= 300) AND (jwt_leeway_seconds >= 0) AND (jwt_leeway_seconds <= 300) AND (pkjwt_jti_window_seconds > 0) AND (pkjwt_jti_window_seconds <= 3600) AND (jose_header_max_len > 0) AND (jose_header_max_len <= 65536) AND (jwks_circuit_open_fails > 0) AND (jwks_circuit_open_fails <= 1000) AND (jwks_circuit_reset_seconds > 0) AND (jwks_circuit_reset_seconds <= 3600) AND (jwks_cache_ttl_seconds > 0) AND (jwks_cache_ttl_seconds <= 86400) AND (jwks_cache_gc_interval_seconds > 0) AND (jwks_cache_gc_interval_seconds <= 86400) AND (jwks_local_cache_max_entries > 0) AND (jwks_local_cache_max_entries <= 1000000) AND (jwks_http_timeout_seconds > 0) AND (jwks_http_timeout_seconds <= 60) AND (jwks_refresh_skew_seconds >= 0) AND (jwks_refresh_skew_seconds <= 3600) AND (jwks_shared_state_max_age_seconds > 0) AND (jwks_shared_state_max_age_seconds <= 86400) AND (jwks_max_body_bytes > 0) AND (jwks_max_body_bytes <= 16777216) AND (jwks_http_retries >= 0) AND (jwks_http_retries <= 10) AND (jwt_bearer_jti_window_seconds > 0) AND (jwt_bearer_jti_window_seconds <= 3600) AND (request_object_jti_ttl_seconds > 0) AND (request_object_jti_ttl_seconds <= 3600) AND (jwt_introspection_exp_seconds > 0) AND (jwt_introspection_exp_seconds <= 60) AND (ssa_leeway_seconds >= 0) AND (ssa_leeway_seconds <= 300) AND (oidc_logout_session_ttl_seconds > 0) AND (oidc_logout_session_ttl_seconds <= 86400) AND (oidc_backchannel_logout_timeout_seconds > 0) AND (oidc_backchannel_logout_timeout_seconds <= 60))),
    CONSTRAINT environment_policies_upstream_outbound_domains_shape CHECK (aegaeon.text_array_is_normalized_set(upstream_outbound_allowed_domains, true))
);


--
-- Name: environment_revoked_client_secrets; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environment_revoked_client_secrets (
    environment_id uuid NOT NULL,
    client_secret_id uuid NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_by_administrator_id uuid,
    reason text
);


--
-- Name: environment_scope_allowlist; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.environment_scope_allowlist (
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    scope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT environment_scope_allowlist_scope_token_shape CHECK (aegaeon.oauth_scope_token_is_valid(scope))
);


--
-- Name: federation_entity_cache; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.federation_entity_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    entity_id text NOT NULL,
    entity_configuration_jws text NOT NULL,
    parsed_statement jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_entity_cache_entity_id_nonempty CHECK ((length(entity_id) > 0)),
    CONSTRAINT federation_entity_cache_expires_after_fetch CHECK ((expires_at > fetched_at)),
    CONSTRAINT federation_entity_cache_jws_nonempty CHECK ((length(TRIM(BOTH FROM entity_configuration_jws)) > 0))
);


--
-- Name: federation_logout_recovery_incidents; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.federation_logout_recovery_incidents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    team_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    connection_id uuid,
    downstream_client_id text,
    upstream_issuer text NOT NULL,
    recovery_policy text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    session_hint_claim text,
    session_hint_value_hash text,
    relay_token_hash text NOT NULL,
    downstream_redirect_uri text CONSTRAINT federation_logout_recovery_inc_downstream_redirect_uri_not_null NOT NULL,
    downstream_state text,
    failure_reason text,
    request_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    resolved_at timestamp with time zone,
    CONSTRAINT federation_logout_recovery_incidents_downstream_redirect_uri_no CHECK ((length(downstream_redirect_uri) > 0)),
    CONSTRAINT federation_logout_recovery_incidents_expires_after_created CHECK ((expires_at > created_at)),
    CONSTRAINT federation_logout_recovery_incidents_recovery_policy_valid CHECK ((recovery_policy = ANY (ARRAY['force_prompt_login'::text, 'disable_connection'::text]))),
    CONSTRAINT federation_logout_recovery_incidents_relay_token_hash_nonempty CHECK ((length(relay_token_hash) > 0)),
    CONSTRAINT federation_logout_recovery_incidents_request_id_nonempty CHECK ((length(request_id) > 0)),
    CONSTRAINT federation_logout_recovery_incidents_resolved_at_matches_status CHECK ((((status = 'pending'::text) AND (resolved_at IS NULL)) OR ((status <> 'pending'::text) AND (resolved_at IS NOT NULL)))),
    CONSTRAINT federation_logout_recovery_incidents_session_hint_claim_nonempt CHECK (((session_hint_claim IS NULL) OR (length(session_hint_claim) > 0))),
    CONSTRAINT federation_logout_recovery_incidents_status_valid CHECK ((status = ANY (ARRAY['pending'::text, 'completed'::text, 'expired'::text, 'callback_rejected'::text, 'operator_cleared'::text]))),
    CONSTRAINT federation_logout_recovery_incidents_upstream_issuer_nonempty CHECK ((length(upstream_issuer) > 0))
);


--
-- Name: federation_trust_anchors; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.federation_trust_anchors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    entity_id text NOT NULL,
    jwks jsonb NOT NULL,
    metadata_policy jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT federation_trust_anchors_entity_id_nonempty CHECK ((length(entity_id) > 0))
);


--
-- Name: federation_trust_chains; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.federation_trust_chains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    leaf_entity_id text NOT NULL,
    anchor_entity_id text NOT NULL,
    chain_jwts jsonb NOT NULL,
    resolved_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT federation_trust_chains_anchor_nonempty CHECK ((length(anchor_entity_id) > 0)),
    CONSTRAINT federation_trust_chains_expires_after_resolve CHECK ((expires_at > resolved_at)),
    CONSTRAINT federation_trust_chains_jwts_nonempty_array CHECK (
CASE
    WHEN (jsonb_typeof(chain_jwts) = 'array'::text) THEN (jsonb_array_length(chain_jwts) > 0)
    ELSE false
END),
    CONSTRAINT federation_trust_chains_leaf_nonempty CHECK ((length(leaf_entity_id) > 0))
);


--
-- Name: management_user_runtime_commands; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.management_user_runtime_commands (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    team_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    end_user_id uuid NOT NULL,
    actor_administrator_id uuid CONSTRAINT management_user_runtime_command_actor_administrator_id_not_null NOT NULL,
    request_id text NOT NULL,
    command_type text NOT NULL,
    status aegaeon.management_runtime_command_status DEFAULT 'requested'::aegaeon.management_runtime_command_status NOT NULL,
    phase text,
    payload jsonb NOT NULL,
    result jsonb,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT management_user_runtime_commands_attempts_nonnegative CHECK ((attempts >= 0)),
    CONSTRAINT management_user_runtime_commands_command_type_nonempty CHECK ((length(command_type) > 0)),
    CONSTRAINT management_user_runtime_commands_phase_nonempty CHECK (((phase IS NULL) OR (length(phase) > 0))),
    CONSTRAINT management_user_runtime_commands_request_id_nonempty CHECK ((length(request_id) > 0)),
    CONSTRAINT management_user_runtime_commands_terminal_state_shape CHECK ((((status = 'requested'::aegaeon.management_runtime_command_status) AND (phase IS NULL) AND (result IS NULL) AND (execution_started_at IS NULL) AND (completed_at IS NULL)) OR ((status = 'executing'::aegaeon.management_runtime_command_status) AND (phase IS NOT NULL) AND (result IS NULL) AND (execution_started_at IS NOT NULL) AND (completed_at IS NULL)) OR ((status <> ALL (ARRAY['requested'::aegaeon.management_runtime_command_status, 'executing'::aegaeon.management_runtime_command_status])) AND (phase IS NOT NULL) AND (result IS NOT NULL) AND (execution_started_at IS NOT NULL) AND (completed_at IS NOT NULL))))
);


--
-- Name: oauth_profiles; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.oauth_profiles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    profile_type aegaeon.oauth_profile_type NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    require_pkce boolean DEFAULT true NOT NULL,
    require_state_parameter boolean DEFAULT true NOT NULL,
    require_iss_parameter boolean DEFAULT false NOT NULL,
    sender_constrained aegaeon.oauth_sender_constraint DEFAULT 'DPOP'::aegaeon.oauth_sender_constraint NOT NULL,
    enforce_refresh_sender_binding boolean DEFAULT true NOT NULL,
    allowed_grant_types text[] NOT NULL,
    token_endpoint_auth_methods_allowed text[] NOT NULL,
    expires_at timestamp with time zone,
    status aegaeon.oauth_profile_status DEFAULT 'ACTIVE'::aegaeon.oauth_profile_status NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT oauth_profiles_auth_methods_shape CHECK ((token_endpoint_auth_methods_allowed <@ ARRAY['client_secret_basic'::text, 'client_secret_post'::text, 'private_key_jwt'::text, 'none'::text])),
    CONSTRAINT oauth_profiles_modern_flow_shape CHECK ((require_pkce AND (NOT ('password'::text = ANY (allowed_grant_types))))),
    CONSTRAINT oauth_profiles_policy_sets_shape CHECK ((aegaeon.text_array_is_normalized_set(allowed_grant_types, false) AND (allowed_grant_types <@ ARRAY['authorization_code'::text, 'refresh_token'::text, 'client_credentials'::text, 'urn:ietf:params:oauth:grant-type:jwt-bearer'::text, 'urn:ietf:params:oauth:grant-type:token-exchange'::text, 'urn:ietf:params:oauth:grant-type:device_code'::text]) AND aegaeon.text_array_is_normalized_set(token_endpoint_auth_methods_allowed, false)))
);


--
-- Name: runtime_keys; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.runtime_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    configuration_version_id uuid NOT NULL,
    usage aegaeon.runtime_key_usage NOT NULL,
    kid text NOT NULL,
    algorithm text NOT NULL,
    provider aegaeon.runtime_key_provider NOT NULL,
    status aegaeon.runtime_key_status NOT NULL,
    public_jwk jsonb NOT NULL,
    key_handle text NOT NULL,
    provider_configuration jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    activated_at timestamp with time zone,
    revoked_at timestamp with time zone,
    retiring_expires_at timestamp with time zone,
    CONSTRAINT runtime_keys_algorithm_matches_usage CHECK ((((usage = 'OIDC_ID_TOKEN_SIGNING'::aegaeon.runtime_key_usage) AND (algorithm = 'RS256'::text)) OR ((usage = 'OIDC_REQUEST_OBJECT_DECRYPTION'::aegaeon.runtime_key_usage) AND (algorithm = 'RSA-OAEP+A256GCM'::text)) OR ((usage = ANY (ARRAY['JWT_ACCESS_TOKEN_SIGNING'::aegaeon.runtime_key_usage, 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage])) AND (algorithm = 'EdDSA'::text)))),
    CONSTRAINT runtime_keys_algorithm_non_empty CHECK ((btrim(algorithm) <> ''::text)),
    CONSTRAINT runtime_keys_key_handle_non_empty CHECK ((btrim(key_handle) <> ''::text)),
    CONSTRAINT runtime_keys_kid_non_empty CHECK ((btrim(kid) <> ''::text)),
    CONSTRAINT runtime_keys_provider_configuration_object CHECK ((jsonb_typeof(provider_configuration) = 'object'::text)),
    CONSTRAINT runtime_keys_provider_shape CHECK ((((provider = 'databaseEncrypted'::aegaeon.runtime_key_provider) AND (provider_configuration = '{}'::jsonb)) OR ((provider = 'awsKms'::aegaeon.runtime_key_provider) AND (usage = 'OIDC_ID_TOKEN_SIGNING'::aegaeon.runtime_key_usage) AND (algorithm = 'RS256'::text) AND (provider_configuration ? 'region'::text) AND (jsonb_typeof((provider_configuration -> 'region'::text)) = 'string'::text) AND (btrim((provider_configuration ->> 'region'::text)) <> ''::text) AND ((provider_configuration - 'region'::text) = '{}'::jsonb)))),
    CONSTRAINT runtime_keys_public_jwk_object CHECK ((jsonb_typeof(public_jwk) = 'object'::text)),
    CONSTRAINT runtime_keys_retiring_expiry_matches_status CHECK ((((status = 'RETIRING'::aegaeon.runtime_key_status) AND (retiring_expires_at IS NOT NULL)) OR ((status <> 'RETIRING'::aegaeon.runtime_key_status) AND (retiring_expires_at IS NULL))))
);


--
-- Name: subject_ownership_adoptions; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.subject_ownership_adoptions (
    environment_id uuid NOT NULL,
    kind text NOT NULL,
    receipt_id uuid NOT NULL,
    contract_version integer DEFAULT 1 NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    session_actor text NOT NULL,
    effective_actor text NOT NULL,
    definer_actor text NOT NULL,
    maintenance_reference text,
    manifest_sha256 text,
    inventory_sha256 text,
    receipt_data jsonb,
    CONSTRAINT subject_ownership_adoptions_contract_version_check CHECK ((contract_version = 1)),
    CONSTRAINT subject_ownership_adoptions_shape CHECK ((((kind = 'fresh'::text) AND (maintenance_reference IS NULL) AND (manifest_sha256 IS NULL) AND (inventory_sha256 IS NULL) AND (receipt_data IS NULL)) OR ((kind = 'legacy'::text) AND (maintenance_reference IS NOT NULL) AND (manifest_sha256 IS NOT NULL) AND (inventory_sha256 IS NOT NULL) AND (manifest_sha256 ~ '^[0-9a-f]{64}$'::text) AND (inventory_sha256 ~ '^[0-9a-f]{64}$'::text) AND (receipt_data IS NOT NULL))))
);


--
-- Name: subject_ownership_namespaces; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.subject_ownership_namespaces (
    environment_id uuid NOT NULL,
    issuer_host text NOT NULL,
    origin text NOT NULL,
    contract_version integer DEFAULT 1 NOT NULL,
    recorded_at timestamp with time zone DEFAULT clock_timestamp() NOT NULL,
    CONSTRAINT subject_ownership_namespaces_contract_version_check CHECK ((contract_version = 1)),
    CONSTRAINT subject_ownership_namespaces_origin_check CHECK ((origin = ANY (ARRAY['legacy'::text, 'fresh'::text])))
);


--
-- Name: team_memberships; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.team_memberships (
    team_id uuid CONSTRAINT organization_memberships_organization_id_not_null NOT NULL,
    administrator_id uuid CONSTRAINT organization_memberships_administrator_id_not_null NOT NULL,
    role aegaeon.team_role CONSTRAINT organization_memberships_role_not_null NOT NULL,
    created_at timestamp with time zone DEFAULT now() CONSTRAINT organization_memberships_created_at_not_null NOT NULL
);


--
-- Name: audit_events_default; Type: TABLE ATTACH; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.audit_events ATTACH PARTITION aegaeon.audit_events_default DEFAULT;


--
-- Name: account_links account_links_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_pkey PRIMARY KEY (id);


--
-- Name: administrators administrators_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.administrators
    ADD CONSTRAINT administrators_pkey PRIMARY KEY (id);


--
-- Name: api_key_capabilities api_key_capabilities_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_key_capabilities
    ADD CONSTRAINT api_key_capabilities_pkey PRIMARY KEY (api_key_id, capability);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: application_authorizations application_authorizations_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.application_authorizations
    ADD CONSTRAINT application_authorizations_pkey PRIMARY KEY (environment_id, client_id, subject);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: audit_events_default audit_events_default_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.audit_events_default
    ADD CONSTRAINT audit_events_default_pkey PRIMARY KEY (id, occurred_at);


--
-- Name: authorization_consents authorization_consents_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_consents
    ADD CONSTRAINT authorization_consents_pkey PRIMARY KEY (id);


--
-- Name: authorization_consents authorization_consents_token_sha256_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_consents
    ADD CONSTRAINT authorization_consents_token_sha256_key UNIQUE (token_sha256);


--
-- Name: authorization_logins authorization_logins_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_logins
    ADD CONSTRAINT authorization_logins_pkey PRIMARY KEY (id);


--
-- Name: authorization_logins authorization_logins_token_sha256_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_logins
    ADD CONSTRAINT authorization_logins_token_sha256_key UNIQUE (token_sha256);


--
-- Name: client_secrets client_secrets_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.client_secrets
    ADD CONSTRAINT client_secrets_pkey PRIMARY KEY (id);


--
-- Name: clients clients_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.clients
    ADD CONSTRAINT clients_pkey PRIMARY KEY (id);


--
-- Name: configuration_versions configuration_versions_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.configuration_versions
    ADD CONSTRAINT configuration_versions_pkey PRIMARY KEY (id);


--
-- Name: connections connections_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);


--
-- Name: control_plane_policies control_plane_policies_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.control_plane_policies
    ADD CONSTRAINT control_plane_policies_pkey PRIMARY KEY (id);


--
-- Name: dynamic_client_registrations dynamic_client_registrations_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.dynamic_client_registrations
    ADD CONSTRAINT dynamic_client_registrations_pkey PRIMARY KEY (environment_id, client_id);


--
-- Name: end_user_identity_owners end_user_identity_owners_owner_id_environment_id_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_identity_owners
    ADD CONSTRAINT end_user_identity_owners_owner_id_environment_id_key UNIQUE (owner_id, environment_id);


--
-- Name: end_user_identity_owners end_user_identity_owners_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_identity_owners
    ADD CONSTRAINT end_user_identity_owners_pkey PRIMARY KEY (owner_id);


--
-- Name: end_user_password_credentials end_user_password_credentials_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_password_credentials
    ADD CONSTRAINT end_user_password_credentials_pkey PRIMARY KEY (id);


--
-- Name: end_user_profiles end_user_profiles_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_profiles
    ADD CONSTRAINT end_user_profiles_pkey PRIMARY KEY (end_user_id);


--
-- Name: end_user_recovery_tokens end_user_recovery_tokens_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_recovery_tokens
    ADD CONSTRAINT end_user_recovery_tokens_pkey PRIMARY KEY (id);


--
-- Name: end_user_subject_reservations end_user_subject_reservations_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_subject_reservations
    ADD CONSTRAINT end_user_subject_reservations_pkey PRIMARY KEY (environment_id, subject);


--
-- Name: end_users end_users_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_users
    ADD CONSTRAINT end_users_pkey PRIMARY KEY (id);


--
-- Name: environment_dcr_bearer_tokens environment_dcr_bearer_tokens_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_dcr_bearer_tokens
    ADD CONSTRAINT environment_dcr_bearer_tokens_pkey PRIMARY KEY (environment_id);


--
-- Name: environment_key_stores environment_key_stores_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_key_stores
    ADD CONSTRAINT environment_key_stores_pkey PRIMARY KEY (environment_id);


--
-- Name: environment_policies environment_policies_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_policies
    ADD CONSTRAINT environment_policies_pkey PRIMARY KEY (environment_id);


--
-- Name: environment_revoked_client_secrets environment_revoked_client_secrets_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_revoked_client_secrets
    ADD CONSTRAINT environment_revoked_client_secrets_pkey PRIMARY KEY (environment_id, client_secret_id);


--
-- Name: environment_scope_allowlist environment_scope_allowlist_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_scope_allowlist
    ADD CONSTRAINT environment_scope_allowlist_pkey PRIMARY KEY (environment_id, scope);


--
-- Name: environments environments_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environments
    ADD CONSTRAINT environments_pkey PRIMARY KEY (id);


--
-- Name: federation_entity_cache federation_entity_cache_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_entity_cache
    ADD CONSTRAINT federation_entity_cache_pkey PRIMARY KEY (id);


--
-- Name: federation_logout_recovery_incidents federation_logout_recovery_incidents_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_logout_recovery_incidents
    ADD CONSTRAINT federation_logout_recovery_incidents_pkey PRIMARY KEY (id);


--
-- Name: federation_trust_anchors federation_trust_anchors_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_trust_anchors
    ADD CONSTRAINT federation_trust_anchors_pkey PRIMARY KEY (id);


--
-- Name: federation_trust_chains federation_trust_chains_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_trust_chains
    ADD CONSTRAINT federation_trust_chains_pkey PRIMARY KEY (id);


--
-- Name: management_user_runtime_commands management_user_runtime_commands_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_pkey PRIMARY KEY (id);


--
-- Name: oauth_profiles oauth_profiles_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.oauth_profiles
    ADD CONSTRAINT oauth_profiles_pkey PRIMARY KEY (id);


--
-- Name: runtime_keys runtime_keys_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.runtime_keys
    ADD CONSTRAINT runtime_keys_pkey PRIMARY KEY (id);


--
-- Name: subject_ownership_adoptions subject_ownership_adoptions_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_adoptions
    ADD CONSTRAINT subject_ownership_adoptions_pkey PRIMARY KEY (environment_id);


--
-- Name: subject_ownership_adoptions subject_ownership_adoptions_receipt_id_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_adoptions
    ADD CONSTRAINT subject_ownership_adoptions_receipt_id_key UNIQUE (receipt_id);


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_environment_id_origin_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_namespaces
    ADD CONSTRAINT subject_ownership_namespaces_environment_id_origin_key UNIQUE (environment_id, origin);


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_issuer_host_key; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_namespaces
    ADD CONSTRAINT subject_ownership_namespaces_issuer_host_key UNIQUE (issuer_host);


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_namespaces
    ADD CONSTRAINT subject_ownership_namespaces_pkey PRIMARY KEY (environment_id);


--
-- Name: team_memberships team_memberships_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.team_memberships
    ADD CONSTRAINT team_memberships_pkey PRIMARY KEY (team_id, administrator_id);


--
-- Name: teams teams_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: account_links_connection_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX account_links_connection_id ON aegaeon.account_links USING btree (connection_id);


--
-- Name: account_links_end_user_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX account_links_end_user_id ON aegaeon.account_links USING btree (end_user_id);


--
-- Name: account_links_env_iss_sub_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX account_links_env_iss_sub_unique ON aegaeon.account_links USING btree (environment_id, upstream_issuer, upstream_sub_hash);


--
-- Name: administrators_email_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX administrators_email_unique ON aegaeon.administrators USING btree (email);


--
-- Name: administrators_kind_status; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX administrators_kind_status ON aegaeon.administrators USING btree (kind, status);


--
-- Name: api_keys_key_prefix; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX api_keys_key_prefix ON aegaeon.api_keys USING btree (key_prefix) WHERE (status = 'ACTIVE'::aegaeon.api_key_status);


--
-- Name: api_keys_service_administrator_id_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX api_keys_service_administrator_id_unique ON aegaeon.api_keys USING btree (service_administrator_id);


--
-- Name: api_keys_team_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX api_keys_team_id ON aegaeon.api_keys USING btree (team_id);


--
-- Name: audit_events_env_time; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_env_time ON ONLY aegaeon.audit_events USING btree (environment_id, occurred_at DESC) WHERE (environment_id IS NOT NULL);


--
-- Name: audit_events_default_environment_id_occurred_at_idx; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_default_environment_id_occurred_at_idx ON aegaeon.audit_events_default USING btree (environment_id, occurred_at DESC) WHERE (environment_id IS NOT NULL);


--
-- Name: audit_events_team_time; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_team_time ON ONLY aegaeon.audit_events USING btree (team_id, occurred_at DESC);


--
-- Name: audit_events_default_organization_id_occurred_at_idx; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_default_organization_id_occurred_at_idx ON aegaeon.audit_events_default USING btree (team_id, occurred_at DESC);


--
-- Name: audit_events_request_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_request_id ON ONLY aegaeon.audit_events USING btree (request_id);


--
-- Name: audit_events_default_request_id_idx; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX audit_events_default_request_id_idx ON aegaeon.audit_events_default USING btree (request_id);


--
-- Name: authorization_consents_environment_idx; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX authorization_consents_environment_idx ON aegaeon.authorization_consents USING btree (environment_id, expires_at);


--
-- Name: authorization_logins_environment_idx; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX authorization_logins_environment_idx ON aegaeon.authorization_logins USING btree (environment_id, expires_at);


--
-- Name: client_secrets_client_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX client_secrets_client_id ON aegaeon.client_secrets USING btree (client_id);


--
-- Name: client_secrets_client_slot_active_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX client_secrets_client_slot_active_unique ON aegaeon.client_secrets USING btree (client_id, active_slot) WHERE ((status = 'ACTIVE'::aegaeon.client_secret_status) AND (active_slot IS NOT NULL));


--
-- Name: client_secrets_id_environment_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX client_secrets_id_environment_unique ON aegaeon.client_secrets USING btree (id, environment_id);


--
-- Name: clients_env_client_identifier_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX clients_env_client_identifier_unique ON aegaeon.clients USING btree (environment_id, client_identifier) WHERE (status <> 'DELETED'::aegaeon.client_status);


--
-- Name: clients_environment_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX clients_environment_id ON aegaeon.clients USING btree (environment_id);


--
-- Name: clients_id_environment_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX clients_id_environment_unique ON aegaeon.clients USING btree (id, environment_id);


--
-- Name: clients_oauth_profile_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX clients_oauth_profile_id ON aegaeon.clients USING btree (oauth_profile_id);


--
-- Name: configuration_versions_env_version_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX configuration_versions_env_version_unique ON aegaeon.configuration_versions USING btree (environment_id, version_number);


--
-- Name: configuration_versions_environment_id_created_at; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX configuration_versions_environment_id_created_at ON aegaeon.configuration_versions USING btree (environment_id, created_at DESC);


--
-- Name: configuration_versions_environment_id_id_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX configuration_versions_environment_id_id_unique ON aegaeon.configuration_versions USING btree (environment_id, id);


--
-- Name: configuration_versions_one_active_per_environment; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX configuration_versions_one_active_per_environment ON aegaeon.configuration_versions USING btree (environment_id) WHERE (status = 'ACTIVE'::aegaeon.configuration_version_status);


--
-- Name: connections_environment_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX connections_environment_id ON aegaeon.connections USING btree (environment_id);


--
-- Name: connections_environment_identifier_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX connections_environment_identifier_unique ON aegaeon.connections USING btree (environment_id, connection_identifier) WHERE (status <> 'DELETED'::aegaeon.connection_status);


--
-- Name: connections_id_environment_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX connections_id_environment_unique ON aegaeon.connections USING btree (id, environment_id);


--
-- Name: connections_oauth_profile_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX connections_oauth_profile_id ON aegaeon.connections USING btree (oauth_profile_id);


--
-- Name: dynamic_client_registrations_env_identifier_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX dynamic_client_registrations_env_identifier_unique ON aegaeon.dynamic_client_registrations USING btree (environment_id, client_identifier);


--
-- Name: dynamic_client_registrations_env_token_hash_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX dynamic_client_registrations_env_token_hash_unique ON aegaeon.dynamic_client_registrations USING btree (environment_id, registration_access_token_hash);


--
-- Name: end_user_password_credentials_end_user_id_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX end_user_password_credentials_end_user_id_unique ON aegaeon.end_user_password_credentials USING btree (end_user_id);


--
-- Name: end_user_password_credentials_status; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX end_user_password_credentials_status ON aegaeon.end_user_password_credentials USING btree (status);


--
-- Name: end_user_recovery_tokens_end_user_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX end_user_recovery_tokens_end_user_id ON aegaeon.end_user_recovery_tokens USING btree (end_user_id);


--
-- Name: end_user_recovery_tokens_one_live_per_user_purpose; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX end_user_recovery_tokens_one_live_per_user_purpose ON aegaeon.end_user_recovery_tokens USING btree (end_user_id, purpose) WHERE ((redeemed_at IS NULL) AND (revoked_at IS NULL));


--
-- Name: end_user_recovery_tokens_token_hash_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX end_user_recovery_tokens_token_hash_unique ON aegaeon.end_user_recovery_tokens USING btree (token_hash);


--
-- Name: end_users_environment_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX end_users_environment_id ON aegaeon.end_users USING btree (environment_id);


--
-- Name: end_users_environment_subject_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX end_users_environment_subject_unique ON aegaeon.end_users USING btree (environment_id, subject) WHERE (status <> 'DELETED'::aegaeon.end_user_status);


--
-- Name: end_users_id_environment_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX end_users_id_environment_unique ON aegaeon.end_users USING btree (id, environment_id);


--
-- Name: environments_id_tenant_id_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX environments_id_tenant_id_unique ON aegaeon.environments USING btree (id, tenant_id);


--
-- Name: environments_issuer_host_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX environments_issuer_host_unique ON aegaeon.environments USING btree (issuer_host);


--
-- Name: environments_tenant_slug_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX environments_tenant_slug_unique ON aegaeon.environments USING btree (tenant_id, slug) WHERE (status <> 'DELETED'::aegaeon.environment_status);


--
-- Name: federation_entity_cache_env_entity_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX federation_entity_cache_env_entity_unique ON aegaeon.federation_entity_cache USING btree (environment_id, entity_id);


--
-- Name: federation_entity_cache_expires_at; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_entity_cache_expires_at ON aegaeon.federation_entity_cache USING btree (expires_at);


--
-- Name: federation_logout_recovery_incidents_connection_status_created; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_logout_recovery_incidents_connection_status_created ON aegaeon.federation_logout_recovery_incidents USING btree (connection_id, status, created_at DESC);


--
-- Name: federation_logout_recovery_incidents_environment_status_created; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_logout_recovery_incidents_environment_status_created ON aegaeon.federation_logout_recovery_incidents USING btree (environment_id, status, created_at DESC);


--
-- Name: federation_logout_recovery_incidents_pending_expires_at; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_logout_recovery_incidents_pending_expires_at ON aegaeon.federation_logout_recovery_incidents USING btree (expires_at) WHERE (status = 'pending'::text);


--
-- Name: federation_logout_recovery_incidents_relay_token_hash_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX federation_logout_recovery_incidents_relay_token_hash_unique ON aegaeon.federation_logout_recovery_incidents USING btree (relay_token_hash);


--
-- Name: federation_logout_recovery_incidents_team_status_created; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_logout_recovery_incidents_team_status_created ON aegaeon.federation_logout_recovery_incidents USING btree (team_id, status, created_at DESC);


--
-- Name: federation_trust_anchors_env_entity_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX federation_trust_anchors_env_entity_unique ON aegaeon.federation_trust_anchors USING btree (environment_id, entity_id);


--
-- Name: federation_trust_chains_env_leaf_anchor_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX federation_trust_chains_env_leaf_anchor_unique ON aegaeon.federation_trust_chains USING btree (environment_id, leaf_entity_id, anchor_entity_id);


--
-- Name: federation_trust_chains_expires_at; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX federation_trust_chains_expires_at ON aegaeon.federation_trust_chains USING btree (expires_at);


--
-- Name: management_user_runtime_commands_active_execution; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX management_user_runtime_commands_active_execution ON aegaeon.management_user_runtime_commands USING btree (environment_id, status, updated_at) WHERE (status = ANY (ARRAY['requested'::aegaeon.management_runtime_command_status, 'executing'::aegaeon.management_runtime_command_status]));


--
-- Name: management_user_runtime_commands_env_status_created; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX management_user_runtime_commands_env_status_created ON aegaeon.management_user_runtime_commands USING btree (environment_id, status, created_at DESC);


--
-- Name: management_user_runtime_commands_request_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX management_user_runtime_commands_request_id ON aegaeon.management_user_runtime_commands USING btree (request_id);


--
-- Name: management_user_runtime_commands_user_created; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX management_user_runtime_commands_user_created ON aegaeon.management_user_runtime_commands USING btree (end_user_id, created_at DESC);


--
-- Name: oauth_profiles_default_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX oauth_profiles_default_unique ON aegaeon.oauth_profiles USING btree (environment_id, configuration_version_id, profile_type) WHERE (is_default AND (status = 'ACTIVE'::aegaeon.oauth_profile_status));


--
-- Name: oauth_profiles_environment_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX oauth_profiles_environment_id ON aegaeon.oauth_profiles USING btree (environment_id);


--
-- Name: oauth_profiles_environment_status; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX oauth_profiles_environment_status ON aegaeon.oauth_profiles USING btree (environment_id, profile_type, status);


--
-- Name: oauth_profiles_id_environment_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX oauth_profiles_id_environment_unique ON aegaeon.oauth_profiles USING btree (id, environment_id);


--
-- Name: runtime_keys_environment_kid_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX runtime_keys_environment_kid_unique ON aegaeon.runtime_keys USING btree (environment_id, kid);


--
-- Name: runtime_keys_one_active_per_environment_usage; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX runtime_keys_one_active_per_environment_usage ON aegaeon.runtime_keys USING btree (environment_id, usage) WHERE (status = 'ACTIVE'::aegaeon.runtime_key_status);


--
-- Name: runtime_keys_one_next_per_environment_usage; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX runtime_keys_one_next_per_environment_usage ON aegaeon.runtime_keys USING btree (environment_id, usage) WHERE (status = 'NEXT'::aegaeon.runtime_key_status);


--
-- Name: runtime_keys_retiring_expires_at; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX runtime_keys_retiring_expires_at ON aegaeon.runtime_keys USING btree (environment_id, usage, retiring_expires_at) WHERE (status = 'RETIRING'::aegaeon.runtime_key_status);


--
-- Name: team_memberships_administrator_id; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE INDEX team_memberships_administrator_id ON aegaeon.team_memberships USING btree (administrator_id);


--
-- Name: teams_slug_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX teams_slug_unique ON aegaeon.teams USING btree (slug) WHERE ((slug IS NOT NULL) AND (status <> 'DELETED'::aegaeon.team_status));


--
-- Name: tenants_id_team_id_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX tenants_id_team_id_unique ON aegaeon.tenants USING btree (id, team_id);


--
-- Name: tenants_team_slug_unique; Type: INDEX; Schema: aegaeon; Owner: -
--

CREATE UNIQUE INDEX tenants_team_slug_unique ON aegaeon.tenants USING btree (team_id, slug) WHERE (status <> 'DELETED'::aegaeon.tenant_status);


--
-- Name: audit_events_default_environment_id_occurred_at_idx; Type: INDEX ATTACH; Schema: aegaeon; Owner: -
--

ALTER INDEX aegaeon.audit_events_env_time ATTACH PARTITION aegaeon.audit_events_default_environment_id_occurred_at_idx;


--
-- Name: audit_events_default_organization_id_occurred_at_idx; Type: INDEX ATTACH; Schema: aegaeon; Owner: -
--

ALTER INDEX aegaeon.audit_events_team_time ATTACH PARTITION aegaeon.audit_events_default_organization_id_occurred_at_idx;


--
-- Name: audit_events_default_pkey; Type: INDEX ATTACH; Schema: aegaeon; Owner: -
--

ALTER INDEX aegaeon.audit_events_pkey ATTACH PARTITION aegaeon.audit_events_default_pkey;


--
-- Name: audit_events_default_request_id_idx; Type: INDEX ATTACH; Schema: aegaeon; Owner: -
--

ALTER INDEX aegaeon.audit_events_request_id ATTACH PARTITION aegaeon.audit_events_default_request_id_idx;


--
-- Name: account_links account_links_connection_binding; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER account_links_connection_binding BEFORE INSERT OR UPDATE OF environment_id, connection_id, upstream_issuer, upstream_refresh_token_connection_id ON aegaeon.account_links FOR EACH ROW EXECUTE FUNCTION aegaeon.enforce_account_link_connection_binding();


--
-- Name: connections connections_issuer_url_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER connections_issuer_url_immutable BEFORE UPDATE OF issuer_url ON aegaeon.connections FOR EACH ROW EXECUTE FUNCTION aegaeon.prevent_connection_issuer_url_update();


--
-- Name: end_user_identity_owners end_user_identity_owners_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER end_user_identity_owners_immutable BEFORE DELETE OR UPDATE ON aegaeon.end_user_identity_owners FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: end_user_identity_owners end_user_identity_owners_no_truncate; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER end_user_identity_owners_no_truncate BEFORE TRUNCATE ON aegaeon.end_user_identity_owners FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: end_user_subject_reservations end_user_subject_reservations_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER end_user_subject_reservations_immutable BEFORE DELETE OR UPDATE ON aegaeon.end_user_subject_reservations FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: end_user_subject_reservations end_user_subject_reservations_no_truncate; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER end_user_subject_reservations_no_truncate BEFORE TRUNCATE ON aegaeon.end_user_subject_reservations FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: end_users end_users_subject_ownership; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER end_users_subject_ownership BEFORE INSERT OR UPDATE ON aegaeon.end_users FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_user();


--
-- Name: environments environments_lifecycle_invariants; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER environments_lifecycle_invariants BEFORE INSERT OR UPDATE OF tenant_id, status ON aegaeon.environments FOR EACH ROW EXECUTE FUNCTION aegaeon.enforce_environment_lifecycle_invariants();


--
-- Name: environments environments_subject_namespace_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER environments_subject_namespace_immutable BEFORE UPDATE ON aegaeon.environments FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_environment();


--
-- Name: environments environments_subject_namespace_initialize; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER environments_subject_namespace_initialize AFTER INSERT ON aegaeon.environments FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_environment();


--
-- Name: client_secrets runtime_authority_notify_client_secrets; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_client_secrets AFTER INSERT OR DELETE OR UPDATE ON aegaeon.client_secrets FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: clients runtime_authority_notify_clients; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_clients AFTER INSERT OR DELETE OR UPDATE ON aegaeon.clients FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: configuration_versions runtime_authority_notify_configuration_versions; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_configuration_versions AFTER INSERT OR DELETE OR UPDATE ON aegaeon.configuration_versions FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: dynamic_client_registrations runtime_authority_notify_dynamic_client_registrations; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_dynamic_client_registrations AFTER INSERT OR DELETE OR UPDATE ON aegaeon.dynamic_client_registrations FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: environment_dcr_bearer_tokens runtime_authority_notify_environment_dcr_bearer_tokens; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_environment_dcr_bearer_tokens AFTER INSERT OR DELETE OR UPDATE ON aegaeon.environment_dcr_bearer_tokens FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: environment_key_stores runtime_authority_notify_environment_key_stores; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_environment_key_stores AFTER INSERT OR DELETE OR UPDATE ON aegaeon.environment_key_stores FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: environment_policies runtime_authority_notify_environment_policies; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_environment_policies AFTER INSERT OR DELETE OR UPDATE ON aegaeon.environment_policies FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: environment_scope_allowlist runtime_authority_notify_environment_scope_allowlist; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_environment_scope_allowlist AFTER INSERT OR DELETE OR UPDATE ON aegaeon.environment_scope_allowlist FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: environments runtime_authority_notify_environments; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_environments AFTER INSERT OR DELETE OR UPDATE ON aegaeon.environments FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: runtime_keys runtime_authority_notify_runtime_keys; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_runtime_keys AFTER INSERT OR DELETE OR UPDATE ON aegaeon.runtime_keys FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: teams runtime_authority_notify_teams; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_teams AFTER INSERT OR DELETE OR UPDATE ON aegaeon.teams FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: tenants runtime_authority_notify_tenants; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER runtime_authority_notify_tenants AFTER INSERT OR DELETE OR UPDATE ON aegaeon.tenants FOR EACH ROW EXECUTE FUNCTION aegaeon.notify_runtime_authority_changed();


--
-- Name: subject_ownership_adoptions subject_ownership_adoptions_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER subject_ownership_adoptions_immutable BEFORE DELETE OR UPDATE ON aegaeon.subject_ownership_adoptions FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: subject_ownership_adoptions subject_ownership_adoptions_no_truncate; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER subject_ownership_adoptions_no_truncate BEFORE TRUNCATE ON aegaeon.subject_ownership_adoptions FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_immutable; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER subject_ownership_namespaces_immutable BEFORE DELETE OR UPDATE ON aegaeon.subject_ownership_namespaces FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_no_truncate; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER subject_ownership_namespaces_no_truncate BEFORE TRUNCATE ON aegaeon.subject_ownership_namespaces FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();


--
-- Name: teams teams_lifecycle_invariants; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER teams_lifecycle_invariants BEFORE UPDATE OF status ON aegaeon.teams FOR EACH ROW EXECUTE FUNCTION aegaeon.enforce_team_lifecycle_invariants();


--
-- Name: tenants tenants_lifecycle_invariants; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER tenants_lifecycle_invariants BEFORE INSERT OR UPDATE OF team_id, status ON aegaeon.tenants FOR EACH ROW EXECUTE FUNCTION aegaeon.enforce_tenant_lifecycle_invariants();


--
-- Name: account_links account_links_connection_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_connection_environment_fkey FOREIGN KEY (connection_id, environment_id) REFERENCES aegaeon.connections(id, environment_id) ON DELETE RESTRICT;


--
-- Name: account_links account_links_connection_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES aegaeon.connections(id) ON DELETE RESTRICT;


--
-- Name: account_links account_links_end_user_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_end_user_environment_fkey FOREIGN KEY (end_user_id, environment_id) REFERENCES aegaeon.end_users(id, environment_id) ON DELETE RESTRICT;


--
-- Name: account_links account_links_end_user_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_end_user_id_fkey FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE RESTRICT;


--
-- Name: account_links account_links_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: account_links account_links_refresh_connection_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.account_links
    ADD CONSTRAINT account_links_refresh_connection_environment_fkey FOREIGN KEY (upstream_refresh_token_connection_id, environment_id) REFERENCES aegaeon.connections(id, environment_id) ON DELETE RESTRICT;


--
-- Name: api_key_capabilities api_key_capabilities_api_key_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_key_capabilities
    ADD CONSTRAINT api_key_capabilities_api_key_id_fkey FOREIGN KEY (api_key_id) REFERENCES aegaeon.api_keys(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_created_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_keys
    ADD CONSTRAINT api_keys_created_by_administrator_id_fkey FOREIGN KEY (created_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_revoked_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_keys
    ADD CONSTRAINT api_keys_revoked_by_administrator_id_fkey FOREIGN KEY (revoked_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: api_keys api_keys_service_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_keys
    ADD CONSTRAINT api_keys_service_administrator_id_fkey FOREIGN KEY (service_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE RESTRICT;


--
-- Name: api_keys api_keys_team_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.api_keys
    ADD CONSTRAINT api_keys_team_id_fkey FOREIGN KEY (team_id) REFERENCES aegaeon.teams(id) ON DELETE RESTRICT;


--
-- Name: application_authorizations application_authorizations_client_record_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.application_authorizations
    ADD CONSTRAINT application_authorizations_client_record_id_fkey FOREIGN KEY (client_record_id) REFERENCES aegaeon.clients(id) ON DELETE SET NULL;


--
-- Name: application_authorizations application_authorizations_end_user_record_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.application_authorizations
    ADD CONSTRAINT application_authorizations_end_user_record_id_fkey FOREIGN KEY (end_user_record_id) REFERENCES aegaeon.end_users(id) ON DELETE SET NULL;


--
-- Name: application_authorizations application_authorizations_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.application_authorizations
    ADD CONSTRAINT application_authorizations_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE CASCADE;


--
-- Name: authorization_consents authorization_consents_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_consents
    ADD CONSTRAINT authorization_consents_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE CASCADE;


--
-- Name: authorization_logins authorization_logins_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.authorization_logins
    ADD CONSTRAINT authorization_logins_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE CASCADE;


--
-- Name: client_secrets client_secrets_client_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.client_secrets
    ADD CONSTRAINT client_secrets_client_same_environment_fkey FOREIGN KEY (client_id, environment_id) REFERENCES aegaeon.clients(id, environment_id) ON DELETE RESTRICT;


--
-- Name: client_secrets client_secrets_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.client_secrets
    ADD CONSTRAINT client_secrets_configuration_version_same_environment_fkey FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: client_secrets client_secrets_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.client_secrets
    ADD CONSTRAINT client_secrets_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: clients clients_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.clients
    ADD CONSTRAINT clients_configuration_version_same_environment_fkey FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: clients clients_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.clients
    ADD CONSTRAINT clients_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: clients clients_oauth_profile_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.clients
    ADD CONSTRAINT clients_oauth_profile_same_environment_fkey FOREIGN KEY (oauth_profile_id, environment_id) REFERENCES aegaeon.oauth_profiles(id, environment_id) ON DELETE RESTRICT;


--
-- Name: configuration_versions configuration_versions_base_configuration_version_same_environm; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.configuration_versions
    ADD CONSTRAINT configuration_versions_base_configuration_version_same_environm FOREIGN KEY (environment_id, base_configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: configuration_versions configuration_versions_created_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.configuration_versions
    ADD CONSTRAINT configuration_versions_created_by_administrator_id_fkey FOREIGN KEY (created_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: configuration_versions configuration_versions_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.configuration_versions
    ADD CONSTRAINT configuration_versions_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: connections connections_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.connections
    ADD CONSTRAINT connections_configuration_version_same_environment_fkey FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: connections connections_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.connections
    ADD CONSTRAINT connections_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: connections connections_oauth_profile_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.connections
    ADD CONSTRAINT connections_oauth_profile_same_environment_fkey FOREIGN KEY (oauth_profile_id, environment_id) REFERENCES aegaeon.oauth_profiles(id, environment_id) ON DELETE RESTRICT;


--
-- Name: dynamic_client_registrations dynamic_client_registrations_client_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.dynamic_client_registrations
    ADD CONSTRAINT dynamic_client_registrations_client_same_environment_fkey FOREIGN KEY (client_id, environment_id) REFERENCES aegaeon.clients(id, environment_id) ON DELETE RESTRICT;


--
-- Name: dynamic_client_registrations dynamic_client_registrations_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.dynamic_client_registrations
    ADD CONSTRAINT dynamic_client_registrations_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: end_user_identity_owners end_user_identity_owners_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_identity_owners
    ADD CONSTRAINT end_user_identity_owners_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT;


--
-- Name: end_user_password_credentials end_user_password_credentials_created_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_password_credentials
    ADD CONSTRAINT end_user_password_credentials_created_by_administrator_id_fkey FOREIGN KEY (created_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: end_user_password_credentials end_user_password_credentials_end_user_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_password_credentials
    ADD CONSTRAINT end_user_password_credentials_end_user_id_fkey FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE RESTRICT;


--
-- Name: end_user_password_credentials end_user_password_credentials_revoked_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_password_credentials
    ADD CONSTRAINT end_user_password_credentials_revoked_by_administrator_id_fkey FOREIGN KEY (revoked_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: end_user_profiles end_user_profiles_end_user_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_profiles
    ADD CONSTRAINT end_user_profiles_end_user_id_fkey FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE CASCADE;


--
-- Name: end_user_recovery_tokens end_user_recovery_tokens_created_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_recovery_tokens
    ADD CONSTRAINT end_user_recovery_tokens_created_by_administrator_id_fkey FOREIGN KEY (created_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: end_user_recovery_tokens end_user_recovery_tokens_end_user_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_recovery_tokens
    ADD CONSTRAINT end_user_recovery_tokens_end_user_id_fkey FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE RESTRICT;


--
-- Name: end_user_recovery_tokens end_user_recovery_tokens_revoked_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_recovery_tokens
    ADD CONSTRAINT end_user_recovery_tokens_revoked_by_administrator_id_fkey FOREIGN KEY (revoked_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: end_user_subject_reservations end_user_subject_reservations_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_subject_reservations
    ADD CONSTRAINT end_user_subject_reservations_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT;


--
-- Name: end_users end_users_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_users
    ADD CONSTRAINT end_users_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environment_dcr_bearer_tokens environment_dcr_bearer_tokens_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_dcr_bearer_tokens
    ADD CONSTRAINT environment_dcr_bearer_tokens_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environment_key_stores environment_key_stores_configuration_version_same_environment_f; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_key_stores
    ADD CONSTRAINT environment_key_stores_configuration_version_same_environment_f FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: environment_key_stores environment_key_stores_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_key_stores
    ADD CONSTRAINT environment_key_stores_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environment_policies environment_policies_configuration_version_same_environment_fke; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_policies
    ADD CONSTRAINT environment_policies_configuration_version_same_environment_fke FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: environment_policies environment_policies_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_policies
    ADD CONSTRAINT environment_policies_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environment_revoked_client_secrets environment_revoked_client_sec_revoked_by_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_revoked_client_secrets
    ADD CONSTRAINT environment_revoked_client_sec_revoked_by_administrator_id_fkey FOREIGN KEY (revoked_by_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE SET NULL;


--
-- Name: environment_revoked_client_secrets environment_revoked_client_secrets_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_revoked_client_secrets
    ADD CONSTRAINT environment_revoked_client_secrets_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environment_revoked_client_secrets environment_revoked_client_secrets_secret_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_revoked_client_secrets
    ADD CONSTRAINT environment_revoked_client_secrets_secret_same_environment_fkey FOREIGN KEY (client_secret_id, environment_id) REFERENCES aegaeon.client_secrets(id, environment_id) ON DELETE RESTRICT;


--
-- Name: environment_scope_allowlist environment_scope_allowlist_configuration_version_same_environm; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_scope_allowlist
    ADD CONSTRAINT environment_scope_allowlist_configuration_version_same_environm FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: environment_scope_allowlist environment_scope_allowlist_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environment_scope_allowlist
    ADD CONSTRAINT environment_scope_allowlist_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: environments environments_active_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environments
    ADD CONSTRAINT environments_active_configuration_version_same_environment_fkey FOREIGN KEY (id, active_configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: environments environments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.environments
    ADD CONSTRAINT environments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT;


--
-- Name: federation_entity_cache federation_entity_cache_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_entity_cache
    ADD CONSTRAINT federation_entity_cache_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: federation_logout_recovery_incidents federation_logout_recovery_incidents_connection_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_logout_recovery_incidents
    ADD CONSTRAINT federation_logout_recovery_incidents_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES aegaeon.connections(id) ON DELETE RESTRICT;


--
-- Name: federation_logout_recovery_incidents federation_logout_recovery_incidents_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_logout_recovery_incidents
    ADD CONSTRAINT federation_logout_recovery_incidents_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: federation_logout_recovery_incidents federation_logout_recovery_incidents_team_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_logout_recovery_incidents
    ADD CONSTRAINT federation_logout_recovery_incidents_team_id_fkey FOREIGN KEY (team_id) REFERENCES aegaeon.teams(id) ON DELETE RESTRICT;


--
-- Name: federation_logout_recovery_incidents federation_logout_recovery_incidents_tenant_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_logout_recovery_incidents
    ADD CONSTRAINT federation_logout_recovery_incidents_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT;


--
-- Name: federation_trust_anchors federation_trust_anchors_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_trust_anchors
    ADD CONSTRAINT federation_trust_anchors_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: federation_trust_chains federation_trust_chains_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.federation_trust_chains
    ADD CONSTRAINT federation_trust_chains_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_actor_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_actor_administrator_id_fkey FOREIGN KEY (actor_administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_actor_team_membership_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_actor_team_membership_fkey FOREIGN KEY (team_id, actor_administrator_id) REFERENCES aegaeon.team_memberships(team_id, administrator_id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_end_user_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_end_user_environment_fkey FOREIGN KEY (end_user_id, environment_id) REFERENCES aegaeon.end_users(id, environment_id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_end_user_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_end_user_id_fkey FOREIGN KEY (end_user_id) REFERENCES aegaeon.end_users(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_environment_tenant_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_environment_tenant_fkey FOREIGN KEY (environment_id, tenant_id) REFERENCES aegaeon.environments(id, tenant_id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_team_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_team_id_fkey FOREIGN KEY (team_id) REFERENCES aegaeon.teams(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_tenant_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT;


--
-- Name: management_user_runtime_commands management_user_runtime_commands_tenant_team_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.management_user_runtime_commands
    ADD CONSTRAINT management_user_runtime_commands_tenant_team_fkey FOREIGN KEY (tenant_id, team_id) REFERENCES aegaeon.tenants(id, team_id) ON DELETE RESTRICT;


--
-- Name: oauth_profiles oauth_profiles_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.oauth_profiles
    ADD CONSTRAINT oauth_profiles_configuration_version_same_environment_fkey FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: oauth_profiles oauth_profiles_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.oauth_profiles
    ADD CONSTRAINT oauth_profiles_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: runtime_keys runtime_keys_configuration_version_same_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.runtime_keys
    ADD CONSTRAINT runtime_keys_configuration_version_same_environment_fkey FOREIGN KEY (environment_id, configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT;


--
-- Name: runtime_keys runtime_keys_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.runtime_keys
    ADD CONSTRAINT runtime_keys_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: subject_ownership_adoptions subject_ownership_adoptions_environment_id_kind_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_adoptions
    ADD CONSTRAINT subject_ownership_adoptions_environment_id_kind_fkey FOREIGN KEY (environment_id, kind) REFERENCES aegaeon.subject_ownership_namespaces(environment_id, origin) ON DELETE RESTRICT;


--
-- Name: subject_ownership_namespaces subject_ownership_namespaces_environment_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.subject_ownership_namespaces
    ADD CONSTRAINT subject_ownership_namespaces_environment_id_fkey FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT;


--
-- Name: end_user_subject_reservations subject_reservations_owner_environment_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.end_user_subject_reservations
    ADD CONSTRAINT subject_reservations_owner_environment_fkey FOREIGN KEY (owner_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id) ON DELETE RESTRICT;


--
-- Name: team_memberships team_memberships_administrator_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.team_memberships
    ADD CONSTRAINT team_memberships_administrator_id_fkey FOREIGN KEY (administrator_id) REFERENCES aegaeon.administrators(id) ON DELETE RESTRICT;


--
-- Name: team_memberships team_memberships_team_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.team_memberships
    ADD CONSTRAINT team_memberships_team_id_fkey FOREIGN KEY (team_id) REFERENCES aegaeon.teams(id) ON DELETE RESTRICT;


--
-- Name: tenants tenants_team_id_fkey; Type: FK CONSTRAINT; Schema: aegaeon; Owner: -
--

ALTER TABLE ONLY aegaeon.tenants
    ADD CONSTRAINT tenants_team_id_fkey FOREIGN KEY (team_id) REFERENCES aegaeon.teams(id) ON DELETE RESTRICT;


--
-- PostgreSQL database dump complete
--



CREATE FUNCTION aegaeon.subject_ownership_guard_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF current_user <> 'aegaeon_subject_owner' THEN
    RAISE EXCEPTION USING ERRCODE='42501',CONSTRAINT='subject_ownership_insert_authority',
      MESSAGE='permanent subject ownership requires an authorized owner entry';
  END IF;
  RETURN NEW;
END
$function$;
CREATE TRIGGER subject_ownership_namespaces_owner_insert BEFORE INSERT ON aegaeon.subject_ownership_namespaces
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER subject_ownership_adoptions_owner_insert BEFORE INSERT ON aegaeon.subject_ownership_adoptions
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER end_user_identity_owners_owner_insert BEFORE INSERT ON aegaeon.end_user_identity_owners
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER end_user_subject_reservations_owner_insert BEFORE INSERT ON aegaeon.end_user_subject_reservations
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();

-- Fixed permanent ownership authority; administrator provisioning precedes this schema.
GRANT USAGE ON SCHEMA aegaeon TO aegaeon_subject_owner, aegaeon_subject_maintenance;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
REVOKE ALL ON FUNCTION aegaeon.subject_ownership_guard_insert() FROM PUBLIC;
REVOKE ALL ON aegaeon.subject_ownership_namespaces, aegaeon.subject_ownership_adoptions,
  aegaeon.end_user_identity_owners, aegaeon.end_user_subject_reservations FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_ownership_immutable(),
  aegaeon.subject_ownership_guard_environment(), aegaeon.subject_ownership_guard_user() FROM PUBLIC;
GRANT SELECT, UPDATE ON aegaeon.environments, aegaeon.end_users, aegaeon.audit_events TO aegaeon_subject_owner;
GRANT INSERT ON aegaeon.audit_events TO aegaeon_subject_owner;
REVOKE ALL ON FUNCTION aegaeon.subject_history_check_maintenance_role(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_frame(bytea), aegaeon.subject_history_chain_start(text),
  aegaeon.subject_history_chain_row(bytea, bigint, text, text), aegaeon.subject_history_chain_end(bytea, bigint),
  aegaeon.subject_history_strict_json(json, integer), aegaeon.subject_history_require_keys(jsonb, text[]),
  aegaeon.subject_history_require_string(jsonb, text), aegaeon.subject_history_maintenance_actor() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_revision_relation(),aegaeon.subject_history_revision_rows(),aegaeon.subject_history_lock_revisions() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_check_runtime_role(text), aegaeon.subject_history_lock(),
  aegaeon.subject_history_physical_catalog(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_key(text[]), aegaeon.subject_history_source_rows(text),
  aegaeon.subject_history_content_id(text,text[],text[]), aegaeon.subject_history_fact(text,text,text,uuid,uuid,text),
  aegaeon.subject_history_finding(text,text,text,text,uuid,jsonb,jsonb,jsonb),
  aegaeon.subject_history_classify(text,text,text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_document_schema(text), aegaeon.subject_history_validate_shape(jsonb,jsonb,jsonb), aegaeon.subject_history_parse_document(bytea,text), aegaeon.subject_history_source_refs(jsonb,jsonb,text,boolean), aegaeon.subject_history_validate_manifest(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_inventory_stream(uuid,text,text,jsonb),
  aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.subject_history_preflight(text),aegaeon.subject_history_observed_physical() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.subject_history_identity_event(text), aegaeon.subject_history_validate_union(jsonb,jsonb), aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text) TO aegaeon_subject_maintenance;
GRANT SELECT ON aegaeon.tenants TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_identity_event(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_validate_union(jsonb,jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text) OWNER TO aegaeon_subject_owner;
REVOKE ALL ON FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) FROM PUBLIC;
ALTER FUNCTION aegaeon.validate_subject_ownership_namespace_v1(uuid) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_observed_physical() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_preflight(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_revision_relation() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_revision_rows() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_lock_revisions() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_inventory_stream(uuid,text,text,jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_document_schema(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_validate_shape(jsonb,jsonb,jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_parse_document(bytea,text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_source_refs(jsonb,jsonb,text,boolean) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_validate_manifest(jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_key(text[]) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_source_rows(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_content_id(text,text[],text[]) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_fact(text,text,text,uuid,uuid,text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_finding(text,text,text,text,uuid,jsonb,jsonb,jsonb) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_classify(text,text,text,uuid) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_check_runtime_role(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_lock() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_physical_catalog(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_ownership_valid_subject(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_ownership_immutable() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_ownership_guard_insert() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_ownership_guard_environment() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_ownership_guard_user() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_frame(bytea) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_chain_start(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_chain_row(bytea, bigint, text, text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_chain_end(bytea, bigint) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_strict_json(json, integer) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_require_keys(jsonb, text[]) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_require_string(jsonb, text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_check_maintenance_role(text) OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.subject_history_maintenance_actor() OWNER TO aegaeon_subject_owner;
ALTER TABLE aegaeon.subject_ownership_namespaces OWNER TO aegaeon_subject_owner;
ALTER TABLE aegaeon.subject_ownership_adoptions OWNER TO aegaeon_subject_owner;
ALTER TABLE aegaeon.end_user_identity_owners OWNER TO aegaeon_subject_owner;
ALTER TABLE aegaeon.end_user_subject_reservations OWNER TO aegaeon_subject_owner;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
DO $partition_lock_privileges$
DECLARE partition_row record;
BEGIN
  FOR partition_row IN SELECT n.nspname,c.relname FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE t.level>0 ORDER BY c.oid LOOP
    EXECUTE pg_catalog.format('GRANT SELECT, UPDATE ON TABLE %I.%I TO aegaeon_subject_owner',partition_row.nspname,partition_row.relname);
  END LOOP;
END
$partition_lock_privileges$;
DO $revision_permissions$
DECLARE item record;
BEGIN
  FOR item IN SELECT n.nspname,c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon') AND c.relkind='r' LOOP
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO aegaeon_subject_owner',item.nspname);
    EXECUTE pg_catalog.format('GRANT SELECT,UPDATE ON TABLE %I.%I TO aegaeon_subject_owner',item.nspname,item.relname);
  END LOOP;
END
$revision_permissions$;
