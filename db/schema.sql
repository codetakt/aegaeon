--
-- PostgreSQL database dump
--


-- Dumped from database version 18.1 (Debian 18.1-1.pgdg13+2)
-- Dumped by pg_dump version 18.1 (Debian 18.1-1.pgdg13+2)

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


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA aegaeon;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

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
-- Name: end_users; Type: TABLE; Schema: aegaeon; Owner: -
--

CREATE TABLE aegaeon.end_users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    environment_id uuid NOT NULL,
    subject text NOT NULL,
    email text,
    status aegaeon.end_user_status DEFAULT 'INVITED'::aegaeon.end_user_status NOT NULL,
    blocked_at timestamp with time zone,
    blocked_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT end_users_email_lowercase CHECK (((email IS NULL) OR (email = lower(email))))
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
-- Name: environments environments_lifecycle_invariants; Type: TRIGGER; Schema: aegaeon; Owner: -
--

CREATE TRIGGER environments_lifecycle_invariants BEFORE INSERT OR UPDATE OF tenant_id, status ON aegaeon.environments FOR EACH ROW EXECUTE FUNCTION aegaeon.enforce_environment_lifecycle_invariants();


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




--
-- Audit events are append-only. In production, the application connects via a
-- restricted DB role; this REVOKE is defense-in-depth against UPDATE/DELETE
-- through any default grants (tracked as security finding sec-M-7).
--

REVOKE UPDATE, DELETE ON aegaeon.audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE ON aegaeon.audit_events_default FROM PUBLIC;
