-- Operator-assisted repair; see docs/operations/configuration-membership-recovery.md.
-- Required psql variables: environment_id, from_version, to_version, client_ids,
-- profile_ids, connection_ids (UUID arrays), request_id and reason.
-- Default execution rolls back. No historical row is selected automatically.
\set ON_ERROR_STOP on
\if :{?apply}
\else
  \set apply false
\endif

BEGIN;
SET LOCAL search_path = pg_catalog;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TEMP TABLE recovery_input ON COMMIT DROP AS
SELECT :'environment_id'::uuid AS environment_id,
       :'from_version'::uuid AS from_version,
       :'to_version'::uuid AS to_version,
       :'request_id'::text AS request_id,
       :'reason'::text AS reason;
CREATE TEMP TABLE recovery_members (
    kind text NOT NULL, id uuid NOT NULL, PRIMARY KEY (kind, id)
) ON COMMIT DROP;
INSERT INTO recovery_members
SELECT 'clients', unnest(:'client_ids'::uuid[])
UNION ALL SELECT 'oauth_profiles', unnest(:'profile_ids'::uuid[])
UNION ALL SELECT 'connections', unnest(:'connection_ids'::uuid[]);

DO $$
DECLARE input record;
BEGIN
  SELECT * INTO STRICT input FROM pg_temp.recovery_input;
  IF btrim(input.request_id) = '' OR btrim(input.reason) = ''
     OR length(input.request_id) > 128 OR length(input.reason) > 1000
     OR NOT EXISTS (SELECT 1 FROM pg_temp.recovery_members) THEN
    RAISE EXCEPTION 'explicit members, request ID and reason are required';
  END IF;
  -- All target-environment writers must already be quiesced by the operator.
  -- Lock order agrees with configuration activation: environment, then members.
  PERFORM 1 FROM aegaeon.environments
    WHERE id = input.environment_id AND status = 'ACTIVE'
      AND active_configuration_version_id = input.to_version FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'environment or expected active version mismatch';
  END IF;
  PERFORM 1 FROM aegaeon.configuration_versions
    WHERE id = input.from_version AND environment_id = input.environment_id
      AND status = 'ARCHIVED' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'source must be an archived version of this environment'; END IF;
  PERFORM 1 FROM aegaeon.configuration_versions
    WHERE id = input.to_version AND environment_id = input.environment_id
      AND status = 'ACTIVE' FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'target must be the active version of this environment'; END IF;
  PERFORM 1 FROM aegaeon.clients WHERE environment_id = input.environment_id ORDER BY id FOR UPDATE;
  PERFORM 1 FROM aegaeon.oauth_profiles WHERE environment_id = input.environment_id ORDER BY id FOR UPDATE;
  PERFORM 1 FROM aegaeon.connections WHERE environment_id = input.environment_id ORDER BY id FOR UPDATE;
  PERFORM 1 FROM aegaeon.client_secrets WHERE environment_id = input.environment_id ORDER BY id FOR UPDATE;
  PERFORM 1 FROM aegaeon.runtime_keys WHERE environment_id = input.environment_id ORDER BY id FOR UPDATE;
END $$;

-- Keep full row images inside the transaction only. Never print these images:
-- they can contain credential hashes, encrypted secrets and provider handles.
CREATE TEMP VIEW recovery_current AS
SELECT 'clients'::text AS kind, c.id, to_jsonb(c) AS payload FROM aegaeon.clients c
  WHERE environment_id = (SELECT environment_id FROM pg_temp.recovery_input)
UNION ALL SELECT 'oauth_profiles', p.id, to_jsonb(p) FROM aegaeon.oauth_profiles p
  WHERE environment_id = (SELECT environment_id FROM pg_temp.recovery_input)
UNION ALL SELECT 'connections', c.id, to_jsonb(c) FROM aegaeon.connections c
  WHERE environment_id = (SELECT environment_id FROM pg_temp.recovery_input)
UNION ALL SELECT 'client_secrets', s.id, to_jsonb(s) FROM aegaeon.client_secrets s
  WHERE environment_id = (SELECT environment_id FROM pg_temp.recovery_input)
UNION ALL SELECT 'runtime_keys', k.id, to_jsonb(k) FROM aegaeon.runtime_keys k
  WHERE environment_id = (SELECT environment_id FROM pg_temp.recovery_input);
CREATE TEMP TABLE recovery_before ON COMMIT DROP AS SELECT * FROM recovery_current;

DO $$
DECLARE input record;
BEGIN
  SELECT * INTO STRICT input FROM pg_temp.recovery_input;
  IF EXISTS (
    SELECT 1 FROM pg_temp.recovery_members m
    LEFT JOIN pg_temp.recovery_before b USING (kind, id)
    WHERE b.id IS NULL
       OR b.payload->>'configuration_version_id' <> input.from_version::text
       OR NOT (b.payload->>'status' = 'ACTIVE'
          OR (m.kind = 'connections' AND b.payload->>'status' = 'DISABLED'))
  ) THEN RAISE EXCEPTION 'member missing, wrong source, or lifecycle state is not eligible'; END IF;
  IF EXISTS (
    SELECT 1 FROM pg_temp.recovery_members m
    JOIN pg_temp.recovery_before b USING (kind, id)
    LEFT JOIN aegaeon.oauth_profiles p ON p.id = (b.payload->>'oauth_profile_id')::uuid
    WHERE m.kind IN ('clients', 'connections') AND b.payload->>'oauth_profile_id' IS NOT NULL
      AND (p.id IS NULL OR p.environment_id <> input.environment_id OR p.status <> 'ACTIVE'
        OR (p.configuration_version_id <> input.to_version AND NOT EXISTS (
          SELECT 1 FROM pg_temp.recovery_members selected
          WHERE selected.kind = 'oauth_profiles' AND selected.id = p.id)))
  ) THEN RAISE EXCEPTION 'referenced profile must already be current or included in the approved set'; END IF;
END $$;

UPDATE aegaeon.clients AS target SET configuration_version_id = i.to_version
FROM recovery_input i WHERE target.environment_id = i.environment_id
  AND target.configuration_version_id = i.from_version
  AND target.id IN (SELECT id FROM recovery_members WHERE kind = 'clients');
UPDATE aegaeon.oauth_profiles AS target SET configuration_version_id = i.to_version
FROM recovery_input i WHERE target.environment_id = i.environment_id
  AND target.configuration_version_id = i.from_version
  AND target.id IN (SELECT id FROM recovery_members WHERE kind = 'oauth_profiles');
UPDATE aegaeon.connections AS target SET configuration_version_id = i.to_version
FROM recovery_input i WHERE target.environment_id = i.environment_id
  AND target.configuration_version_id = i.from_version
  AND target.id IN (SELECT id FROM recovery_members WHERE kind = 'connections');

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM (
      SELECT b.kind, b.id, CASE WHEN m.id IS NULL THEN b.payload
        ELSE b.payload || jsonb_build_object('configuration_version_id', i.to_version) END AS payload
      FROM pg_temp.recovery_before b CROSS JOIN pg_temp.recovery_input i
      LEFT JOIN pg_temp.recovery_members m ON m.kind = b.kind AND m.id = b.id
    ) expected FULL JOIN pg_temp.recovery_current actual USING (kind, id)
    WHERE expected.payload IS DISTINCT FROM actual.payload
  ) THEN RAISE EXCEPTION 'row count or fields changed beyond approved memberships'; END IF;
END $$;

INSERT INTO aegaeon.audit_events (
  team_id, tenant_id, environment_id, event_type, category, outcome, severity,
  occurred_at, actor_type, actor_id, target_type, target_id, request_id,
  from_configuration_version_id, to_configuration_version_id, data
)
SELECT t.team_id, e.tenant_id, e.id, 'CONFIGURATION_MEMBERSHIP_RECOVERED',
  'CONTROL_PLANE', 'SUCCESS', 'WARNING', now(), 'DATABASE_OPERATOR', session_user,
  'ENVIRONMENT', e.id::text, i.request_id, i.from_version, i.to_version,
  jsonb_build_object('reason', i.reason, 'members',
    (SELECT jsonb_agg(to_jsonb(m) ORDER BY kind, id) FROM recovery_members m))
FROM recovery_input i JOIN aegaeon.environments e ON e.id = i.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id;

-- Safe transcript: identifiers and counts, no credential or row payloads.
SELECT kind, count(*) AS selected_members FROM recovery_members GROUP BY kind ORDER BY kind;
SELECT environment_id, from_version, to_version, request_id FROM recovery_input;
\if :apply
  COMMIT;
\else
  ROLLBACK;
\endif
