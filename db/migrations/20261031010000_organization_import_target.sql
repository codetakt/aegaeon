-- ORG-R17/R18/R19: private, read-only target dependency inspection.
-- No import, activation, credential transfer or raw maintenance SELECT grants.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT SELECT ON aegaeon.clients,aegaeon.administrators,aegaeon.team_memberships,aegaeon.teams TO aegaeon_subject_owner;
GRANT SELECT(end_user_id,status,password_hash) ON aegaeon.end_user_password_credentials TO aegaeon_subject_owner;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE INDEX end_user_subject_reservations_owner_lookup ON aegaeon.end_user_subject_reservations(owner_id,environment_id,subject);
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_target_v1(
  scope_environment uuid, runtime_name text, collection text, lookup_keys jsonb
) RETURNS TABLE(row_key text, row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE schema_hash text;
BEGIN
  PERFORM aegaeon.subject_history_maintenance_actor();
  IF scope_environment IS NULL OR scope_environment='00000000-0000-0000-0000-000000000000'
    OR runtime_name IS NULL OR octet_length(runtime_name) NOT BETWEEN 1 AND 63
    OR collection IS NULL OR collection NOT IN ('catalog','namespace','environment_dependency','domain','owners','subject_history','identities','client_dependencies','operators','organizations','targets')
    OR lookup_keys IS NULL OR jsonb_typeof(lookup_keys)<>'array'
    OR pg_catalog.pg_is_in_recovery()
    OR current_setting('transaction_isolation')<>'repeatable read'
    OR current_setting('transaction_read_only')<>'on' THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid import target request';
  END IF;
  IF jsonb_array_length(lookup_keys)>10
    OR EXISTS(SELECT FROM jsonb_array_elements(lookup_keys) k WHERE jsonb_typeof(k)<>'string' OR octet_length(k#>>'{}') NOT BETWEEN 1 AND 4096)
    OR (SELECT count(*) FROM jsonb_array_elements(lookup_keys))<>(SELECT count(DISTINCT k) FROM jsonb_array_elements(lookup_keys) k) THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid import target keys';
  END IF;
  IF collection IN ('catalog','namespace') THEN
    IF jsonb_array_length(lookup_keys)<>0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unexpected catalog keys'; END IF;
    schema_hash:=aegaeon.subject_history_preflight(runtime_name);
    IF collection='catalog' THEN
      RETURN QUERY SELECT c.row_key,c.row_text FROM aegaeon.subject_history_physical_catalog(runtime_name) c
        WHERE c.row_key LIKE 'function:%' OR c.row_key LIKE 'atlas_revision:%'
          OR (c.row_key LIKE 'role:%' AND c.row_text::jsonb->>'rolname'='aegaeon_subject_owner');
    ELSE
      RETURN QUERY SELECT n.environment_id::text,jsonb_build_object('environment_id',n.environment_id,'issuer_host',n.issuer_host,'origin',n.origin,'contract_version',n.contract_version,'receipt_id',a.receipt_id,'schema_sha256',schema_hash)::text
        FROM aegaeon.subject_ownership_namespaces n JOIN aegaeon.subject_ownership_adoptions a
          ON a.environment_id=n.environment_id AND a.kind=n.origin
        WHERE n.environment_id=scope_environment AND n.contract_version=1;
    END IF;
    RETURN;
  END IF;
  IF jsonb_array_length(lookup_keys)=0 THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='missing target keys'; END IF;
  IF collection IN ('domain','environment_dependency','owners','identities','client_dependencies','operators','organizations') AND EXISTS(
    SELECT FROM jsonb_array_elements_text(lookup_keys) k WHERE k !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR k='00000000-0000-0000-0000-000000000000') THEN
    RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid target object key';
  END IF;
  RETURN QUERY WITH keys AS (SELECT k AS key, CASE WHEN collection IN ('domain','environment_dependency','owners','identities','client_dependencies','operators','organizations') THEN k::uuid ELSE NULL END AS id FROM jsonb_array_elements_text(lookup_keys) k), rows AS (
    SELECT e.id::text AS key,to_jsonb(v) AS data FROM aegaeon.environments e CROSS JOIN LATERAL (
      SELECT e.id,e.issuer_host,e.issuer_url,e.status,e.active_configuration_version_id,e.organization_identity_policy,e.organization_identity_policy_revision
    ) v WHERE collection='environment_dependency' AND e.id=scope_environment AND e.id IN (SELECT id FROM keys)
    UNION ALL SELECT d.id::text,to_jsonb(d) FROM aegaeon.authorization_domains d
      WHERE collection='domain' AND (d.id IN (SELECT id FROM keys) OR (d.environment_id=scope_environment AND d.is_default))
    UNION ALL SELECT o.owner_id::text,to_jsonb(o)||jsonb_build_object('history_count',(SELECT count(*) FROM aegaeon.end_user_subject_reservations r WHERE r.owner_id=o.owner_id),'current_identity_present',EXISTS(SELECT FROM aegaeon.end_users u WHERE u.id=o.owner_id))
      FROM aegaeon.end_user_identity_owners o WHERE collection='owners' AND o.owner_id IN (SELECT id FROM keys)
    UNION ALL SELECT r.subject,to_jsonb(r) FROM aegaeon.end_user_subject_reservations r
      WHERE collection='subject_history' AND r.environment_id=scope_environment AND r.subject COLLATE "C" IN (SELECT key COLLATE "C" FROM keys)
    UNION ALL SELECT u.id::text,to_jsonb(v)||jsonb_build_object('active_credentials',(SELECT count(*) FROM aegaeon.end_user_password_credentials p WHERE p.end_user_id=u.id AND p.status='ACTIVE'),
      'compatible_credentials',(SELECT count(*) FROM aegaeon.end_user_password_credentials p WHERE p.end_user_id=u.id AND p.status='ACTIVE' AND octet_length(p.password_hash)=97 AND p.password_hash ~ '^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]{21}[AQgw]\$[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$'))
      FROM aegaeon.end_users u CROSS JOIN LATERAL (
        SELECT u.id,u.environment_id,u.subject,u.status,u.created_at,u.updated_at,u.organization_identity_revision,u.organization_reauthentication_after
      ) v WHERE collection='identities' AND u.id IN (SELECT id FROM keys)
    UNION ALL SELECT c.id::text,to_jsonb(v) FROM aegaeon.clients c CROSS JOIN LATERAL (
      SELECT c.id,c.environment_id,c.configuration_version_id,c.client_identifier,c.client_type,c.status,c.deleted_at,c.allowed_grant_types,c.allowed_scopes,c.dpop_bound_access_tokens,c.token_endpoint_authentication_method
    ) v WHERE collection='client_dependencies' AND c.id IN (SELECT id FROM keys)
    UNION ALL SELECT a.id::text,jsonb_build_object('id',a.id,'human_member',a.status='ACTIVE' AND a.kind='HUMAN' AND t.status='ACTIVE' AND n.status='ACTIVE' AND e.status='ACTIVE')
      FROM aegaeon.administrators a JOIN aegaeon.team_memberships m ON m.administrator_id=a.id
      JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.tenants n ON n.team_id=t.id
      JOIN aegaeon.environments e ON e.tenant_id=n.id
      WHERE collection='operators' AND e.id=scope_environment AND a.id IN (SELECT id FROM keys)
    UNION ALL SELECT o.id::text,jsonb_build_object('id',o.id) FROM aegaeon.application_organizations o
      WHERE collection='organizations' AND o.id IN (SELECT id FROM keys)
    UNION ALL SELECT t.audience,jsonb_build_object('domain_id',t.domain_id) FROM aegaeon.authorization_domain_targets t
      WHERE collection='targets' AND t.environment_id=scope_environment AND t.audience COLLATE "C" IN (SELECT key COLLATE "C" FROM keys)
  ) SELECT r.key,CASE WHEN octet_length(r.data::text)<=262144 THEN r.data::text ELSE NULL END FROM rows r ORDER BY r.key COLLATE "C";
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_import_target_v1(uuid,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_target_v1(uuid,text,text,jsonb) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
