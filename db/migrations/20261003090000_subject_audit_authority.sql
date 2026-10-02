-- Forward correction of audit-history authority. Preserve existing ownership/ACLs.
-- Privileged installers must stop and drain serving runtimes before applying.
-- Unsafe grants are refused by preflight; remediation is an administrator action.

DO $installation$
BEGIN
  IF (SELECT count(*) FROM pg_catalog.pg_roles
      WHERE rolname IN ('aegaeon_subject_owner','aegaeon_subject_maintenance')
        AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))<>2
      OR EXISTS (SELECT FROM pg_catalog.pg_auth_members
        WHERE member IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole)) THEN
    RAISE EXCEPTION 'subject authority roles require checked administrator provisioning';
  END IF;
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; administrator remediation required';
  END IF;
END
$installation$;
-- The provisioned migration login is SET-only, never an inherited runtime owner.
-- Atlas runs this file transactionally; no temporary grant survives a failure.
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
-- Atlas writes revision progress between statements. Restore the migration
-- role inside this single statement before Atlas performs its next write.
DO $replacement$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_check_runtime_role(runtime_name text) RETURNS void
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
  -- Relation OIDs include the parent, leaves and subpartitions in every schema.
  -- INSERT and SELECT are legitimate runtime audit operations; mutation is not.
  FOR relation_row IN SELECT c.oid,c.relowner
      FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass) t
      JOIN pg_catalog.pg_class c ON c.oid=t.relid LOOP
    IF pg_catalog.pg_has_role(runtime_id,relation_row.relowner,'USAGE')
       OR pg_catalog.pg_has_role(runtime_id,relation_row.relowner,'SET')
       OR pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'UPDATE,DELETE,TRUNCATE,TRIGGER')
       OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'UPDATE') THEN
      RAISE EXCEPTION 'subject runtime can rewrite protected audit history';
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
$definition$;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_check_maintenance_role(actor_name text) RETURNS void
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
        WHERE (n.nspname='aegaeon' AND c.relname IN ('environments','end_users','tenants','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations'))
          OR c.oid IN (SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass))
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
$definition$;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_inventory_stream(target_environment uuid, deployment_name text, runtime_name text, tool_identity jsonb)
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
    'schema_revision','20261003090000','schema_sha256',physical_contract_hash,'catalog_sha256',catalog_hash)||tool_identity;
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
$definition$;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_preflight(runtime_name text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE expected jsonb := $physical${"columns":[{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_identity_owners","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":"C"},{"name":"owner_id","type":"uuid","default":null,"not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"end_user_subject_reservations","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"end_users","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"end_users","collation":null},{"name":"subject","type":"text","default":null,"not_null":true,"relation":"end_users","collation":"C"},{"name":"email","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"status","type":"aegaeon.end_user_status","default":"'INVITED'::aegaeon.end_user_status","not_null":true,"relation":"end_users","collation":null},{"name":"blocked_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"end_users","collation":null},{"name":"blocked_reason","type":"text","default":null,"not_null":false,"relation":"end_users","collation":"default"},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"end_users","collation":null},{"name":"id","type":"uuid","default":"gen_random_uuid()","not_null":true,"relation":"environments","collation":null},{"name":"tenant_id","type":"uuid","default":null,"not_null":true,"relation":"environments","collation":null},{"name":"name","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"slug","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"environments","collation":"default"},{"name":"issuer_url","type":"text","default":"('https://'::text || issuer_host)","not_null":false,"relation":"environments","collation":"default"},{"name":"active_configuration_version_id","type":"uuid","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"status","type":"aegaeon.environment_status","default":"'ACTIVE'::aegaeon.environment_status","not_null":true,"relation":"environments","collation":null},{"name":"created_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"updated_at","type":"timestamp with time zone","default":"now()","not_null":true,"relation":"environments","collation":null},{"name":"deleted_at","type":"timestamp with time zone","default":null,"not_null":false,"relation":"environments","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"kind","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_adoptions","collation":null},{"name":"session_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"effective_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"definer_actor","type":"text","default":null,"not_null":true,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"maintenance_reference","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"manifest_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"inventory_sha256","type":"text","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":"default"},{"name":"receipt_data","type":"jsonb","default":null,"not_null":false,"relation":"subject_ownership_adoptions","collation":null},{"name":"environment_id","type":"uuid","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"issuer_host","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"origin","type":"text","default":null,"not_null":true,"relation":"subject_ownership_namespaces","collation":"default"},{"name":"contract_version","type":"integer","default":"1","not_null":true,"relation":"subject_ownership_namespaces","collation":null},{"name":"recorded_at","type":"timestamp with time zone","default":"clock_timestamp()","not_null":true,"relation":"subject_ownership_namespaces","collation":null}],"triggers":[{"name":"end_user_identity_owners_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null},{"name":"end_user_identity_owners_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_identity_owners","arguments":"","qualifier":null},{"relation":"end_user_identity_owners","name":"end_user_identity_owners_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"end_user_subject_reservations_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null},{"name":"end_user_subject_reservations_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"end_user_subject_reservations","arguments":"","qualifier":null},{"relation":"end_user_subject_reservations","name":"end_user_subject_reservations_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"end_users_subject_ownership","type":23,"enabled":"O","function":"subject_ownership_guard_user","relation":"end_users","arguments":"","qualifier":null},{"name":"environments_lifecycle_invariants","type":23,"enabled":"O","function":"enforce_environment_lifecycle_invariants","relation":"environments","arguments":"","qualifier":null},{"name":"environments_subject_namespace_immutable","type":19,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null},{"name":"environments_subject_namespace_initialize","type":5,"enabled":"O","function":"subject_ownership_guard_environment","relation":"environments","arguments":"","qualifier":null},{"name":"runtime_authority_notify_environments","type":29,"enabled":"O","function":"notify_runtime_authority_changed","relation":"environments","arguments":"","qualifier":null},{"name":"subject_ownership_adoptions_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null},{"name":"subject_ownership_adoptions_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_adoptions","arguments":"","qualifier":null},{"relation":"subject_ownership_adoptions","name":"subject_ownership_adoptions_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null},{"name":"subject_ownership_namespaces_immutable","type":27,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null},{"name":"subject_ownership_namespaces_no_truncate","type":34,"enabled":"O","function":"subject_ownership_immutable","relation":"subject_ownership_namespaces","arguments":"","qualifier":null},{"relation":"subject_ownership_namespaces","name":"subject_ownership_namespaces_owner_insert","type":7,"function":"subject_ownership_guard_insert","enabled":"O","arguments":"","qualifier":null}],"constraints":[{"name":"end_user_identity_owners_environment_id_fkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_identity_owners_environment_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_identity_owners_owner_id_environment_id_key","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"UNIQUE (owner_id, environment_id)"},{"name":"end_user_identity_owners_owner_id_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_identity_owners_pkey","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"PRIMARY KEY (owner_id)"},{"name":"end_user_identity_owners_recorded_at_not_null","deferred":false,"relation":"end_user_identity_owners","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_subject_reservations_environment_id_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.subject_ownership_namespaces(environment_id) ON DELETE RESTRICT"},{"name":"end_user_subject_reservations_environment_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_user_subject_reservations_owner_id_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL owner_id"},{"name":"end_user_subject_reservations_pkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id, subject)"},{"name":"end_user_subject_reservations_recorded_at_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"end_user_subject_reservations_subject_check","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_user_subject_reservations_subject_not_null","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"subject_reservations_owner_environment_fkey","deferred":false,"relation":"end_user_subject_reservations","validated":true,"deferrable":false,"definition":"FOREIGN KEY (owner_id, environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id, environment_id) ON DELETE RESTRICT"},{"name":"end_users_created_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"end_users_email_lowercase","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (((email IS NULL) OR (email = lower(email))))"},{"name":"end_users_environment_id_fkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"end_users_environment_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"end_users_id_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"end_users_pkey","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"end_users_status_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"end_users_subject_format","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"CHECK (aegaeon.subject_ownership_valid_subject(subject))"},{"name":"end_users_subject_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL subject"},{"name":"end_users_updated_at_not_null","deferred":false,"relation":"end_users","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"environments_active_configuration_version_same_environment_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (id, active_configuration_version_id) REFERENCES aegaeon.configuration_versions(environment_id, id) ON DELETE RESTRICT"},{"name":"environments_created_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL created_at"},{"name":"environments_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL id"},{"name":"environments_issuer_host_check","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((issuer_host = lower(issuer_host)) AND (POSITION(('://'::text) IN (issuer_host)) = 0) AND (POSITION(('/'::text) IN (issuer_host)) = 0) AND (POSITION(('?'::text) IN (issuer_host)) = 0) AND (POSITION(('#'::text) IN (issuer_host)) = 0)))"},{"name":"environments_issuer_host_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"environments_name_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL name"},{"name":"environments_pkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"PRIMARY KEY (id)"},{"name":"environments_slug_dns_label","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"CHECK (((slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'::text) AND (slug = lower(slug))))"},{"name":"environments_slug_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL slug"},{"name":"environments_status_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL status"},{"name":"environments_tenant_id_fkey","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"FOREIGN KEY (tenant_id) REFERENCES aegaeon.tenants(id) ON DELETE RESTRICT"},{"name":"environments_tenant_id_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL tenant_id"},{"name":"environments_updated_at_not_null","deferred":false,"relation":"environments","validated":true,"deferrable":false,"definition":"NOT NULL updated_at"},{"name":"subject_ownership_adoptions_contract_version_check","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_adoptions_contract_version_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_adoptions_definer_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL definer_actor"},{"name":"subject_ownership_adoptions_effective_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL effective_actor"},{"name":"subject_ownership_adoptions_environment_id_kind_fkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id, kind) REFERENCES aegaeon.subject_ownership_namespaces(environment_id, origin) ON DELETE RESTRICT"},{"name":"subject_ownership_adoptions_environment_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_adoptions_kind_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL kind"},{"name":"subject_ownership_adoptions_pkey","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_adoptions_receipt_id_key","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"UNIQUE (receipt_id)"},{"name":"subject_ownership_adoptions_receipt_id_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL receipt_id"},{"name":"subject_ownership_adoptions_recorded_at_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"},{"name":"subject_ownership_adoptions_session_actor_not_null","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"NOT NULL session_actor"},{"name":"subject_ownership_adoptions_shape","deferred":false,"relation":"subject_ownership_adoptions","validated":true,"deferrable":false,"definition":"CHECK ((((kind = 'fresh'::text) AND (maintenance_reference IS NULL) AND (manifest_sha256 IS NULL) AND (inventory_sha256 IS NULL) AND (receipt_data IS NULL)) OR ((kind = 'legacy'::text) AND (maintenance_reference IS NOT NULL) AND (manifest_sha256 IS NOT NULL) AND (inventory_sha256 IS NOT NULL) AND (manifest_sha256 ~ '^[0-9a-f]{64}$'::text) AND (inventory_sha256 ~ '^[0-9a-f]{64}$'::text) AND (receipt_data IS NOT NULL))))"},{"name":"subject_ownership_namespaces_contract_version_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((contract_version = 1))"},{"name":"subject_ownership_namespaces_contract_version_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL contract_version"},{"name":"subject_ownership_namespaces_environment_id_fkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"FOREIGN KEY (environment_id) REFERENCES aegaeon.environments(id) ON DELETE RESTRICT"},{"name":"subject_ownership_namespaces_environment_id_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL environment_id"},{"name":"subject_ownership_namespaces_environment_id_origin_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (environment_id, origin)"},{"name":"subject_ownership_namespaces_issuer_host_key","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"UNIQUE (issuer_host)"},{"name":"subject_ownership_namespaces_issuer_host_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL issuer_host"},{"name":"subject_ownership_namespaces_origin_check","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"CHECK ((origin = ANY (ARRAY['legacy'::text, 'fresh'::text])))"},{"name":"subject_ownership_namespaces_origin_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL origin"},{"name":"subject_ownership_namespaces_pkey","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"PRIMARY KEY (environment_id)"},{"name":"subject_ownership_namespaces_recorded_at_not_null","deferred":false,"relation":"subject_ownership_namespaces","validated":true,"deferrable":false,"definition":"NOT NULL recorded_at"}]}$physical$::jsonb;
  expected_functions jsonb := $functions$[{"signature":"aegaeon.subject_ownership_valid_subject(text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"fc9882541afc9a780cb6caf80c97d96fe8be21e62568205f8e7ef7be2b349eb6","settings":["search_path=pg_catalog, pg_temp"],"result":"boolean","defaults":null},{"signature":"aegaeon.subject_ownership_guard_insert()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"52b9475146e50d85310a14c71ead5c119d0b6b202f8bb521928c36c46739497f","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_immutable()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"c365d747fb17ea03ac06aa4612a993663f3dbf74c6fb47240fcdc856d159d9d2","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_guard_environment()","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"6406ec1158669d7225bb0c5e09595ab2517e849df4cbf892c652628e46cb2d58","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_ownership_guard_user()","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"9614948221b7e5aa281211f40a79a7536c465ba5d5fa6dd091eb4fb29668c34d","settings":["search_path=pg_catalog, pg_temp"],"result":"trigger","defaults":null},{"signature":"aegaeon.subject_history_frame(bytea)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"73af3455a9d9ed6d84a6b2d177850c382d37cc03538db945d99ed4e50c6536c5","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_start(text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"6a89cf6cfeaf7b67228160c980a685d2340106c53c81d5d282cc68f7a8d30444","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_row(bytea,bigint,text,text)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"995e91e793b4bb0b8441035c374ae62c48afd83b1fc79f4731b976377d441599","settings":["search_path=pg_catalog, pg_temp"],"result":"bytea","defaults":null},{"signature":"aegaeon.subject_history_chain_end(bytea,bigint)","language":"sql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"00c46633113a05cbd996b6bc36d9fb55874d2c964a4ca1675188756bc5067290","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_strict_json(json,integer)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"de16f880ea0c9ff4ef15676b05d2cb42b1fd86ef1c760563de9cbf323f0b38bd","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":"0"},{"signature":"aegaeon.subject_history_require_keys(jsonb,text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"5b3e7a080c1ad342fc617a2d11632708df22395107c024a631b22775ab998324","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_require_string(jsonb,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"d51baf6bfdfe6c472679c279e366dd8bbba63140694a9a8f7e7e8d39483d61d6","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_check_maintenance_role(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"ad22a5c97d4dc321fa33b6ef3a237a3e66867aadf4ec0ffc7e2f144e3083fe2d","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_maintenance_actor()","language":"plpgsql","security_definer":true,"volatility":"s","strict":false,"body_sha256":"8d62d6f1ac5189b60e6a0553e4e361109776468f33a8de1c6064e3bfe0e981ee","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_check_runtime_role(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"21ef610a3972f7a49d63e7e1163bb82c99d2e3d8c2f64e4ed0f5a3869bc543e8","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_lock()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"627ee964ca9d785f28708042e3aee5f60f08e702b30be583eb16d17c98460786","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_revision_relation()","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"d64c499c2301b4ba5c0d25a375434dbd0a4d6321e8db419d8ca7773e5f5575c4","settings":["search_path=pg_catalog, pg_temp"],"result":"regclass","defaults":null},{"signature":"aegaeon.subject_history_revision_rows()","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"1674cf69df8522d842fb678547ea047d64db68293a702421e42d44610a3bf73d","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_lock_revisions()","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"4504247c9f8d02f60f728d5a13778bc37c0f065e1949f8ee1cf24e4a1d3e28b3","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_physical_catalog(text)","language":"sql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"dab1b87fa17049d8d9cf2360ddc85e31743c43b117ddab3a574bace7b015e342","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_key(text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":true,"body_sha256":"8ae3364074e7f5b84b1f36e23fc893d5c55b64fb9db00d8ebce3fceb467dce39","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_source_rows(text)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"a0625351b63ad3180f2b0898f847ef5b30e4653548273174c2272f452c2f2567","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(collection_name text, row_key text, row_text text)","defaults":null},{"signature":"aegaeon.subject_history_content_id(text,text[],text[])","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"f857b4ccabedc2c61d12ab699db33a8d7bd24cb5c46c15a57e5fe75d731c9250","settings":["search_path=pg_catalog, pg_temp"],"result":"text","defaults":null},{"signature":"aegaeon.subject_history_fact(text,text,text,uuid,uuid,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"50c81e2960f390c6395fe4ff7c1eafd9e70d1a8c06703f52dc3e5d7c2963b072","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_finding(text,text,text,text,uuid,jsonb,jsonb,jsonb)","language":"sql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"5e48222af63e3b68f8c9889789b307ca9898ad44a34b3dd0f9521d457e24b42e","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_classify(text,text,text,uuid)","language":"plpgsql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"4234db1e406f61682c13c52bd27c5809d261a08fe19a92656f7d35ea6a421314","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(record_type text, payload jsonb)","defaults":null},{"signature":"aegaeon.subject_history_document_schema(text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"39cd34d015032e888a7ae344126f163f624b415bed7e1aa11107af3396d6f875","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_validate_shape(jsonb,jsonb,jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"1d4453458e87bed963c4d3519234082e48e4ba3a657b8a249a0e53306cb67a09","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_parse_document(bytea,text)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"b18bc5ce79110960ba66a2e5aca7f6c1707c82bb2c1bdbaa9cfb53c523884b16","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_source_refs(jsonb,jsonb,text,boolean)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"f67403f7dbc56971dbac94e03f488a3c480a43e9c17d1be31c614b7b514f357b","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_validate_manifest(jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"091c069b1d18676295e2f107c96512ed006e2f985886798bf6a62888e4dba071","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.subject_history_observed_physical()","language":"sql","security_definer":false,"volatility":"s","strict":false,"body_sha256":"3c4962a3121741e8da7f4b7346622ce78d0d7095ac5b9da4c5144c5c007d067d","settings":["search_path=pg_catalog, pg_temp"],"result":"jsonb","defaults":null},{"signature":"aegaeon.subject_history_inventory_stream(uuid,text,text,jsonb)","language":"plpgsql","security_definer":false,"volatility":"v","strict":false,"body_sha256":"492e346cf2a26b45ff29054d9883d6ec4e4aa276c6ea01fa2dd04ae608f1058f","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null},{"signature":"aegaeon.inventory_subject_ownership_history_v1(uuid,text,text,jsonb)","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"163a5a4186fb6931bfe5ad36b37b8b2009442665ad37700c43140e4a28aca6ed","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null},{"signature":"aegaeon.subject_history_identity_event(text)","language":"sql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"6089a7cc7506b6b595b0cc0dd16e9973b8207fe3bc98d325c61e2c9dcb2cf7ef","settings":["search_path=pg_catalog, pg_temp"],"result":"boolean","defaults":null},{"signature":"aegaeon.subject_history_validate_union(jsonb,jsonb)","language":"plpgsql","security_definer":false,"volatility":"i","strict":false,"body_sha256":"8483684ad930becb24f663ea50086cfc7c6249dc6d109ff0ac8858906d11d6f4","settings":["search_path=pg_catalog, pg_temp"],"result":"void","defaults":null},{"signature":"aegaeon.adopt_subject_ownership_history_v1(bytea,bytea,text,text)","language":"plpgsql","security_definer":true,"volatility":"v","strict":false,"body_sha256":"403dd259b7863e50b410efbcabf3baade2321926d6e64ae535bc20966dc642f0","settings":["datestyle=iso, ymd","extra_float_digits=3","intervalstyle=postgres","search_path=pg_catalog, pg_temp","timezone=utc"],"result":"TABLE(environment_id uuid, receipt_id uuid, manifest_sha256 text, inventory_sha256 text, session_actor text, effective_actor text, definer_actor text, owner_count bigint, reservation_count bigint)","defaults":null},{"signature":"aegaeon.validate_subject_ownership_namespace_v1(uuid)","language":"plpgsql","security_definer":true,"volatility":"s","strict":false,"body_sha256":"6edd9f6fe332c899235ccf1f8be4f8af146796ceb17719386d27252b99753c06","settings":["search_path=pg_catalog, pg_temp"],"result":"TABLE(record_type text, row_key text, payload text)","defaults":null}]$functions$::jsonb;
  expected_revisions jsonb := $revisions$[{"version":"20260803140000","description":"baseline","sha256_base64":"MiEiQpBNweRvDKhVVt17w7Td1YklwRIaQ6GXfRwCmjE="},{"version":"20260909070000","description":"authorization_consents","sha256_base64":"PEdKG9v67t73TfECEz8BkuHoh0DaH7/pS57dHwGWEWY="},{"version":"20260909090000","description":"authorization_logins","sha256_base64":"z9IBFYQfQuCGGm08Ndc50Q461gDjhRzOu3YJUQ98ij8="},{"version":"20260909120000","description":"token_exchange_policy","sha256_base64":"r6cY8qHe7i1SBvcCYCy5KX2WY/YHAQr3p04fLN7SZyo="},{"version":"20260911090000","description":"application_authorizations","sha256_base64":"X4s7SL8Qx+0r+dZtKEg3rSOsFikvh0zoyFuZsAE4Vn4="},{"version":"20260913090000","description":"application_authorization_identities","sha256_base64":"EVIREfQ3EgynjVT8qwujTqVIvaNzLfAUvyPYIxUBaL0="},{"version":"20260930090000","description":"client_credentials_policy","sha256_base64":"7hvvi5YVMmIdeLRyVJ4DZodwsU41SzCBxvBBybrguVg="},{"version":"20261002130000","description":"subject_ownership","sha256_base64":"GGNSKSoQtSPXzvYaerHFEh4k071HSvU8Ujx4+m+qUj8="},{"version":"20261003090000","description":"subject_audit_authority","sha256_base64":null}]$revisions$::jsonb;
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
$definition$;

RESET ROLE;
END
$replacement$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
