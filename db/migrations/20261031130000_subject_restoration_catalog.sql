-- Scoped snapshot history supplier physical authority.
-- ORG-G02 / ORG-P02, ORG-P13: compose the current signed prerequisite history.
-- Forward-only catalog replacement; all preceding migration bytes are retained.
-- Apply the complete stage while all readers/writers are stopped and drained.
-- ORG-R02 / ORG-G02 / ORG-P02, ORG-P13: include explicit domain operator grants.
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
CREATE OR REPLACE FUNCTION aegaeon.subject_history_physical_catalog(runtime_name text)
RETURNS TABLE(row_key text, row_text text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
 WITH protected_relations AS (
   SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','audit_events',
      'subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')
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
       FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee)) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname LIKE 'subject_ownership_%' OR p.proname IN ('restore_subject_history_page_v1','organization_creation_record_v1','organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','organization_snapshot_history_v1','organization_import_target_v1','organization_import_hold_guard','organization_import_operation_v1','organization_import_begin_v1','organization_import_row_v1','organization_import_finish_v1') OR p.proname IN ('inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1','validate_subject_ownership_namespace_v1'))
   UNION ALL SELECT 'role',r.oid::text,pg_catalog.to_jsonb(r) FROM pg_catalog.pg_roles r
   UNION ALL SELECT 'membership',m.roleid::text||':'||m.member::text||':'||m.grantor::text,pg_catalog.to_jsonb(m) FROM pg_catalog.pg_auth_members m
   UNION ALL SELECT 'parameter_acl',p.oid::text,pg_catalog.to_jsonb(p) FROM pg_catalog.pg_parameter_acl p
   UNION ALL SELECT 'atlas_revision',r.row_key,r.row_text::jsonb FROM aegaeon.subject_history_revision_rows() r
   UNION ALL SELECT 'runtime_role',runtime_name,pg_catalog.jsonb_build_object('runtime_role',runtime_name)
 ) SELECT kind||':'||key, value::text FROM rows ORDER BY kind COLLATE "C",key COLLATE "C"
$function$;
$definition$;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_observed_physical() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp
AS $function$
SELECT pg_catalog.jsonb_build_object(
'columns',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',a.attname,'type',pg_catalog.format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'collation',co.collname,'default',pg_catalog.pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname COLLATE "C",a.attnum) FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_catalog.pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',con.conname,'definition',pg_catalog.pg_get_constraintdef(con.oid,false),'validated',con.convalidated,'deferrable',con.condeferrable,'deferred',con.condeferred) ORDER BY c.relname COLLATE "C",con.conname COLLATE "C") FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid=con.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages')),
'triggers',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',t.tgname,'type',t.tgtype,'function',p.proname,'enabled',t.tgenabled,'arguments',pg_catalog.encode(t.tgargs,'hex'),'qualifier',pg_catalog.pg_get_expr(t.tgqual,t.tgrelid)) ORDER BY c.relname COLLATE "C",t.tgname COLLATE "C") FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='aegaeon' AND c.relname IN ('subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','end_users','end_user_password_credentials','end_user_profiles','environments','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') AND NOT t.tgisinternal),
'indexes',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('relation',c.relname,'name',ic.relname,'definition',pg_catalog.pg_get_indexdef(i.indexrelid),'unique',i.indisunique,'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'immediate',i.indimmediate) ORDER BY c.relname COLLATE "C",ic.relname COLLATE "C") FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_class ic ON ic.oid=i.indexrelid WHERE n.nspname='aegaeon' AND c.relname IN ('authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages'))
);
$function$;
$definition$;

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
  FOR relation_row IN SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='aegaeon' AND c.relname IN ('subject_history_restorations','subject_history_restoration_pages') LOOP
    IF pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
      OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
      RAISE EXCEPTION 'runtime has direct history restoration authority';
    END IF;
  END LOOP;
  IF pg_catalog.has_table_privilege(runtime_id,'aegaeon.organization_creation_receipts','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,MAINTAIN')
    OR pg_catalog.has_any_column_privilege(runtime_id,'aegaeon.organization_creation_receipts','INSERT,UPDATE,REFERENCES') THEN
    RAISE EXCEPTION 'runtime has direct creation receipt mutation authority';
  END IF;

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
      WHERE (n.nspname = 'aegaeon' AND c.relname IN ('environments', 'end_users','end_user_password_credentials','end_user_profiles',
        'subject_ownership_namespaces', 'subject_ownership_adoptions',
        'end_user_identity_owners', 'end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages'))
        OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
    IF pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'USAGE')
       OR pg_catalog.pg_has_role(runtime_id, relation_row.relowner, 'SET') THEN
      RAISE EXCEPTION 'subject runtime can assume ownership of a guarded table';
    END IF;
    IF pg_catalog.has_table_privilege(runtime_id, relation_row.oid, 'TRIGGER') THEN
      RAISE EXCEPTION 'subject runtime can install competing identity triggers';
    END IF;
    IF relation_row.relname NOT IN ('environments', 'end_users','end_user_password_credentials','end_user_profiles','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts')
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
        ('organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert',
         'inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1'))
      AND (pg_catalog.has_function_privilege(runtime_id, p.oid, 'EXECUTE')
        OR pg_catalog.pg_has_role(runtime_id,p.proowner,'USAGE') OR pg_catalog.pg_has_role(runtime_id,p.proowner,'SET'))) THEN
    RAISE EXCEPTION 'subject runtime can execute or own protected maintenance helpers';
  END IF;
  IF pg_catalog.has_table_privilege(runtime_id,'aegaeon.organization_identity_requests','UPDATE')
    OR EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid='aegaeon.organization_identity_requests'::regclass
      AND a.attnum>0 AND NOT a.attisdropped
      AND a.attname NOT IN ('state','result','delivery_revision','delivered_at','delivery_outcome','capability_hash')
      AND pg_catalog.has_column_privilege(runtime_id,a.attrelid,a.attnum,'UPDATE')) THEN
    RAISE EXCEPTION 'runtime can rewrite identity request bindings';
  END IF;
  -- History deletion and identity replacement are not runtime operations.
  FOR relation_row IN SELECT c.oid,c.relname FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='aegaeon' AND c.relname IN ('authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages') LOOP
    IF pg_catalog.has_table_privilege(runtime_id,relation_row.oid,'DELETE,TRUNCATE,REFERENCES')
       OR pg_catalog.has_any_column_privilege(runtime_id,relation_row.oid,'REFERENCES') THEN
      RAISE EXCEPTION 'organization runtime can delete or redefine authority history';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_attribute a WHERE a.attrelid=relation_row.oid
        AND a.attnum>0 AND NOT a.attisdropped
        AND a.attname<>ALL(CASE relation_row.relname
        WHEN 'organization_invitations' THEN ARRAY['state','revision','delivery_revision','delivered_at','capability_hash','accepted_challenge_id','result','delivery_outcome']::text[]
        WHEN 'organization_invitation_challenges' THEN ARRAY['delivery_revision','delivered_at','capability_hash','delivery_outcome']::text[]
        WHEN 'organization_identity_requests' THEN ARRAY['state','result','delivery_revision','delivered_at','capability_hash','delivery_outcome']::text[]
        WHEN 'organization_client_bindings' THEN ARRAY['active','revision','targets']::text[]
        WHEN 'organization_operator_grants' THEN ARRAY['active','revision','capabilities']::text[]
        WHEN 'organization_admin_access_grants' THEN ARRAY['active','revision','revocation_key','revocation_digest']::text[]
        WHEN 'authorization_domains' THEN ARRAY['name','is_default','enabled','revision','invitation_delivery','support_policy','support_policy_revision']::text[]
        WHEN 'authorization_domain_targets' THEN ARRAY['domain_id','management','introspection_clients']::text[]
        WHEN 'application_organizations' THEN ARRAY['state','revision','grant_generation']::text[]
        WHEN 'organization_role_definitions' THEN ARRAY['version','privileges','manages_members','assignable_roles']::text[]
        WHEN 'organization_memberships' THEN ARRAY['state','revision','grant_generation','roles']::text[]
        WHEN 'organization_authority_outbox' THEN ARRAY['delivered_at','attempts']::text[]
        ELSE ARRAY[]::text[] END)
        AND pg_catalog.has_column_privilege(runtime_id,relation_row.oid,a.attnum,'UPDATE')) THEN
      RAISE EXCEPTION 'organization runtime can replace identity or rewrite immutable records';
    END IF;
  END LOOP;
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
        WHERE (n.nspname='aegaeon' AND c.relname IN ('environments','end_users','end_user_password_credentials','end_user_profiles','tenants','subject_ownership_namespaces','subject_ownership_adoptions','end_user_identity_owners','end_user_subject_reservations','authorization_domains','authorization_domain_targets','application_organizations','organization_role_definitions','organization_memberships','organization_authority_events','organization_authority_outbox','organization_authority_receipts','organization_operator_grants','organization_client_bindings','organization_invitations','organization_invitation_challenges','organization_identity_requests','organization_admin_access_grants','organization_import_operations','organization_creation_receipts','subject_history_restorations','subject_history_restoration_pages'))
          OR c.oid IN (SELECT relid FROM pg_catalog.pg_partition_tree('aegaeon.audit_events'::regclass))
          OR (c.relname='atlas_schema_revisions' AND n.nspname IN ('public','aegaeon')) LOOP
        IF reachable.oid=relation_row.relowner OR pg_catalog.has_table_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR pg_catalog.has_any_column_privilege(reachable.oid,relation_row.oid,'SELECT,INSERT,UPDATE,REFERENCES') THEN
          RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor requires EXECUTE-only source authority';
        END IF;
      END LOOP;
      IF EXISTS (SELECT FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname IN
            ('organization_creation_record_v1','organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','organization_snapshot_history_v1','subject_ownership_guard_user','subject_ownership_guard_environment','subject_ownership_immutable','subject_ownership_guard_insert'))
          AND (pg_catalog.has_function_privilege(reachable.oid,p.oid,'EXECUTE')
            OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'USAGE') OR pg_catalog.pg_has_role(reachable.oid,p.proowner,'SET'))) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='maintenance actor can execute private authority helpers';
      END IF;
    END LOOP;
END
$function$;
$definition$;

EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.subject_history_lock() RETURNS void
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
  LOCK TABLE aegaeon.authorization_domains IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_operator_grants IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_client_bindings IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_invitations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_invitation_challenges IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.authorization_domain_targets IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.application_organizations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_role_definitions IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_memberships IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_events IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_outbox IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_authority_receipts IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.organization_creation_receipts IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_history_restorations IN SHARE ROW EXCLUSIVE MODE;
  LOCK TABLE aegaeon.subject_history_restoration_pages IN SHARE ROW EXCLUSIVE MODE;
  PERFORM aegaeon.subject_history_lock_revisions();
END
$function$;
$definition$;

RESET ROLE;
END
$replacement$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
