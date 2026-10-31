-- ORG-R18/R19: bounded current prepared-content inspection; no activation.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN RAISE EXCEPTION 'subject owner has preexisting schema CREATE'; END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_prepared_rows_v1(
 operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text,
 section_name text, after_key text, page_limit integer
) RETURNS TABLE(row_key text,row_data text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE statement text; receipt jsonb;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 IF operation_id IS NULL OR scope_environment IS NULL OR scope_domain IS NULL OR source_digest IS NULL
  OR section_name IS NULL OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 10 OR octet_length(after_key)>4096 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid prepared content inspection';
 END IF;
 receipt:=aegaeon.organization_import_operation_v1(operation_id,scope_environment,scope_domain,source_digest);
 IF receipt IS NULL OR NOT EXISTS(SELECT FROM aegaeon.authorization_domains d
   WHERE d.environment_id=scope_environment AND d.id=scope_domain AND d.import_operation_id=operation_id AND NOT d.enabled) THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='prepared inactive scope missing';
 END IF;
 CASE section_name
 WHEN 'domain' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,name,is_default,enabled,revision,invitation_delivery,support_policy,support_policy_revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2) v';
 WHEN 'targets' THEN statement := 'SELECT (audience)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,audience,management,introspection_clients FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'roles' THEN statement := 'SELECT (role_key)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles FROM aegaeon.organization_role_definitions WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'client_bindings' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,client_registration_id,client_identifier,active,revision,targets,created_at FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'operators' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,administrator_id,active,revision,capabilities,created_at FROM aegaeon.organization_operator_grants WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'organizations' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,external_id,state,revision,grant_generation,created_at FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'memberships' THEN statement := 'SELECT (jsonb_build_array(organization_id,end_user_id)::text)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,organization_id,end_user_id,incarnation,state,revision,grant_generation,roles FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'invitations' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,revision,state,recipient,authority,issued_at,expires_at,delivery_revision,delivered_at,accepted_challenge_id,result,delivery_outcome FROM aegaeon.organization_invitations WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'challenges' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,invitation_id,invitation_delivery_revision,recipient_binding,request_key,issued_at,expires_at,delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_invitation_challenges WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'identity_requests' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,invitation_id,invitation_delivery_revision,policy_revision,purpose,request_key,encode(request_digest,''hex'') AS request_digest,target_user_id,target_identity_revision,issued_at,expires_at,state,result,delivery_revision,delivered_at,delivery_outcome FROM aegaeon.organization_identity_requests WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'administrative_grants' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,revision,active,issued_at,expires_at,creation_key,encode(request_digest,''hex'') AS request_digest,revocation_key,encode(revocation_digest,''hex'') AS revocation_digest FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'audit' THEN statement := 'SELECT (id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,client_registration_id,request_id,reason,event_type,data,created_at FROM aegaeon.organization_authority_events WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'receipts' THEN statement := 'SELECT (jsonb_build_array(actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key)::text)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,encode(request_digest,''hex'') AS request_digest,result,created_at FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2) v';
 WHEN 'outbox' THEN statement := 'SELECT (event_id)::text AS row_key,to_jsonb(v)::text AS row_data FROM (SELECT event_id,attempts,delivered_at FROM aegaeon.organization_authority_outbox WHERE EXISTS(SELECT 1 FROM aegaeon.organization_authority_events e WHERE e.id=event_id AND e.environment_id=$1 AND e.domain_id=$2)) v';
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unknown prepared section';
 END CASE;
 RETURN QUERY EXECUTE 'SELECT r.row_key,CASE WHEN octet_length(r.row_data)<=262144 THEN r.row_data ELSE NULL END FROM ('||statement||') r WHERE $3::text IS NULL OR r.row_key COLLATE "C">$3 COLLATE "C" ORDER BY r.row_key COLLATE "C" LIMIT $4'
 USING scope_environment,scope_domain,after_key,page_limit;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_prepared_rows_v1(uuid,uuid,uuid,text,text,text,integer) TO aegaeon_subject_maintenance;
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
       FROM pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner))) a LEFT JOIN pg_catalog.pg_roles r ON r.oid=a.grantee)) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='aegaeon' AND (p.proname LIKE 'subject_history_%' OR p.proname LIKE 'subject_ownership_%' OR p.proname IN ('restore_subject_history_page_v1','organization_creation_record_v1','organization_import_hold_guard','organization_identity_guard','organization_identity_credential_guard','organization_identity_policy_guard','organization_identity_profile_guard','organization_support_policy_guard','organization_admin_access_guard','organization_snapshot_history_v1','organization_import_target_v1','organization_import_hold_guard','organization_import_prepared_rows_v1','organization_import_operation_v1','organization_import_begin_v1','organization_import_row_v1','organization_import_finish_v1') OR p.proname IN ('inventory_subject_ownership_history_v1','adopt_subject_ownership_history_v1','validate_subject_ownership_namespace_v1'))
   UNION ALL SELECT 'role',r.oid::text,pg_catalog.to_jsonb(r) FROM pg_catalog.pg_roles r
   UNION ALL SELECT 'membership',m.roleid::text||':'||m.member::text||':'||m.grantor::text,pg_catalog.to_jsonb(m) FROM pg_catalog.pg_auth_members m
   UNION ALL SELECT 'parameter_acl',p.oid::text,pg_catalog.to_jsonb(p) FROM pg_catalog.pg_parameter_acl p
   UNION ALL SELECT 'atlas_revision',r.row_key,r.row_text::jsonb FROM aegaeon.subject_history_revision_rows() r
   UNION ALL SELECT 'runtime_role',runtime_name,pg_catalog.jsonb_build_object('runtime_role',runtime_name)
 ) SELECT kind||':'||key, value::text FROM rows ORDER BY kind COLLATE "C",key COLLATE "C"
$function$;
$definition$;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
