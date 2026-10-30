-- ORG-R18/R19: maintenance-only inactive preparation. No activation entrypoint.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') OR pg_catalog.has_table_privilege('aegaeon_subject_owner','aegaeon.environments','REFERENCES') THEN
  RAISE EXCEPTION 'subject owner has preexisting schema CREATE';
 END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
GRANT REFERENCES ON aegaeon.environments TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domains ADD COLUMN import_operation_id uuid;
ALTER TABLE aegaeon.authorization_domains ADD CONSTRAINT organization_import_inactive CHECK (import_operation_id IS NULL OR NOT enabled);

CREATE TABLE aegaeon.organization_import_operations (
 id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 environment_id uuid NOT NULL,
 domain_id uuid NOT NULL,
 source_sha256 text COLLATE "C" NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
 source_enabled boolean NOT NULL,
 session_actor name NOT NULL,
 maintenance_actor name NOT NULL,
 state text NOT NULL CHECK(state IN ('writing','prepared')),
 receipt jsonb NOT NULL CHECK(jsonb_typeof(receipt)='object' AND octet_length(receipt::text)<=32768),
 created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 UNIQUE(environment_id,domain_id),
 FOREIGN KEY(environment_id) REFERENCES aegaeon.environments(id)
);
REVOKE ALL ON aegaeon.organization_import_operations FROM PUBLIC;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_hold_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE old_row jsonb; new_row jsonb; candidate jsonb; held boolean;
BEGIN
 IF current_user='aegaeon_subject_owner' THEN
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 IF TG_OP<>'INSERT' THEN old_row:=to_jsonb(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_row:=to_jsonb(NEW); END IF;
 FOREACH candidate IN ARRAY ARRAY[old_row,new_row] LOOP
  IF candidate IS NULL THEN CONTINUE; END IF;
  IF TG_TABLE_NAME='authorization_domains' THEN
   held:=candidate->>'import_operation_id' IS NOT NULL;
  ELSIF TG_TABLE_NAME='organization_authority_outbox' THEN
   SELECT EXISTS(SELECT FROM aegaeon.organization_authority_events e JOIN aegaeon.authorization_domains d ON d.id=e.domain_id AND d.environment_id=e.environment_id WHERE e.id=(candidate->>'event_id')::uuid AND d.import_operation_id IS NOT NULL) INTO held;
  ELSE
   SELECT EXISTS(SELECT FROM aegaeon.authorization_domains d WHERE d.id=(candidate->>'domain_id')::uuid AND d.environment_id=(candidate->>'environment_id')::uuid AND d.import_operation_id IS NOT NULL) INTO held;
  END IF;
  IF held THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='inactive import cannot be changed by normal authority'; END IF;
 END LOOP;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_operation_v1(operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE previous aegaeon.organization_import_operations%ROWTYPE;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 SELECT * INTO previous FROM aegaeon.organization_import_operations WHERE id=operation_id;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF previous.environment_id IS DISTINCT FROM scope_environment OR previous.domain_id IS DISTINCT FROM scope_domain OR previous.source_sha256 IS DISTINCT FROM source_digest OR previous.state<>'prepared' THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='import operation replay conflicts';
 END IF;
 RETURN previous.receipt;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_begin_v1(operation_id uuid, scope_environment uuid, scope_domain uuid, source_digest text, source_domain jsonb, inspection jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 IF pg_is_in_recovery() OR current_setting('transaction_read_only')<>'off' OR operation_id IS NULL OR operation_id='00000000-0000-0000-0000-000000000000' OR scope_environment IS NULL OR scope_domain IS NULL OR source_digest IS NULL OR source_digest!~'^[0-9a-f]{64}$'
  OR source_domain IS NULL OR jsonb_typeof(source_domain)<>'object' OR octet_length(source_domain::text)>262144
  OR source_domain->>'environment_id' IS DISTINCT FROM scope_environment::text OR source_domain->>'id' IS DISTINCT FROM scope_domain::text
  OR inspection IS NULL OR inspection->'activationAuthorized' IS DISTINCT FROM 'false'::jsonb THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inactive preparation';
 END IF;
 INSERT INTO aegaeon.organization_import_operations(id,environment_id,domain_id,source_sha256,source_enabled,session_actor,maintenance_actor,state,receipt)
 VALUES(operation_id,scope_environment,scope_domain,source_digest,(source_domain->>'enabled')::boolean,session_user,aegaeon.subject_history_maintenance_actor(),'writing',inspection);
 INSERT INTO aegaeon.authorization_domains(id,environment_id,name,is_default,enabled,revision,invitation_delivery,support_policy,support_policy_revision,import_operation_id)
 SELECT r.id,r.environment_id,r.name,r.is_default,false,r.revision,r.invitation_delivery,r.support_policy,r.support_policy_revision,operation_id FROM jsonb_populate_record(NULL::aegaeon.authorization_domains,source_domain) r;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_row_v1(operation_id uuid, section_name text, payload jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET timezone = 'UTC' SET datestyle = 'ISO, YMD'
AS $function$
DECLARE operation aegaeon.organization_import_operations%ROWTYPE;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 SELECT * INTO operation FROM aegaeon.organization_import_operations WHERE id=operation_id FOR UPDATE;
 IF NOT FOUND OR operation.state<>'writing' OR payload IS NULL OR jsonb_typeof(payload)<>'object' OR octet_length(payload::text)>262144 THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='invalid inactive import row';
 END IF;
 IF section_name='outbox' THEN
  IF NOT EXISTS(SELECT FROM aegaeon.organization_authority_events WHERE id=(payload->>'event_id')::uuid AND environment_id=operation.environment_id AND domain_id=operation.domain_id) THEN
   RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive outbox scope mismatch';
  END IF;
 ELSIF payload->>'environment_id' IS DISTINCT FROM operation.environment_id::text OR payload->>'domain_id' IS DISTINCT FROM operation.domain_id::text THEN
  RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive row scope mismatch';
 END IF;
 CASE section_name
 WHEN 'targets' THEN INSERT INTO aegaeon.authorization_domain_targets(environment_id,domain_id,audience,management,introspection_clients) SELECT r.environment_id,r.domain_id,r.audience,r.management,r.introspection_clients FROM jsonb_populate_record(NULL::aegaeon.authorization_domain_targets,payload) r;
 WHEN 'roles' THEN INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles) SELECT r.environment_id,r.domain_id,r.role_key,r.version,r.privileges,r.manages_members,r.assignable_roles FROM jsonb_populate_record(NULL::aegaeon.organization_role_definitions,payload) r;
 WHEN 'client_bindings' THEN INSERT INTO aegaeon.organization_client_bindings(id,environment_id,domain_id,client_registration_id,client_identifier,active,revision,targets,created_at) SELECT r.id,r.environment_id,r.domain_id,r.client_registration_id,r.client_identifier,r.active,r.revision,r.targets,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_client_bindings,payload) r;
 WHEN 'operators' THEN INSERT INTO aegaeon.organization_operator_grants(id,environment_id,domain_id,administrator_id,active,revision,capabilities,created_at) SELECT r.id,r.environment_id,r.domain_id,r.administrator_id,r.active,r.revision,r.capabilities,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_operator_grants,payload) r;
 WHEN 'organizations' THEN INSERT INTO aegaeon.application_organizations(id,environment_id,domain_id,external_id,state,revision,grant_generation,created_at) SELECT r.id,r.environment_id,r.domain_id,r.external_id,r.state,r.revision,r.grant_generation,r.created_at FROM jsonb_populate_record(NULL::aegaeon.application_organizations,payload) r;
 WHEN 'memberships' THEN INSERT INTO aegaeon.organization_memberships(environment_id,domain_id,organization_id,end_user_id,incarnation,state,revision,grant_generation,roles) SELECT r.environment_id,r.domain_id,r.organization_id,r.end_user_id,r.incarnation,r.state,r.revision,r.grant_generation,r.roles FROM jsonb_populate_record(NULL::aegaeon.organization_memberships,payload) r;
 WHEN 'invitations' THEN INSERT INTO aegaeon.organization_invitations(id,environment_id,domain_id,organization_id,revision,state,recipient,authority,issued_at,expires_at,delivery_revision,delivered_at,accepted_challenge_id,result,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.revision,r.state,r.recipient,r.authority,r.issued_at,r.expires_at,r.delivery_revision,r.delivered_at,r.accepted_challenge_id,r.result,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_invitations,payload||jsonb_build_object('capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'challenges' THEN INSERT INTO aegaeon.organization_invitation_challenges(id,environment_id,domain_id,invitation_id,invitation_delivery_revision,recipient_binding,request_key,issued_at,expires_at,delivery_revision,delivered_at,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.invitation_id,r.invitation_delivery_revision,r.recipient_binding,r.request_key,r.issued_at,r.expires_at,r.delivery_revision,r.delivered_at,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_invitation_challenges,payload||jsonb_build_object('capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'identity_requests' THEN INSERT INTO aegaeon.organization_identity_requests(id,environment_id,domain_id,invitation_id,invitation_delivery_revision,policy_revision,purpose,request_key,request_digest,target_user_id,target_identity_revision,issued_at,expires_at,state,result,delivery_revision,delivered_at,delivery_outcome,capability_hash) SELECT r.id,r.environment_id,r.domain_id,r.invitation_id,r.invitation_delivery_revision,r.policy_revision,r.purpose,r.request_key,r.request_digest,r.target_user_id,r.target_identity_revision,r.issued_at,r.expires_at,r.state,r.result,r.delivery_revision,r.delivered_at,r.delivery_outcome,r.capability_hash FROM jsonb_populate_record(NULL::aegaeon.organization_identity_requests,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END,'capability_hash',CASE WHEN (payload->>'delivery_revision')::bigint=0 THEN NULL ELSE chr(92)||'x'||encode(sha256(convert_to(gen_random_uuid()::text||gen_random_uuid()::text,'UTF8')),'hex') END)) r;
 WHEN 'administrative_grants' THEN INSERT INTO aegaeon.organization_admin_access_grants(id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,revision,active,issued_at,expires_at,creation_key,request_digest,revocation_key,revocation_digest) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.user_id,r.client_registration_id,r.root_id,r.authority,r.revision,r.active,r.issued_at,r.expires_at,r.creation_key,r.request_digest,r.revocation_key,r.revocation_digest FROM jsonb_populate_record(NULL::aegaeon.organization_admin_access_grants,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END,'revocation_digest',CASE WHEN payload->>'revocation_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'revocation_digest') END)) r;
 WHEN 'audit' THEN INSERT INTO aegaeon.organization_authority_events(id,environment_id,domain_id,organization_id,actor_id,actor_kind,client_id,client_registration_id,request_id,reason,event_type,data,created_at) SELECT r.id,r.environment_id,r.domain_id,r.organization_id,r.actor_id,r.actor_kind,r.client_id,r.client_registration_id,r.request_id,r.reason,r.event_type,r.data,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_events,payload) r;
 WHEN 'receipts' THEN INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result,created_at) SELECT r.environment_id,r.domain_id,r.actor_id,r.actor_kind,r.client_id,r.client_registration_id,r.operation,r.idempotency_key,r.request_digest,r.result,r.created_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_receipts,payload||jsonb_build_object('request_digest',CASE WHEN payload->>'request_digest' IS NULL THEN NULL ELSE chr(92)||'x'||(payload->>'request_digest') END)) r;
 WHEN 'outbox' THEN INSERT INTO aegaeon.organization_authority_outbox(event_id,attempts,delivered_at) SELECT r.event_id,r.attempts,r.delivered_at FROM jsonb_populate_record(NULL::aegaeon.organization_authority_outbox,payload) r;
 ELSE RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='unknown inactive import section';
 END CASE;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_import_finish_v1(operation_id uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE result jsonb;
BEGIN
 PERFORM aegaeon.subject_history_maintenance_actor();
 UPDATE aegaeon.organization_import_operations SET state='prepared'
 WHERE id=operation_id AND state='writing' RETURNING receipt INTO result;
 IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='inactive import phase mismatch'; END IF;
 RETURN result;
END
$function$;
$definition$;
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.authorization_domains FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.authorization_domain_targets FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_role_definitions FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_client_bindings FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_operator_grants FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.application_organizations FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_memberships FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_invitations FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_invitation_challenges FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_identity_requests FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_admin_access_grants FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_events FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_receipts FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
CREATE TRIGGER organization_import_hold BEFORE INSERT OR UPDATE OR DELETE ON aegaeon.organization_authority_outbox FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_import_hold_guard();
REVOKE ALL ON FUNCTION aegaeon.organization_import_hold_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_operation_v1(uuid,uuid,uuid,text) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_begin_v1(uuid,uuid,uuid,text,jsonb,jsonb) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_row_v1(uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_row_v1(uuid,text,jsonb) TO aegaeon_subject_maintenance;
REVOKE ALL ON FUNCTION aegaeon.organization_import_finish_v1(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_import_finish_v1(uuid) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
REVOKE REFERENCES ON aegaeon.environments FROM aegaeon_subject_owner;
