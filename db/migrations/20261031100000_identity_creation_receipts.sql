-- ORG-R02/R19/R21, ORG-G02/G13: immutable primary creation evidence.
-- Stop and drain all serving writers before this administrator migration.
DO $preflight$
BEGIN
 IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
  RAISE EXCEPTION 'subject owner has preexisting schema CREATE';
 END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE TABLE aegaeon.organization_creation_receipts (
 environment_id uuid NOT NULL,
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('management_create','management_invite','management_csv','registration','upstream')),
 selector_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(selector_sha256)=64 AND selector_sha256 ~ '^[0-9a-f]{64}$'),
 actor_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(actor_sha256)=64 AND actor_sha256 ~ '^[0-9a-f]{64}$'),
 payload_sha256 text COLLATE "C" NOT NULL CHECK(octet_length(payload_sha256)=64 AND payload_sha256 ~ '^[0-9a-f]{64}$'),
 owner_id uuid NOT NULL UNIQUE CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 subject text COLLATE "C" NOT NULL CHECK(aegaeon.subject_ownership_valid_subject(subject)),
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 32),
 epoch uuid NOT NULL CHECK(epoch<>'00000000-0000-0000-0000-000000000000'),
 identity_revision bigint NOT NULL CHECK(identity_revision>0 AND identity_revision<9223372036854775807),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 PRIMARY KEY(environment_id,operation_id),
 UNIQUE(environment_id,kind,selector_sha256),
 FOREIGN KEY(owner_id,environment_id) REFERENCES aegaeon.end_user_identity_owners(owner_id,environment_id)
);
REVOKE ALL ON aegaeon.organization_creation_receipts FROM PUBLIC;
CREATE TRIGGER organization_creation_owner_insert BEFORE INSERT ON aegaeon.organization_creation_receipts
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER organization_creation_immutable BEFORE UPDATE OR DELETE ON aegaeon.organization_creation_receipts
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER organization_creation_no_truncate BEFORE TRUNCATE ON aegaeon.organization_creation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_creation_record_v1(input jsonb) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE r aegaeon.organization_creation_receipts%ROWTYPE; previous aegaeon.organization_creation_receipts%ROWTYPE;
 field text; computed bytea;
BEGIN
 IF input IS NULL OR jsonb_typeof(input)<>'object' OR octet_length(input::text)>4096 THEN
  RAISE EXCEPTION 'creation receipt shape refused';
 END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(input))<>11 OR input-ARRAY[
  'environment_id','operation_id','kind','selector_sha256','actor_sha256','payload_sha256','owner_id','subject','attempt','epoch','identity_revision']<>'{}'::jsonb THEN
  RAISE EXCEPTION 'creation receipt fields refused';
 END IF;
 FOREACH field IN ARRAY ARRAY['environment_id','operation_id','kind','selector_sha256','actor_sha256','payload_sha256','owner_id','subject','epoch'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'creation receipt field type refused'; END IF;
 END LOOP;
 IF jsonb_typeof(input->'attempt') IS DISTINCT FROM 'number' OR jsonb_typeof(input->'identity_revision') IS DISTINCT FROM 'number' THEN
  RAISE EXCEPTION 'creation receipt counter type refused';
 END IF;
 SELECT * INTO r FROM jsonb_populate_record(NULL::aegaeon.organization_creation_receipts,input);
 IF NOT EXISTS(SELECT FROM aegaeon.end_users WHERE id=r.owner_id AND environment_id=r.environment_id
   AND subject=r.subject COLLATE "C" AND status<>'DELETED' AND organization_identity_revision=r.identity_revision FOR UPDATE) THEN
  RAISE EXCEPTION 'creation receipt current identity mismatch';
 END IF;
 computed:=sha256(convert_to('aegaeon-creation-primary-v1','UTF8')||decode('00','hex')||uuid_send(r.environment_id)||uuid_send(r.operation_id)
  ||int4send(octet_length(r.kind))||convert_to(r.kind,'UTF8')||decode(r.selector_sha256,'hex')||decode(r.actor_sha256,'hex')||decode(r.payload_sha256,'hex')
  ||uuid_send(r.owner_id)||int4send(octet_length(r.subject))||convert_to(r.subject,'UTF8')||int4send(r.attempt)||uuid_send(r.epoch)||int8send(r.identity_revision));
 SELECT * INTO previous FROM aegaeon.organization_creation_receipts WHERE environment_id=r.environment_id AND operation_id=r.operation_id;
 IF FOUND THEN
  IF (to_jsonb(previous)-ARRAY['receipt_sha256','recorded_at']) IS DISTINCT FROM input OR previous.receipt_sha256 IS DISTINCT FROM computed THEN
   RAISE EXCEPTION 'creation receipt replay conflict';
  END IF;
  RETURN computed;
 END IF;
 INSERT INTO aegaeon.organization_creation_receipts(environment_id,operation_id,kind,selector_sha256,actor_sha256,payload_sha256,owner_id,subject,attempt,epoch,identity_revision,receipt_sha256)
 VALUES(r.environment_id,r.operation_id,r.kind,r.selector_sha256,r.actor_sha256,r.payload_sha256,r.owner_id,r.subject,r.attempt,r.epoch,r.identity_revision,computed);
 RETURN computed;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_creation_record_v1(jsonb) FROM PUBLIC;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
