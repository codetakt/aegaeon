-- Permanent facts only: no identity, credential, grant or activation writes.
-- Stop and drain serving writers before this separately authorized migration.
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
CREATE TABLE aegaeon.subject_history_restorations (
 operation_id uuid PRIMARY KEY CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 environment_id uuid NOT NULL REFERENCES aegaeon.subject_ownership_namespaces(environment_id),
 source jsonb NOT NULL CHECK(jsonb_typeof(source)='object' AND octet_length(source::text)<=4096),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 session_actor text NOT NULL
);
CREATE TABLE aegaeon.subject_history_restoration_pages (
 operation_id uuid NOT NULL REFERENCES aegaeon.subject_history_restorations(operation_id),
 after_sequence bigint NOT NULL CHECK(after_sequence BETWEEN 0 AND 999999),
 entry_count integer NOT NULL CHECK(entry_count BETWEEN 1 AND 256),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 input jsonb NOT NULL CHECK(jsonb_typeof(input)='object' AND octet_length(input::text)<=1048576),
 recorded_at timestamptz NOT NULL DEFAULT statement_timestamp(),
 session_actor text NOT NULL,
 PRIMARY KEY(operation_id,after_sequence),
 CHECK(after_sequence+entry_count<=1000000)
);
REVOKE ALL ON aegaeon.subject_history_restorations,aegaeon.subject_history_restoration_pages FROM PUBLIC;
CREATE TRIGGER subject_history_restorations_owner_insert BEFORE INSERT ON aegaeon.subject_history_restorations
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER subject_history_restorations_immutable BEFORE UPDATE OR DELETE ON aegaeon.subject_history_restorations
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restorations_no_truncate BEFORE TRUNCATE ON aegaeon.subject_history_restorations
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restoration_pages_owner_insert BEFORE INSERT ON aegaeon.subject_history_restoration_pages
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_guard_insert();
CREATE TRIGGER subject_history_restoration_pages_immutable BEFORE UPDATE OR DELETE ON aegaeon.subject_history_restoration_pages
FOR EACH ROW EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
CREATE TRIGGER subject_history_restoration_pages_no_truncate BEFORE TRUNCATE ON aegaeon.subject_history_restoration_pages
FOR EACH STATEMENT EXECUTE FUNCTION aegaeon.subject_ownership_immutable();
EXECUTE $definition$
CREATE FUNCTION aegaeon.restore_subject_history_page_v1(input jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE operation uuid; environment uuid; deployment uuid; witness_operation uuid;
 revision bigint; issuer text; source_sequence bigint; source_digest bytea; page_after bigint;
 count_entries integer; source jsonb; previous_source jsonb; prior aegaeon.subject_history_restoration_pages%ROWTYPE;
 entry jsonb; owner uuid; reserved_subject text; recorded timestamptz; sequence bigint; digest bytea; previous bytea;
 actual_environment uuid; actual_owner uuid; field text;
BEGIN
 IF input IS NULL OR jsonb_typeof(input)<>'object' OR octet_length(input::text)>1048576
  OR (SELECT count(*) FROM jsonb_object_keys(input))<>11
  OR input-ARRAY['operation_id','environment_id','deployment_id','witness_operation_id','witness_revision',
   'issuer_host','source_sequence','source_digest','after_sequence','previous_digest','entries']<>'{}'::jsonb
 THEN RAISE EXCEPTION 'history restoration input shape'; END IF;
 IF jsonb_typeof(input->'entries') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'history restoration page shape'; END IF;
 FOREACH field IN ARRAY ARRAY['operation_id','environment_id','deployment_id','witness_operation_id','issuer_host','source_digest','previous_digest'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'history restoration metadata type'; END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['witness_revision','source_sequence','after_sequence'] LOOP
  IF jsonb_typeof(input->field) IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'history restoration counter type'; END IF;
 END LOOP;
 operation:=(input->>'operation_id')::uuid; environment:=(input->>'environment_id')::uuid;
 deployment:=(input->>'deployment_id')::uuid; witness_operation:=(input->>'witness_operation_id')::uuid;
 revision:=(input->>'witness_revision')::bigint; issuer:=input->>'issuer_host';
 source_sequence:=(input->>'source_sequence')::bigint; page_after:=(input->>'after_sequence')::bigint;
 count_entries:=jsonb_array_length(input->'entries');
 IF operation IS NULL OR operation='00000000-0000-0000-0000-000000000000'
  OR environment IS NULL OR deployment IS NULL OR deployment='00000000-0000-0000-0000-000000000000'
  OR witness_operation IS NULL OR witness_operation='00000000-0000-0000-0000-000000000000'
  OR revision IS NULL OR revision<1 OR issuer IS NULL OR octet_length(issuer) NOT BETWEEN 1 AND 1024
  OR source_sequence IS NULL OR source_sequence NOT BETWEEN 1 AND 1000000
  OR page_after IS NULL OR page_after<0 OR page_after+count_entries>source_sequence
  OR count_entries NOT BETWEEN 1 AND 256
  OR input->>'source_digest' IS NULL OR input->>'source_digest' !~ '^[0-9a-f]{64}$'
  OR input->>'previous_digest' IS NULL OR input->>'previous_digest' !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'history restoration metadata'; END IF;
 source_digest:=decode(input->>'source_digest','hex'); previous:=decode(input->>'previous_digest','hex');
 IF NOT EXISTS(SELECT FROM aegaeon.subject_ownership_namespaces n JOIN aegaeon.subject_ownership_adoptions a USING(environment_id)
  WHERE n.environment_id=environment AND n.issuer_host=issuer COLLATE "C")
 THEN RAISE EXCEPTION 'history restoration adopted namespace mismatch'; END IF;
 source:=input-ARRAY['after_sequence','previous_digest','entries'];
 INSERT INTO aegaeon.subject_history_restorations(operation_id,environment_id,source,session_actor)
 VALUES(operation,environment,source,session_user) ON CONFLICT(operation_id) DO NOTHING;
 SELECT r.source INTO STRICT previous_source FROM aegaeon.subject_history_restorations r WHERE r.operation_id=operation;
 IF previous_source IS DISTINCT FROM source THEN RAISE EXCEPTION 'history restoration operation conflict'; END IF;
 -- Serialize pages and exact concurrent replays using the immutable header row.
 PERFORM 1 FROM aegaeon.subject_history_restorations r WHERE r.operation_id=operation FOR UPDATE;
 SELECT * INTO prior FROM aegaeon.subject_history_restoration_pages p WHERE p.operation_id=operation AND p.after_sequence=page_after;
 IF FOUND THEN
  IF prior.input IS DISTINCT FROM input THEN RAISE EXCEPTION 'history restoration page conflict'; END IF;
  RETURN jsonb_build_object('operation_id',operation,'sequence',page_after+prior.entry_count,
   'digest',encode(prior.digest,'hex'),'complete',page_after+prior.entry_count=source_sequence,'activation_authorized',false);
 END IF;
 IF page_after=0 THEN
  digest:=sha256(convert_to('aegaeon-permanent-history-v1','UTF8')||decode('00','hex')||uuid_send(environment)
   ||int4send(octet_length(issuer))||convert_to(issuer,'UTF8'));
 ELSE
  SELECT * INTO prior FROM aegaeon.subject_history_restoration_pages p WHERE p.operation_id=operation
   ORDER BY p.after_sequence DESC LIMIT 1;
  IF NOT FOUND OR prior.after_sequence+prior.entry_count<>page_after THEN RAISE EXCEPTION 'history restoration prefix missing'; END IF;
  digest:=prior.digest;
 END IF;
 IF digest IS DISTINCT FROM previous THEN RAISE EXCEPTION 'history restoration page link'; END IF;
 sequence:=page_after;
 FOR entry IN SELECT value FROM jsonb_array_elements(input->'entries') LOOP
  sequence:=sequence+1;
  IF jsonb_typeof(entry)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(entry))<>13
   OR entry-ARRAY['sequence','kind','owner_id','subject','operation_id','epoch','worker_id','slot','generation','principal','recorded_at','previous_digest','digest']<>'{}'::jsonb
   OR jsonb_typeof(entry->'sequence') IS DISTINCT FROM 'number'
   OR jsonb_typeof(entry->'kind') IS DISTINCT FROM 'string'
   OR jsonb_typeof(entry->'principal') IS DISTINCT FROM 'string'
   OR octet_length(entry->>'principal') NOT BETWEEN 1 AND 63
   OR jsonb_typeof(entry->'operation_id') IS DISTINCT FROM 'string'
   OR (entry->>'operation_id')::uuid='00000000-0000-0000-0000-000000000000'
   OR (entry->>'sequence')::bigint IS DISTINCT FROM sequence
   OR entry->>'previous_digest' IS DISTINCT FROM encode(digest,'hex')
   OR entry->>'digest' IS NULL OR entry->>'digest' !~ '^[0-9a-f]{64}$'
   OR jsonb_typeof(entry->'owner_id') IS DISTINCT FROM 'string'
   OR jsonb_typeof(entry->'recorded_at') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'history restoration entry shape'; END IF;
  IF (entry->'epoch'='null'::jsonb AND entry->'worker_id'='null'::jsonb
      AND entry->'slot'='null'::jsonb AND entry->'generation'='null'::jsonb) THEN NULL;
  ELSIF jsonb_typeof(entry->'epoch')='string' AND jsonb_typeof(entry->'worker_id')='string'
      AND jsonb_typeof(entry->'slot')='number' AND jsonb_typeof(entry->'generation')='number'
      AND (entry->>'epoch')::uuid<>'00000000-0000-0000-0000-000000000000'
      AND (entry->>'worker_id')::uuid<>'00000000-0000-0000-0000-000000000000'
      AND (entry->>'slot')::integer BETWEEN 0 AND 63 AND (entry->>'generation')::bigint>0 THEN NULL;
  ELSE RAISE EXCEPTION 'history restoration provenance shape'; END IF;
  owner:=(entry->>'owner_id')::uuid; recorded:=(entry->>'recorded_at')::timestamptz;
  IF NOT isfinite(recorded) THEN RAISE EXCEPTION 'history restoration timestamp'; END IF;
  reserved_subject:=entry->>'subject';
  IF entry->>'kind'='owner' AND entry->'subject'='null'::jsonb THEN
   digest:=sha256(digest||int8send(sequence)||decode('00','hex')||uuid_send(owner)||int4send(0));
   INSERT INTO aegaeon.end_user_identity_owners(owner_id,environment_id,recorded_at)
    VALUES(owner,environment,recorded) ON CONFLICT(owner_id) DO NOTHING;
   SELECT o.environment_id INTO STRICT actual_environment FROM aegaeon.end_user_identity_owners o WHERE o.owner_id=owner;
   IF actual_environment IS DISTINCT FROM environment THEN RAISE EXCEPTION 'history restoration owner conflict'; END IF;
  ELSIF entry->>'kind'='reservation' AND jsonb_typeof(entry->'subject')='string'
   AND aegaeon.subject_ownership_valid_subject(reserved_subject) THEN
   digest:=sha256(digest||int8send(sequence)||decode('01','hex')||uuid_send(owner)||int4send(octet_length(reserved_subject))||convert_to(reserved_subject,'UTF8'));
   INSERT INTO aegaeon.end_user_subject_reservations(environment_id,subject,owner_id,recorded_at)
    VALUES(environment,reserved_subject,owner,recorded) ON CONFLICT ON CONSTRAINT end_user_subject_reservations_pkey DO NOTHING;
   SELECT s.owner_id INTO STRICT actual_owner FROM aegaeon.end_user_subject_reservations s
    WHERE s.environment_id=environment AND s.subject=reserved_subject COLLATE "C";
   IF actual_owner IS DISTINCT FROM owner THEN RAISE EXCEPTION 'history restoration subject conflict'; END IF;
  ELSE RAISE EXCEPTION 'history restoration entry kind'; END IF;
  IF encode(digest,'hex') IS DISTINCT FROM entry->>'digest' THEN RAISE EXCEPTION 'history restoration entry digest'; END IF;
 END LOOP;
 IF sequence=source_sequence AND digest IS DISTINCT FROM source_digest THEN RAISE EXCEPTION 'history restoration source head'; END IF;
 INSERT INTO aegaeon.subject_history_restoration_pages(operation_id,after_sequence,entry_count,digest,input,session_actor)
 VALUES(operation,page_after,count_entries,digest,input,session_user);
 RETURN jsonb_build_object('operation_id',operation,'sequence',sequence,'digest',encode(digest,'hex'),
  'complete',sequence=source_sequence,'activation_authorized',false);
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.restore_subject_history_page_v1(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.restore_subject_history_page_v1(jsonb) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
