-- Append-only subject ownership in the independently provisioned witness.
-- Apply after schema-v1.sql and schema-v2.sql with all service writers stopped.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;

CREATE FUNCTION organization_witness.history_subject(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
 SELECT octet_length(convert_to(value,'UTF8')) BETWEEN 1 AND 255
 AND NOT EXISTS(SELECT FROM generate_series(0,octet_length(convert_to(value,'UTF8'))-1) AS bytes(i)
                WHERE get_byte(convert_to(value,'UTF8'),bytes.i)>127)
$$;

CREATE TABLE organization_witness.history_namespaces (
 environment_id uuid PRIMARY KEY REFERENCES organization_witness.authorities(environment_id),
 issuer_host text COLLATE "C" NOT NULL UNIQUE CHECK(octet_length(issuer_host) BETWEEN 1 AND 1024),
 operation_id uuid NOT NULL,
 control_revision bigint NOT NULL CHECK(control_revision>0),
 receipt_id uuid NOT NULL,
 manifest_sha256 text NOT NULL CHECK(manifest_sha256 ~ '^[0-9a-f]{64}$'),
 inventory_sha256 text NOT NULL CHECK(inventory_sha256 ~ '^[0-9a-f]{64}$'),
 expected_owners integer NOT NULL CHECK(expected_owners BETWEEN 0 AND 1000000),
 expected_subjects integer NOT NULL CHECK(expected_subjects BETWEEN 0 AND 1000000),
 expected_digest text NOT NULL CHECK(expected_digest ~ '^[0-9a-f]{64}$'),
 sequence bigint NOT NULL DEFAULT 0 CHECK(sequence BETWEEN 0 AND 1000000),
 owner_count integer NOT NULL DEFAULT 0 CHECK(owner_count>=0),
 subject_count integer NOT NULL DEFAULT 0 CHECK(subject_count>=0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 sealed boolean NOT NULL DEFAULT false,
 CHECK(expected_owners+expected_subjects<=1000000),
 CHECK(sequence=owner_count::bigint+subject_count::bigint),
 FOREIGN KEY(environment_id,operation_id) REFERENCES organization_witness.operations(environment_id,id)
);
CREATE TABLE organization_witness.history_owners (
 owner_id uuid PRIMARY KEY,
 environment_id uuid NOT NULL REFERENCES organization_witness.history_namespaces(environment_id),
 UNIQUE(owner_id,environment_id)
);
CREATE TABLE organization_witness.history_entries (
 environment_id uuid NOT NULL REFERENCES organization_witness.history_namespaces(environment_id),
 sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 1000000),
 kind smallint NOT NULL CHECK(kind IN (0,1)),
 owner_id uuid NOT NULL,
 subject text COLLATE "C",
 operation_id uuid NOT NULL,
 epoch uuid,
 worker_id uuid,
 slot integer,
 generation bigint,
 principal name NOT NULL DEFAULT session_user,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 previous_digest bytea NOT NULL CHECK(octet_length(previous_digest)=32),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 PRIMARY KEY(environment_id,sequence),
 FOREIGN KEY(owner_id,environment_id) REFERENCES organization_witness.history_owners(owner_id,environment_id),
 FOREIGN KEY(environment_id,operation_id) REFERENCES organization_witness.operations(environment_id,id),
 FOREIGN KEY(environment_id,epoch) REFERENCES organization_witness.epochs(environment_id,epoch),
 CHECK((epoch IS NULL AND worker_id IS NULL AND slot IS NULL AND generation IS NULL)
  OR (epoch IS NOT NULL AND worker_id IS NOT NULL AND slot IS NOT NULL AND slot BETWEEN 0 AND 63 AND generation IS NOT NULL AND generation>0)),
 CHECK((kind=0 AND subject IS NULL) OR (kind=1 AND subject IS NOT NULL AND organization_witness.history_subject(subject)))
);
CREATE UNIQUE INDEX history_owner_entry ON organization_witness.history_entries(environment_id,owner_id) WHERE kind=0;
CREATE UNIQUE INDEX history_subject_entry ON organization_witness.history_entries(environment_id,subject) WHERE kind=1;

CREATE FUNCTION organization_witness.history_progress(p_environment uuid) RETURNS jsonb
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
 SELECT jsonb_build_object('environment_id',environment_id,'issuer_host',issuer_host,
  'operation_id',operation_id,'control_revision',control_revision,'receipt_id',receipt_id,
  'manifest_sha256',manifest_sha256,'inventory_sha256',inventory_sha256,
  'expected_owners',expected_owners,'expected_subjects',expected_subjects,'expected_digest',expected_digest,
  'sequence',sequence,'owner_count',owner_count,'subject_count',subject_count,
  'digest',encode(digest,'hex'),'sealed',sealed)
 FROM organization_witness.history_namespaces WHERE environment_id=p_environment
$$;

CREATE FUNCTION organization_witness.history_require_fence(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.authorities
  WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'fenced' OR a.operation_id IS DISTINCT FROM p_operation OR a.revision IS DISTINCT FROM p_revision
  OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND pending)
 THEN RAISE EXCEPTION 'history requires exact drained fence'; END IF;
END $$;

CREATE FUNCTION organization_witness.history_begin(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint,
 p_issuer text,p_receipt uuid,p_manifest text,p_inventory text,p_owners integer,p_subjects integer,p_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE h organization_witness.history_namespaces%ROWTYPE; initial bytea;
BEGIN
 PERFORM organization_witness.history_require_fence(p_environment,p_deployment,p_operation,p_revision);
 SELECT * INTO h FROM organization_witness.history_namespaces WHERE environment_id=p_environment FOR UPDATE;
 IF FOUND THEN
  IF ROW(h.operation_id,h.control_revision,h.issuer_host,h.receipt_id,h.manifest_sha256,h.inventory_sha256,h.expected_owners,h.expected_subjects,h.expected_digest)
   IS DISTINCT FROM ROW(p_operation,p_revision,p_issuer,p_receipt,p_manifest,p_inventory,p_owners,p_subjects,p_digest)
  THEN RAISE EXCEPTION 'conflicting history enrollment'; END IF;
  RETURN organization_witness.history_progress(p_environment);
 END IF;
 initial := sha256(convert_to('aegaeon-permanent-history-v1','UTF8')||decode('00','hex')||uuid_send(p_environment)||int4send(octet_length(p_issuer))||convert_to(p_issuer,'UTF8'));
 INSERT INTO organization_witness.history_namespaces(environment_id,issuer_host,operation_id,control_revision,receipt_id,
  manifest_sha256,inventory_sha256,expected_owners,expected_subjects,expected_digest,digest)
 VALUES(p_environment,p_issuer,p_operation,p_revision,p_receipt,p_manifest,p_inventory,p_owners,p_subjects,p_digest,initial);
 RETURN organization_witness.history_progress(p_environment);
END $$;

-- Only the fixed entrypoints call this helper, while holding authority and
-- namespace locks. A thrown conflict rolls back the complete calling statement.
CREATE FUNCTION organization_witness.history_append(p_environment uuid,p_kind smallint,p_owner uuid,p_subject text,p_epoch uuid,p_worker uuid,p_slot integer,p_generation bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE h organization_witness.history_namespaces%ROWTYPE; next_digest bytea; next_sequence bigint; operation_uuid uuid;
BEGIN
 SELECT * INTO STRICT h FROM organization_witness.history_namespaces WHERE environment_id=p_environment FOR UPDATE;
 IF h.sequence>=1000000 THEN RAISE EXCEPTION 'history capacity exhausted'; END IF;
 IF p_kind=0 THEN
  INSERT INTO organization_witness.history_owners(owner_id,environment_id) VALUES(p_owner,p_environment);
 END IF;
 next_sequence := h.sequence+1;
 next_digest := sha256(h.digest||int8send(next_sequence)||decode(lpad(to_hex(p_kind::integer),2,'0'),'hex')||uuid_send(p_owner)
  ||int4send(octet_length(COALESCE(p_subject,'')))||convert_to(COALESCE(p_subject,''),'UTF8'));
 operation_uuid := CASE WHEN p_epoch IS NULL THEN h.operation_id ELSE (SELECT operation_id FROM organization_witness.authorities WHERE environment_id=p_environment) END;
 INSERT INTO organization_witness.history_entries(environment_id,sequence,kind,owner_id,subject,operation_id,epoch,worker_id,slot,generation,previous_digest,digest)
 VALUES(p_environment,next_sequence,p_kind,p_owner,p_subject,operation_uuid,p_epoch,p_worker,p_slot,p_generation,h.digest,next_digest);
 UPDATE organization_witness.history_namespaces SET sequence=next_sequence,digest=next_digest,
  owner_count=owner_count+CASE WHEN p_kind=0 THEN 1 ELSE 0 END,
  subject_count=subject_count+CASE WHEN p_kind=1 THEN 1 ELSE 0 END WHERE environment_id=p_environment;
END $$;

CREATE FUNCTION organization_witness.history_batch(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint,p_from bigint,p_entries jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE h organization_witness.history_namespaces%ROWTYPE; old_entry organization_witness.history_entries%ROWTYPE;
 item jsonb; owner_uuid uuid; subject_value text; entry_kind smallint; position bigint; n integer; prior_owner uuid; prior_subject text;
BEGIN
 PERFORM organization_witness.history_require_fence(p_environment,p_deployment,p_operation,p_revision);
 SELECT * INTO STRICT h FROM organization_witness.history_namespaces WHERE environment_id=p_environment FOR UPDATE;
 IF h.operation_id IS DISTINCT FROM p_operation OR h.control_revision IS DISTINCT FROM p_revision
  OR p_from IS NULL OR p_from<0 OR p_from>h.sequence OR p_entries IS NULL
  OR jsonb_typeof(p_entries)<>'array' OR octet_length(p_entries::text)>1048576
 THEN RAISE EXCEPTION 'invalid history batch'; END IF;
 n := jsonb_array_length(p_entries);
 IF n<1 OR n>256 OR p_from+n>1000000 OR (p_from<h.sequence AND p_from+n>h.sequence)
  OR (h.sealed AND p_from+n>h.sequence) THEN RAISE EXCEPTION 'history batch range refused'; END IF;
 position := p_from;
 FOR item IN SELECT value FROM jsonb_array_elements(p_entries) LOOP
  position := position+1;
  IF jsonb_typeof(item)<>'object' OR item-ARRAY['kind','owner_id','subject']<>'{}'::jsonb
   OR NOT (item ?& ARRAY['kind','owner_id','subject']) OR jsonb_typeof(item->'owner_id')<>'string'
   OR item->>'kind' NOT IN ('owner','reservation') OR item->>'kind' IS NULL
  THEN RAISE EXCEPTION 'invalid history entry'; END IF;
  owner_uuid := (item->>'owner_id')::uuid;
  IF owner_uuid::text IS DISTINCT FROM item->>'owner_id' THEN RAISE EXCEPTION 'noncanonical owner input'; END IF;
  entry_kind := CASE WHEN item->>'kind'='owner' THEN 0 ELSE 1 END;
  subject_value := item->>'subject';
  IF (entry_kind=0 AND item->'subject'<>'null'::jsonb) OR
   (entry_kind=1 AND (jsonb_typeof(item->'subject')<>'string' OR NOT organization_witness.history_subject(subject_value)))
  THEN RAISE EXCEPTION 'invalid history subject'; END IF;
  IF position<=h.sequence THEN
   SELECT * INTO STRICT old_entry FROM organization_witness.history_entries WHERE environment_id=p_environment AND sequence=position;
   IF ROW(old_entry.kind,old_entry.owner_id,old_entry.subject) IS DISTINCT FROM ROW(entry_kind,owner_uuid,subject_value)
   THEN RAISE EXCEPTION 'conflicting history replay'; END IF;
  ELSE
   IF entry_kind=0 THEN
    IF h.subject_count<>0 OR h.owner_count>=h.expected_owners THEN RAISE EXCEPTION 'history owner order refused'; END IF;
    SELECT owner_id INTO prior_owner FROM organization_witness.history_entries WHERE environment_id=p_environment AND kind=0 ORDER BY sequence DESC LIMIT 1;
    IF prior_owner IS NOT NULL AND owner_uuid<=prior_owner THEN RAISE EXCEPTION 'history owner order refused'; END IF;
   ELSE
    IF h.owner_count<>h.expected_owners OR h.subject_count>=h.expected_subjects THEN RAISE EXCEPTION 'history subject order refused'; END IF;
    SELECT subject INTO prior_subject FROM organization_witness.history_entries WHERE environment_id=p_environment AND kind=1 ORDER BY sequence DESC LIMIT 1;
    IF prior_subject IS NOT NULL AND subject_value COLLATE "C"<=prior_subject COLLATE "C" THEN RAISE EXCEPTION 'history subject order refused'; END IF;
   END IF;
   PERFORM organization_witness.history_append(p_environment,entry_kind,owner_uuid,subject_value,NULL,NULL,NULL,NULL);
   SELECT * INTO STRICT h FROM organization_witness.history_namespaces WHERE environment_id=p_environment;
  END IF;
 END LOOP;
 RETURN organization_witness.history_progress(p_environment);
END $$;

CREATE FUNCTION organization_witness.history_seal(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE h organization_witness.history_namespaces%ROWTYPE;
BEGIN
 PERFORM organization_witness.history_require_fence(p_environment,p_deployment,p_operation,p_revision);
 SELECT * INTO STRICT h FROM organization_witness.history_namespaces WHERE environment_id=p_environment FOR UPDATE;
 IF h.operation_id IS DISTINCT FROM p_operation OR h.control_revision IS DISTINCT FROM p_revision
  OR h.owner_count<>h.expected_owners OR h.subject_count<>h.expected_subjects OR encode(h.digest,'hex')<>h.expected_digest
 THEN RAISE EXCEPTION 'history sealing refused'; END IF;
 UPDATE organization_witness.history_namespaces SET sealed=true WHERE environment_id=p_environment;
 RETURN organization_witness.history_progress(p_environment);
END $$;

CREATE FUNCTION organization_witness.history_read(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint,p_after bigint,p_limit integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE h organization_witness.history_namespaces%ROWTYPE; entries jsonb;
BEGIN
 PERFORM organization_witness.history_require_fence(p_environment,p_deployment,p_operation,p_revision);
 SELECT * INTO STRICT h FROM organization_witness.history_namespaces WHERE environment_id=p_environment FOR SHARE;
 IF p_after IS NULL OR p_after<0 OR p_after>h.sequence OR p_limit IS NULL OR p_limit<1 OR p_limit>256
 THEN RAISE EXCEPTION 'history inspection range refused'; END IF;
 SELECT COALESCE(jsonb_agg(jsonb_build_object('sequence',e.sequence,'kind',CASE WHEN e.kind=0 THEN 'owner' ELSE 'reservation' END,
  'owner_id',e.owner_id,'subject',e.subject,'operation_id',e.operation_id,'epoch',e.epoch,'worker_id',e.worker_id,'slot',e.slot,'generation',e.generation,'principal',e.principal,'recorded_at',e.recorded_at,'previous_digest',encode(e.previous_digest,'hex'),'digest',encode(e.digest,'hex')) ORDER BY e.sequence),'[]'::jsonb) INTO entries
 FROM (SELECT * FROM organization_witness.history_entries WHERE environment_id=p_environment AND sequence>p_after ORDER BY sequence LIMIT p_limit) e;
 RETURN jsonb_build_object('progress',organization_witness.history_progress(p_environment),'entries',entries);
END $$;

CREATE FUNCTION organization_witness.history_require_admission(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'active' OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
  OR NOT EXISTS(SELECT FROM organization_witness.history_namespaces WHERE environment_id=p_environment AND sealed)
 THEN RAISE EXCEPTION 'history admission refused'; END IF;
END $$;

CREATE FUNCTION organization_witness.history_reserve(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_owner uuid,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE existing_environment uuid; existing_owner uuid;
BEGIN
 PERFORM organization_witness.history_require_admission(p_environment,p_deployment,p_slot,p_generation,p_epoch,p_worker);
 IF p_owner IS NULL OR p_subject IS NULL OR NOT organization_witness.history_subject(p_subject) THEN RAISE EXCEPTION 'history reservation refused'; END IF;
 SELECT environment_id INTO existing_environment FROM organization_witness.history_owners WHERE owner_id=p_owner;
 IF FOUND THEN
  IF existing_environment<>p_environment THEN RAISE EXCEPTION 'permanent owner conflict'; END IF;
 ELSE
  PERFORM organization_witness.history_append(p_environment,0::smallint,p_owner,NULL,p_epoch,p_worker,p_slot,p_generation);
 END IF;
 SELECT owner_id INTO existing_owner FROM organization_witness.history_entries WHERE environment_id=p_environment AND kind=1 AND subject=p_subject COLLATE "C";
 IF FOUND THEN
  IF existing_owner<>p_owner THEN RAISE EXCEPTION 'permanent subject conflict'; END IF;
 ELSE
  PERFORM organization_witness.history_append(p_environment,1::smallint,p_owner,p_subject,p_epoch,p_worker,p_slot,p_generation);
 END IF;
 RETURN organization_witness.history_progress(p_environment);
END $$;

CREATE FUNCTION organization_witness.history_check(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_owner uuid,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
BEGIN
 PERFORM organization_witness.history_require_admission(p_environment,p_deployment,p_slot,p_generation,p_epoch,p_worker);
 IF NOT EXISTS(SELECT FROM organization_witness.history_entries WHERE environment_id=p_environment AND kind=1 AND owner_id=p_owner AND subject=p_subject COLLATE "C")
 THEN RAISE EXCEPTION 'permanent subject missing'; END IF;
 RETURN organization_witness.history_progress(p_environment);
END $$;

REVOKE ALL ON organization_witness.history_namespaces,organization_witness.history_owners,organization_witness.history_entries FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA organization_witness FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.history_begin(uuid,uuid,uuid,bigint,text,uuid,text,text,integer,integer,text),
 organization_witness.history_batch(uuid,uuid,uuid,bigint,bigint,jsonb),organization_witness.history_seal(uuid,uuid,uuid,bigint),
 organization_witness.history_read(uuid,uuid,uuid,bigint,bigint,integer) TO aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.history_reserve(uuid,uuid,integer,bigint,uuid,uuid,uuid,text),
 organization_witness.history_check(uuid,uuid,integer,bigint,uuid,uuid,uuid,text) TO aegaeon_organization_witness_runtime;
COMMIT;
