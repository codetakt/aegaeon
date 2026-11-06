-- Retained creation attempts. Apply after v1/v2/v3 with service writers stopped.
-- Primary receipts and callers must establish the separately documented outcomes.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;

CREATE FUNCTION organization_witness.creation_digest(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
 SELECT octet_length(value)=64 AND value ~ '^[0-9a-f]{64}$'
$$;

CREATE TABLE organization_witness.creation_counts (
 environment_id uuid PRIMARY KEY REFERENCES organization_witness.history_namespaces(environment_id),
 operations integer NOT NULL DEFAULT 0 CHECK(operations BETWEEN 0 AND 500000),
 events integer NOT NULL DEFAULT 0 CHECK(events BETWEEN 0 AND 1000000),
 reserved integer NOT NULL DEFAULT 0 CHECK(reserved BETWEEN 0 AND 500000),
 CHECK(events::bigint+reserved<=1000000)
);
CREATE TABLE organization_witness.creations (
 environment_id uuid NOT NULL REFERENCES organization_witness.creation_counts(environment_id),
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('management_create','management_invite','management_csv','registration','upstream')),
 selector_sha256 text COLLATE "C" NOT NULL CHECK(organization_witness.creation_digest(selector_sha256)),
 actor_sha256 text COLLATE "C" NOT NULL CHECK(organization_witness.creation_digest(actor_sha256)),
 payload_sha256 text COLLATE "C" NOT NULL CHECK(organization_witness.creation_digest(payload_sha256)),
 requested_subject text COLLATE "C" CHECK(organization_witness.history_subject(requested_subject)),
 owner_id uuid NOT NULL CHECK(owner_id<>'00000000-0000-0000-0000-000000000000'),
 subject text COLLATE "C" NOT NULL CHECK(organization_witness.history_subject(subject)),
 state text NOT NULL CHECK(state IN ('reserved','retryable','committed')),
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 32),
 epoch uuid NOT NULL,
 slot integer NOT NULL CHECK(slot BETWEEN 0 AND 63),
 generation bigint NOT NULL CHECK(generation>0),
 worker_id uuid NOT NULL,
 principal name NOT NULL,
 receipt_sha256 text CHECK(organization_witness.creation_digest(receipt_sha256)),
 PRIMARY KEY(environment_id,operation_id),
 UNIQUE(environment_id,kind,selector_sha256),
 UNIQUE(owner_id),
 FOREIGN KEY(owner_id,environment_id) REFERENCES organization_witness.history_owners(owner_id,environment_id),
 FOREIGN KEY(environment_id,epoch) REFERENCES organization_witness.epochs(environment_id,epoch),
 CHECK((state='committed')=(receipt_sha256 IS NOT NULL)),
 CHECK(requested_subject IS NULL OR requested_subject=subject COLLATE "C")
);
CREATE TABLE organization_witness.creation_events (
 environment_id uuid NOT NULL,
 sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 1000000),
 operation_id uuid NOT NULL,
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 32),
 state text NOT NULL CHECK(state IN ('reserved','retryable','committed')),
 epoch uuid NOT NULL,
 slot integer NOT NULL CHECK(slot BETWEEN 0 AND 63),
 generation bigint NOT NULL CHECK(generation>0),
 worker_id uuid NOT NULL,
 principal name NOT NULL,
 receipt_sha256 text CHECK(organization_witness.creation_digest(receipt_sha256)),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment_id,sequence),
 UNIQUE(environment_id,operation_id,attempt,state),
 FOREIGN KEY(environment_id,operation_id) REFERENCES organization_witness.creations(environment_id,operation_id),
 FOREIGN KEY(environment_id,epoch) REFERENCES organization_witness.epochs(environment_id,epoch),
 CHECK((state='committed')=(receipt_sha256 IS NOT NULL))
);

CREATE INDEX creation_reserved_work ON organization_witness.creations(environment_id,epoch,slot,generation,worker_id) WHERE state='reserved';

-- Authority row serializes counters, attempts, history and admission completion.
-- This helper has no service grant. Its event consumes a pre-reserved credit
-- when finishing, so capacity exhaustion cannot strand an existing attempt.
CREATE FUNCTION organization_witness.creation_event(p_environment uuid,p_operation uuid,p_reserving boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE c organization_witness.creations%ROWTYPE; n integer;
BEGIN
 SELECT * INTO STRICT c FROM organization_witness.creations WHERE environment_id=p_environment AND operation_id=p_operation;
 UPDATE organization_witness.creation_counts SET events=events+1,reserved=reserved+CASE WHEN p_reserving THEN 1 ELSE -1 END
  WHERE environment_id=p_environment RETURNING events INTO STRICT n;
 INSERT INTO organization_witness.creation_events(environment_id,sequence,operation_id,attempt,state,epoch,slot,generation,worker_id,principal,receipt_sha256)
 VALUES(c.environment_id,n,c.operation_id,c.attempt,c.state,c.epoch,c.slot,c.generation,c.worker_id,c.principal,c.receipt_sha256);
END $$;

CREATE FUNCTION organization_witness.creation_prepare(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,
 p_kind text,p_selector text,p_actor text,p_payload text,p_subject text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE c organization_witness.creations%ROWTYPE; counts organization_witness.creation_counts%ROWTYPE; new_owner uuid;
BEGIN
 PERFORM organization_witness.history_require_admission(p_environment,p_deployment,p_slot,p_generation,p_epoch,p_worker);
 IF p_kind IS NULL OR p_kind NOT IN ('management_create','management_invite','management_csv','registration','upstream')
  OR p_selector IS NULL OR NOT organization_witness.creation_digest(p_selector)
  OR p_actor IS NULL OR NOT organization_witness.creation_digest(p_actor)
  OR p_payload IS NULL OR NOT organization_witness.creation_digest(p_payload)
  OR (p_subject IS NOT NULL AND NOT organization_witness.history_subject(p_subject))
 THEN RAISE EXCEPTION 'creation input refused'; END IF;
 SELECT * INTO c FROM organization_witness.creations
  WHERE environment_id=p_environment AND kind=p_kind COLLATE "C" AND selector_sha256=p_selector COLLATE "C" FOR UPDATE;
 IF FOUND THEN
  IF c.actor_sha256 IS DISTINCT FROM p_actor OR c.payload_sha256 IS DISTINCT FROM p_payload
   OR c.requested_subject IS DISTINCT FROM p_subject COLLATE "C"
  THEN RAISE EXCEPTION 'creation conflict'; END IF;
  IF c.state='committed' THEN RETURN to_jsonb(c); END IF;
  IF c.epoch IS DISTINCT FROM p_epoch THEN RAISE EXCEPTION 'creation requires epoch reconciliation'; END IF;
  IF c.state='reserved' THEN
   IF ROW(c.slot,c.generation,c.worker_id,c.principal) IS DISTINCT FROM ROW(p_slot,p_generation,p_worker,session_user)
   THEN RAISE EXCEPTION 'creation attempt still reserved'; END IF;
   RETURN to_jsonb(c);
  END IF;
  IF c.attempt>=32 THEN RAISE EXCEPTION 'creation attempts exhausted'; END IF;
 ELSE
  INSERT INTO organization_witness.creation_counts(environment_id) VALUES(p_environment) ON CONFLICT DO NOTHING;
 END IF;
 SELECT * INTO STRICT counts FROM organization_witness.creation_counts WHERE environment_id=p_environment FOR UPDATE;
 IF counts.events::bigint+counts.reserved+2>1000000 THEN RAISE EXCEPTION 'creation event capacity exhausted'; END IF;
 IF c.operation_id IS NULL THEN
  IF counts.operations>=500000 THEN RAISE EXCEPTION 'creation capacity exhausted'; END IF;
  new_owner := gen_random_uuid();
  PERFORM organization_witness.history_reserve(p_environment,p_deployment,p_slot,p_generation,p_epoch,p_worker,new_owner,COALESCE(p_subject,new_owner::text));
  INSERT INTO organization_witness.creations(environment_id,operation_id,kind,selector_sha256,actor_sha256,payload_sha256,requested_subject,
   owner_id,subject,state,attempt,epoch,slot,generation,worker_id,principal)
  VALUES(p_environment,gen_random_uuid(),p_kind,p_selector,p_actor,p_payload,p_subject,new_owner,COALESCE(p_subject,new_owner::text),
   'reserved',1,p_epoch,p_slot,p_generation,p_worker,session_user) RETURNING * INTO c;
  UPDATE organization_witness.creation_counts SET operations=operations+1 WHERE environment_id=p_environment;
 ELSE
  UPDATE organization_witness.creations SET state='reserved',attempt=attempt+1,slot=p_slot,generation=p_generation,worker_id=p_worker,principal=session_user
   WHERE environment_id=p_environment AND operation_id=c.operation_id RETURNING * INTO c;
 END IF;
 PERFORM organization_witness.creation_event(p_environment,c.operation_id,true);
 RETURN to_jsonb(c);
END $$;

-- Finishing already admitted work remains possible after a fence. It never
-- reserves a new attempt and never adopts a different epoch or principal.
CREATE FUNCTION organization_witness.creation_finish(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,
 p_operation uuid,p_attempt integer,p_state text,p_receipt text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; c organization_witness.creations%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase NOT IN ('active','fenced') OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 THEN RAISE EXCEPTION 'creation completion admission refused'; END IF;
 IF p_state IS NULL OR p_state NOT IN ('retryable','committed')
  OR (p_state='retryable' AND p_receipt IS NOT NULL)
  OR (p_state='committed' AND (p_receipt IS NULL OR NOT organization_witness.creation_digest(p_receipt)))
 THEN RAISE EXCEPTION 'creation outcome refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.creations WHERE environment_id=p_environment AND operation_id=p_operation FOR UPDATE;
 IF ROW(c.epoch,c.slot,c.generation,c.worker_id,c.principal,c.attempt)
  IS DISTINCT FROM ROW(p_epoch,p_slot,p_generation,p_worker,session_user,p_attempt)
 THEN RAISE EXCEPTION 'creation attempt mismatch'; END IF;
 IF c.state=p_state AND c.receipt_sha256 IS NOT DISTINCT FROM p_receipt THEN RETURN to_jsonb(c); END IF;
 IF c.state<>'reserved' THEN RAISE EXCEPTION 'creation outcome immutable'; END IF;
 UPDATE organization_witness.creations SET state=p_state,receipt_sha256=p_receipt
  WHERE environment_id=p_environment AND operation_id=p_operation RETURNING * INTO c;
 PERFORM organization_witness.creation_event(p_environment,p_operation,false);
 RETURN to_jsonb(c);
END $$;

CREATE OR REPLACE FUNCTION organization_witness.release(p_environment uuid, p_deployment uuid, p_slot integer, p_generation bigint, p_epoch uuid, p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; s organization_witness.slots%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT s FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot;
 IF p_generation IS NULL OR p_epoch IS NULL OR p_worker IS NULL OR p_generation<=0
  OR s.generation<>p_generation OR s.epoch IS DISTINCT FROM p_epoch OR s.worker_id IS DISTINCT FROM p_worker OR s.principal IS DISTINCT FROM session_user
 THEN RAISE EXCEPTION 'admission completion refused'; END IF;
 IF EXISTS(SELECT FROM organization_witness.creations WHERE environment_id=p_environment AND epoch=p_epoch AND slot=p_slot
  AND generation=p_generation AND worker_id=p_worker AND state='reserved')
 THEN RAISE EXCEPTION 'creation attempt still reserved'; END IF;
 UPDATE organization_witness.slots SET pending=false WHERE environment_id=p_environment AND slot=p_slot;
 RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

REVOKE ALL ON organization_witness.creation_counts,organization_witness.creations,organization_witness.creation_events FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA organization_witness FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.creation_prepare(uuid,uuid,integer,bigint,uuid,uuid,text,text,text,text,text),
 organization_witness.creation_finish(uuid,uuid,integer,bigint,uuid,uuid,uuid,integer,text,text) TO aegaeon_organization_witness_runtime;
COMMIT;
