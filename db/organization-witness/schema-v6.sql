-- Retained store observations, not supplier qualification or serving admission.
-- Apply after v1-v5 with service writers stopped. Earlier records remain intact.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;

CREATE FUNCTION organization_witness.store_observation_valid(p_primary jsonb,p_token jsonb)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT COALESCE(jsonb_typeof(p_primary)='object' AND jsonb_typeof(p_token)='object'
  AND octet_length(p_primary::text)<=1024 AND octet_length(p_token::text)<=256
  AND p_primary-ARRAY['cluster_id','database_oid','database_name','started_us','timeline','wal_position']='{}'::jsonb
  AND p_token-ARRAY['run_id','database']='{}'::jsonb
  AND jsonb_typeof(p_primary->'cluster_id')='number'
  AND p_primary->>'cluster_id' ~ '^-?[1-9][0-9]{0,18}$'
  AND (p_primary->>'cluster_id')::numeric BETWEEN -9223372036854775808 AND 9223372036854775807
  AND jsonb_typeof(p_primary->'database_oid')='number'
  AND p_primary->>'database_oid' ~ '^[1-9][0-9]{0,9}$'
  AND (p_primary->>'database_oid')::numeric BETWEEN 1 AND 4294967295
  AND jsonb_typeof(p_primary->'database_name')='string'
  AND octet_length(p_primary->>'database_name') BETWEEN 1 AND 63
  AND jsonb_typeof(p_primary->'started_us')='number'
  AND p_primary->>'started_us' ~ '^[1-9][0-9]{0,18}$'
  AND (p_primary->>'started_us')::numeric BETWEEN 1 AND 9223372036854775807
  AND jsonb_typeof(p_primary->'timeline')='number'
  AND p_primary->>'timeline' ~ '^[1-9][0-9]{0,9}$'
  AND (p_primary->>'timeline')::numeric BETWEEN 1 AND 4294967295
  AND jsonb_typeof(p_primary->'wal_position')='number'
  AND p_primary->>'wal_position' ~ '^(0|[1-9][0-9]{0,19})$'
  AND (p_primary->>'wal_position')::numeric BETWEEN 0 AND 18446744073709551615
  AND jsonb_typeof(p_token->'run_id')='string'
  AND p_token->>'run_id' COLLATE "C" ~ '^[0-9a-f]{40}$'
  AND jsonb_typeof(p_token->'database')='number'
  AND p_token->>'database' ~ '^(0|[1-9][0-9]{0,9})$'
  AND (p_token->>'database')::numeric BETWEEN 0 AND 4294967295,false)
$$;

CREATE TABLE organization_witness.store_checkpoints (
 environment_id uuid NOT NULL,
 epoch uuid NOT NULL,
 operation_id uuid NOT NULL,
 prepared_revision bigint NOT NULL CHECK(prepared_revision>0),
 primary_id uuid NOT NULL,
 token_store_id uuid NOT NULL,
 primary_incarnation jsonb NOT NULL,
 token_incarnation jsonb NOT NULL,
 initial_wal numeric(20,0) NOT NULL CHECK(initial_wal BETWEEN 0 AND 18446744073709551615),
 wal_position numeric(20,0) NOT NULL CHECK(wal_position BETWEEN initial_wal AND 18446744073709551615),
 principal name NOT NULL,
 PRIMARY KEY(environment_id,epoch),
 FOREIGN KEY(environment_id,epoch) REFERENCES organization_witness.epochs(environment_id,epoch),
 FOREIGN KEY(environment_id,operation_id) REFERENCES organization_witness.operations(environment_id,id)
);
CREATE TABLE organization_witness.store_observations (
 environment_id uuid NOT NULL,
 slot integer NOT NULL CHECK(slot BETWEEN 0 AND 63),
 generation bigint NOT NULL CHECK(generation>0),
 epoch uuid NOT NULL,
 worker_id uuid NOT NULL,
 principal name NOT NULL,
 minimum_wal numeric(20,0) NOT NULL CHECK(minimum_wal BETWEEN 0 AND 18446744073709551615),
 finished_wal numeric(20,0) CHECK(finished_wal BETWEEN minimum_wal AND 18446744073709551615),
 PRIMARY KEY(environment_id,slot),
 FOREIGN KEY(environment_id,epoch) REFERENCES organization_witness.store_checkpoints(environment_id,epoch),
 FOREIGN KEY(environment_id,slot) REFERENCES organization_witness.slots(environment_id,slot)
);

CREATE FUNCTION organization_witness.store_progress_pin(p_environment uuid,p_deployment uuid,p_operation uuid,p_revision bigint,p_primary jsonb,p_token jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; c organization_witness.store_checkpoints%ROWTYPE; position numeric;
BEGIN
 IF NOT organization_witness.store_observation_valid(p_primary,p_token) THEN RAISE EXCEPTION 'invalid store observation'; END IF;
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'prepared' OR a.operation_id IS DISTINCT FROM p_operation OR a.revision IS DISTINCT FROM p_revision
  OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND pending)
 THEN RAISE EXCEPTION 'store pin requires exact drained preparation'; END IF;
 position:=(p_primary->>'wal_position')::numeric;
 SELECT * INTO c FROM organization_witness.store_checkpoints WHERE environment_id=p_environment AND epoch=a.epoch;
 IF FOUND THEN
  IF c.operation_id IS DISTINCT FROM p_operation OR c.prepared_revision IS DISTINCT FROM p_revision
   OR c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
   OR c.primary_incarnation IS DISTINCT FROM p_primary-'wal_position' OR c.token_incarnation IS DISTINCT FROM p_token
   OR position<c.initial_wal
  THEN RAISE EXCEPTION 'store pin replay conflicts'; END IF;
  RETURN to_jsonb(c);
 END IF;
 INSERT INTO organization_witness.store_checkpoints VALUES(p_environment,a.epoch,p_operation,p_revision,
  a.primary_id,a.token_store_id,p_primary-'wal_position',p_token,position,position,session_user) RETURNING * INTO c;
 RETURN to_jsonb(c);
END $$;

CREATE FUNCTION organization_witness.store_progress_begin(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; c organization_witness.store_checkpoints%ROWTYPE; o organization_witness.store_observations%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'active' OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 THEN RAISE EXCEPTION 'store observation admission refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.store_checkpoints WHERE environment_id=p_environment AND epoch=p_epoch;
 IF c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
  OR EXISTS(SELECT FROM organization_witness.store_observations WHERE environment_id=p_environment AND slot=p_slot AND generation=p_generation)
 THEN RAISE EXCEPTION 'store observation already begun or selection differs'; END IF;
 INSERT INTO organization_witness.store_observations VALUES(p_environment,p_slot,p_generation,p_epoch,p_worker,session_user,c.wal_position,NULL)
 ON CONFLICT(environment_id,slot) DO UPDATE SET generation=EXCLUDED.generation,epoch=EXCLUDED.epoch,
  worker_id=EXCLUDED.worker_id,principal=EXCLUDED.principal,minimum_wal=EXCLUDED.minimum_wal,finished_wal=NULL RETURNING * INTO o;
 RETURN jsonb_build_object('checkpoint',to_jsonb(c),'observation',to_jsonb(o));
END $$;

CREATE FUNCTION organization_witness.store_progress_finish(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_primary jsonb,p_token jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; c organization_witness.store_checkpoints%ROWTYPE; o organization_witness.store_observations%ROWTYPE; position numeric;
BEGIN
 IF NOT organization_witness.store_observation_valid(p_primary,p_token) THEN RAISE EXCEPTION 'invalid store observation'; END IF;
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF a.phase NOT IN ('active','fenced') OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 THEN RAISE EXCEPTION 'store observation completion refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.store_checkpoints WHERE environment_id=p_environment AND epoch=p_epoch;
 SELECT * INTO STRICT o FROM organization_witness.store_observations WHERE environment_id=p_environment AND slot=p_slot
  AND generation=p_generation AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user;
 position:=(p_primary->>'wal_position')::numeric;
 IF c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
  OR c.primary_incarnation IS DISTINCT FROM p_primary-'wal_position' OR c.token_incarnation IS DISTINCT FROM p_token
  OR position<o.minimum_wal OR (o.finished_wal IS NOT NULL AND o.finished_wal IS DISTINCT FROM position)
 THEN RAISE EXCEPTION 'store progress differs or regressed'; END IF;
 UPDATE organization_witness.store_checkpoints SET wal_position=greatest(wal_position,position)
  WHERE environment_id=p_environment AND epoch=p_epoch RETURNING * INTO c;
 UPDATE organization_witness.store_observations SET finished_wal=position WHERE environment_id=p_environment AND slot=p_slot;
 RETURN jsonb_build_object('checkpoint',to_jsonb(c),'observation',to_jsonb(o)||jsonb_build_object('finished_wal',position));
END $$;

REVOKE ALL ON TABLE organization_witness.store_checkpoints,organization_witness.store_observations FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_witness.store_observation_valid(jsonb,jsonb),
 organization_witness.store_progress_pin(uuid,uuid,uuid,bigint,jsonb,jsonb),
 organization_witness.store_progress_begin(uuid,uuid,integer,bigint,uuid,uuid),
 organization_witness.store_progress_finish(uuid,uuid,integer,bigint,uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.store_progress_pin(uuid,uuid,uuid,bigint,jsonb,jsonb) TO aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.store_progress_begin(uuid,uuid,integer,bigint,uuid,uuid),
 organization_witness.store_progress_finish(uuid,uuid,integer,bigint,uuid,uuid,jsonb,jsonb) TO aegaeon_organization_witness_runtime;
COMMIT;
