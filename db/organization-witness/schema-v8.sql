-- Deployment-scoped store continuity and bounded pending inspection.
-- Install after v7 with all writers stopped and parent/children fenced/drained.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 THEN RAISE EXCEPTION 'deployment observation migration requires drained fences'; END IF;
END $$;

-- New child registration locks its explicit parent before any child state.
-- Existing drained children are preserved for explicit deployment adoption.
CREATE OR REPLACE FUNCTION organization_witness.initialize(p_environment uuid, p_deployment uuid, p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
BEGIN
    -- Creation is explicit and never changes an existing authority. Its lost reply
    -- is reconciled through current_state, not an idempotent reinitialization.
    PERFORM 1 FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'matching deployment registration required'; END IF;
    LOCK TABLE organization_witness.authorities IN SHARE ROW EXCLUSIVE MODE;
    IF (SELECT count(*) FROM organization_witness.authorities)>=1024 THEN RAISE EXCEPTION 'environment capacity exhausted'; END IF;
    INSERT INTO organization_witness.authorities(environment_id,deployment_id,revision,phase,operation_id)
        VALUES(p_environment,p_deployment,1,'fenced',p_operation);
    INSERT INTO organization_witness.operations(environment_id,id,fence_from) VALUES(p_environment,p_operation,0);
    INSERT INTO organization_witness.slots(environment_id,slot) SELECT p_environment,n FROM generate_series(0,63) n;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

CREATE TABLE organization_witness.deployment_store_checkpoints (
 deployment_id uuid NOT NULL,
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
 PRIMARY KEY(deployment_id,epoch),
 FOREIGN KEY(deployment_id,epoch) REFERENCES organization_witness.deployment_epochs(deployment_id,epoch),
 FOREIGN KEY(deployment_id,operation_id) REFERENCES organization_witness.deployment_operations(deployment_id,operation_id)
);
CREATE TABLE organization_witness.deployment_store_observations (
 deployment_id uuid NOT NULL,
 slot integer NOT NULL CHECK(slot BETWEEN 0 AND 63),
 generation bigint NOT NULL CHECK(generation>0),
 epoch uuid NOT NULL,
 worker_id uuid NOT NULL,
 principal name NOT NULL,
 minimum_wal numeric(20,0) NOT NULL CHECK(minimum_wal BETWEEN 0 AND 18446744073709551615),
 finished_wal numeric(20,0) CHECK(finished_wal BETWEEN minimum_wal AND 18446744073709551615),
 PRIMARY KEY(deployment_id,slot),
 FOREIGN KEY(deployment_id,epoch) REFERENCES organization_witness.deployment_store_checkpoints(deployment_id,epoch),
 FOREIGN KEY(deployment_id,slot) REFERENCES organization_witness.deployment_slots(deployment_id,slot)
);

CREATE FUNCTION organization_witness.deployment_store_progress_pin(p_deployment uuid,p_operation uuid,p_revision bigint,p_primary jsonb,p_token jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.deployments%ROWTYPE; c organization_witness.deployment_store_checkpoints%ROWTYPE; position numeric;
BEGIN
 IF NOT organization_witness.store_observation_valid(p_primary,p_token) THEN RAISE EXCEPTION 'invalid store observation'; END IF;
 SELECT * INTO STRICT a FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'prepared' OR a.operation_id IS DISTINCT FROM p_operation OR a.revision IS DISTINCT FROM p_revision
  OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 THEN RAISE EXCEPTION 'store pin requires exact drained preparation'; END IF;
 position:=(p_primary->>'wal_position')::numeric;
 SELECT * INTO c FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=a.epoch;
 IF FOUND THEN
  IF c.operation_id IS DISTINCT FROM p_operation OR c.prepared_revision IS DISTINCT FROM p_revision
   OR c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
   OR c.primary_incarnation IS DISTINCT FROM p_primary-'wal_position' OR c.token_incarnation IS DISTINCT FROM p_token
   OR position<c.initial_wal
  THEN RAISE EXCEPTION 'store pin replay conflicts'; END IF;
  RETURN to_jsonb(c);
 END IF;
 INSERT INTO organization_witness.deployment_store_checkpoints VALUES(p_deployment,a.epoch,p_operation,p_revision,
  a.primary_id,a.token_store_id,p_primary-'wal_position',p_token,position,position,session_user) RETURNING * INTO c;
 RETURN to_jsonb(c);
END $$;

CREATE FUNCTION organization_witness.deployment_store_progress_begin(p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.deployments%ROWTYPE; c organization_witness.deployment_store_checkpoints%ROWTYPE; o organization_witness.deployment_store_observations%ROWTYPE;
BEGIN
 SELECT * INTO STRICT a FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF a.phase<>'active' OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 THEN RAISE EXCEPTION 'store observation admission refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=p_epoch;
 IF c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
  OR EXISTS(SELECT FROM organization_witness.deployment_store_observations WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation)
 THEN RAISE EXCEPTION 'store observation already begun or selection differs'; END IF;
 INSERT INTO organization_witness.deployment_store_observations VALUES(p_deployment,p_slot,p_generation,p_epoch,p_worker,session_user,c.wal_position,NULL)
 ON CONFLICT(deployment_id,slot) DO UPDATE SET generation=EXCLUDED.generation,epoch=EXCLUDED.epoch,
  worker_id=EXCLUDED.worker_id,principal=EXCLUDED.principal,minimum_wal=EXCLUDED.minimum_wal,finished_wal=NULL RETURNING * INTO o;
 RETURN jsonb_build_object('checkpoint',to_jsonb(c),'observation',to_jsonb(o));
END $$;

CREATE FUNCTION organization_witness.deployment_store_progress_finish(p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_primary jsonb,p_token jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE a organization_witness.deployments%ROWTYPE; c organization_witness.deployment_store_checkpoints%ROWTYPE; o organization_witness.deployment_store_observations%ROWTYPE; position numeric;
BEGIN
 IF NOT organization_witness.store_observation_valid(p_primary,p_token) THEN RAISE EXCEPTION 'invalid store observation'; END IF;
 SELECT * INTO STRICT a FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF a.phase NOT IN ('active','fenced') OR a.epoch IS DISTINCT FROM p_epoch OR NOT EXISTS(
  SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation
   AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 THEN RAISE EXCEPTION 'store observation completion refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=p_epoch;
 SELECT * INTO STRICT o FROM organization_witness.deployment_store_observations WHERE deployment_id=p_deployment AND slot=p_slot
  AND generation=p_generation AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user;
 position:=(p_primary->>'wal_position')::numeric;
 IF c.primary_id IS DISTINCT FROM a.primary_id OR c.token_store_id IS DISTINCT FROM a.token_store_id
  OR c.primary_incarnation IS DISTINCT FROM p_primary-'wal_position' OR c.token_incarnation IS DISTINCT FROM p_token
  OR position<o.minimum_wal OR (o.finished_wal IS NOT NULL AND o.finished_wal IS DISTINCT FROM position)
 THEN RAISE EXCEPTION 'store progress differs or regressed'; END IF;
 UPDATE organization_witness.deployment_store_checkpoints SET wal_position=greatest(wal_position,position)
  WHERE deployment_id=p_deployment AND epoch=p_epoch RETURNING * INTO c;
 UPDATE organization_witness.deployment_store_observations SET finished_wal=position WHERE deployment_id=p_deployment AND slot=p_slot;
 RETURN jsonb_build_object('checkpoint',to_jsonb(c),'observation',to_jsonb(o)||jsonb_build_object('finished_wal',position));
END $$;

CREATE FUNCTION organization_witness.deployment_pending_work(p_deployment uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; admissions jsonb;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR SHARE;
 SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.slot),'[]'::jsonb) INTO admissions
 FROM organization_witness.deployment_slots s WHERE s.deployment_id=p_deployment AND s.pending;
 RETURN jsonb_build_object('state',to_jsonb(d)||jsonb_build_object('pending',jsonb_array_length(admissions)), 'admissions',admissions);
END $$;

CREATE OR REPLACE FUNCTION organization_witness.deployment_activate(p_deployment uuid,p_operation uuid,p_expected bigint,p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint;
BEGIN
 IF p_operation IS NULL OR p_expected IS NULL OR p_acceptance IS NULL THEN RAISE EXCEPTION 'invalid deployment activation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT activate_from INTO STRICT old_from FROM organization_witness.deployment_operations WHERE deployment_id=p_deployment AND operation_id=p_operation;
 IF d.operation_id=p_operation AND d.phase='active' AND old_from=p_expected AND d.acceptance_sha256=p_acceptance
 THEN RETURN organization_witness.deployment_state(p_deployment); END IF;
 IF d.operation_id<>p_operation OR d.phase<>'prepared' OR d.revision<>p_expected OR d.revision>=9223372036854775806 OR d.acceptance_sha256<>p_acceptance
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 THEN RAISE EXCEPTION 'deployment activation boundary refused'; END IF;
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=d.epoch AND operation_id=p_operation AND prepared_revision=p_expected AND primary_id=d.primary_id AND token_store_id=d.token_store_id) THEN RAISE EXCEPTION 'deployment store checkpoint required'; END IF;
 UPDATE organization_witness.deployment_operations SET activate_from=p_expected,activate_principal=session_user,activated_at=clock_timestamp() WHERE deployment_id=p_deployment AND operation_id=p_operation;
 UPDATE organization_witness.deployments SET phase='active',revision=revision+1 WHERE deployment_id=p_deployment;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

CREATE OR REPLACE FUNCTION organization_witness.deployment_acquire(p_deployment uuid,p_epoch uuid,p_primary uuid,p_token uuid,p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; s organization_witness.deployment_slots%ROWTYPE;
BEGIN
 IF p_epoch IS NULL OR p_primary IS NULL OR p_token IS NULL OR p_worker IS NULL OR p_worker='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid deployment admission'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF d.phase<>'active' OR ROW(d.epoch,d.primary_id,d.token_store_id) IS DISTINCT FROM ROW(p_epoch,p_primary,p_token) THEN RAISE EXCEPTION 'inactive deployment selection'; END IF;
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=p_epoch AND primary_id=p_primary AND token_store_id=p_token) THEN RAISE EXCEPTION 'deployment store checkpoint required'; END IF;
 IF EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND worker_id=p_worker AND pending) THEN RAISE EXCEPTION 'deployment admission already pending'; END IF;
 SELECT * INTO STRICT s FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND NOT pending AND generation<9223372036854775807 ORDER BY slot LIMIT 1;
 UPDATE organization_witness.deployment_slots SET generation=generation+1,pending=true,epoch=p_epoch,worker_id=p_worker,principal=session_user WHERE deployment_id=p_deployment AND slot=s.slot RETURNING * INTO s;
 RETURN to_jsonb(s);
END $$;

CREATE OR REPLACE FUNCTION organization_witness.deployment_release(p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE s organization_witness.deployment_slots%ROWTYPE;
BEGIN
 PERFORM 1 FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT s FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND slot=p_slot FOR UPDATE;
 IF p_generation IS NULL OR p_generation<=0 OR ROW(s.generation,s.epoch,s.worker_id,s.principal) IS DISTINCT FROM ROW(p_generation,p_epoch,p_worker,session_user)
 THEN RAISE EXCEPTION 'deployment completion refused'; END IF;
 IF EXISTS(SELECT FROM organization_witness.deployment_child_slots c JOIN organization_witness.slots child_slot
  ON child_slot.environment_id=c.environment_id AND child_slot.slot=c.child_slot AND child_slot.generation=c.child_generation AND child_slot.pending
  WHERE c.deployment_id=p_deployment AND c.parent_slot=p_slot AND c.parent_generation=p_generation)
 THEN RAISE EXCEPTION 'deployment child still pending'; END IF;
 IF EXISTS(SELECT FROM organization_witness.deployment_store_observations WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation AND finished_wal IS NULL) THEN RAISE EXCEPTION 'deployment store observation unfinished'; END IF;
 UPDATE organization_witness.deployment_slots SET pending=false WHERE deployment_id=p_deployment AND slot=p_slot;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

REVOKE ALL ON TABLE organization_witness.deployment_store_checkpoints,organization_witness.deployment_store_observations FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_witness.deployment_store_progress_pin(uuid,uuid,bigint,jsonb,jsonb),
 organization_witness.deployment_store_progress_begin(uuid,integer,bigint,uuid,uuid),
 organization_witness.deployment_store_progress_finish(uuid,integer,bigint,uuid,uuid,jsonb,jsonb),
 organization_witness.deployment_pending_work(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.deployment_store_progress_pin(uuid,uuid,bigint,jsonb,jsonb),
 organization_witness.deployment_pending_work(uuid) TO aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.deployment_store_progress_begin(uuid,integer,bigint,uuid,uuid),
 organization_witness.deployment_store_progress_finish(uuid,integer,bigint,uuid,uuid,jsonb,jsonb) TO aegaeon_organization_witness_runtime;
COMMIT;
