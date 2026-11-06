-- Retain post-work seals before admitting a new physical store incarnation.
-- Old checkpoints and observations are preserved by the restart journal.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities,
 organization_witness.cutover_operations IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.cutover_operations WHERE NOT completed AND NOT aborted)
 THEN RAISE EXCEPTION 'store continuity migration requires drained fenced state'; END IF;
END $$;

CREATE TABLE organization_witness.deployment_store_seals (
 deployment_id uuid NOT NULL,
 epoch uuid NOT NULL,
 seal uuid NOT NULL CHECK(seal<>'00000000-0000-0000-0000-000000000000'),
 restart_generation integer NOT NULL DEFAULT 0 CHECK(restart_generation BETWEEN 0 AND 65536),
 PRIMARY KEY(deployment_id,epoch),
 FOREIGN KEY(deployment_id,epoch) REFERENCES organization_witness.deployment_store_checkpoints(deployment_id,epoch)
);
CREATE TABLE organization_witness.deployment_store_restarts (
 deployment_id uuid NOT NULL,
 epoch uuid NOT NULL,
 generation integer NOT NULL CHECK(generation BETWEEN 1 AND 65536),
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 seal uuid NOT NULL,
 previous_checkpoints jsonb NOT NULL CHECK(octet_length(previous_checkpoints::text)<=2097152),
 primary_observation jsonb NOT NULL,
 token_observation jsonb NOT NULL,
 principal name NOT NULL,
 PRIMARY KEY(deployment_id,epoch,generation),
 UNIQUE(deployment_id,operation_id),
 FOREIGN KEY(deployment_id,epoch) REFERENCES organization_witness.deployment_store_seals(deployment_id,epoch)
);
CREATE TABLE organization_witness.deployment_store_completions (
 deployment_id uuid NOT NULL,
 slot integer NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 epoch uuid NOT NULL,
 worker_id uuid NOT NULL,
 principal name NOT NULL,
 seal uuid NOT NULL,
 PRIMARY KEY(deployment_id,slot),
 FOREIGN KEY(deployment_id,slot) REFERENCES organization_witness.deployment_slots(deployment_id,slot),
 FOREIGN KEY(deployment_id,epoch) REFERENCES organization_witness.deployment_store_seals(deployment_id,epoch)
);
REVOKE ALL ON organization_witness.deployment_store_seals,
 organization_witness.deployment_store_restarts,organization_witness.deployment_store_completions FROM PUBLIC;

-- Pinning may run inside the existing complete cutover transaction. It never
-- commits that caller's transaction or changes an active deployment.
CREATE FUNCTION organization_witness.deployment_store_seal_preparation(
 p_deployment uuid,p_operation uuid,p_revision bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; s organization_witness.deployment_store_seals%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF d.phase<>'prepared' OR d.operation_id IS DISTINCT FROM p_operation OR d.revision IS DISTINCT FROM p_revision
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 OR EXISTS(SELECT FROM organization_witness.slots child_slot JOIN organization_witness.authorities a USING(environment_id)
  WHERE a.deployment_id=p_deployment AND child_slot.pending)
 OR NOT EXISTS(SELECT FROM organization_witness.deployment_store_checkpoints c
  WHERE c.deployment_id=p_deployment AND c.epoch=d.epoch AND c.operation_id=p_operation
   AND c.prepared_revision=p_revision AND c.primary_id=d.primary_id AND c.token_store_id=d.token_store_id)
 THEN RAISE EXCEPTION 'seal requires exact drained preparation'; END IF;
 SELECT * INTO s FROM organization_witness.deployment_store_seals WHERE deployment_id=p_deployment AND epoch=d.epoch;
 RETURN jsonb_build_object('epoch',d.epoch,'seal',s.seal);
END $$;

CREATE FUNCTION organization_witness.deployment_store_seal_pin(
 p_deployment uuid,p_operation uuid,p_revision bigint,p_seal uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE prepared jsonb;
BEGIN
 IF p_seal IS NULL OR p_seal='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid seal'; END IF;
 prepared:=organization_witness.deployment_store_seal_preparation(p_deployment,p_operation,p_revision);
 IF prepared->>'seal' IS NOT NULL THEN
  IF (prepared->>'seal')::uuid<>p_seal THEN RAISE EXCEPTION 'seal preparation replay differs'; END IF;
 ELSE
  INSERT INTO organization_witness.deployment_store_seals(deployment_id,epoch,seal)
   VALUES(p_deployment,(prepared->>'epoch')::uuid,p_seal);
 END IF;
 RETURN jsonb_build_object('epoch',prepared->'epoch','seal',p_seal);
END $$;

-- This read-only snapshot precedes acquisition. The actual acquisition and
-- observation still read current state; it is not a serving capability.
CREATE FUNCTION organization_witness.deployment_store_continuity(p_deployment uuid,p_selection jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; c organization_witness.deployment_store_checkpoints%ROWTYPE;
 s organization_witness.deployment_store_seals%ROWTYPE; selected jsonb;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment;
 selected:=jsonb_build_object('epoch',d.epoch,'primary',d.primary_id,'token_store',d.token_store_id,
  'source_sha256',d.source_sha256,'history_sha256',d.history_sha256,'acceptance_sha256',d.acceptance_sha256);
 IF d.phase<>'active' OR p_selection IS DISTINCT FROM selected THEN RAISE EXCEPTION 'continuity selection refused'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=d.epoch;
 SELECT * INTO STRICT s FROM organization_witness.deployment_store_seals WHERE deployment_id=p_deployment AND epoch=d.epoch;
 IF ROW(c.primary_id,c.token_store_id) IS DISTINCT FROM ROW(d.primary_id,d.token_store_id)
 THEN RAISE EXCEPTION 'continuity checkpoint differs'; END IF;
 RETURN jsonb_build_object('deployment_id',p_deployment,'selection',selected,'seal',s.seal,
  'restart_generation',s.restart_generation,'primary_incarnation',c.primary_incarnation,
  'token_incarnation',c.token_incarnation,'minimum_wal',c.wal_position);
END $$;

-- The caller keeps this row lock through actual seal writes, observation,
-- checkpoint advancement and release in ONE control transaction.
CREATE FUNCTION organization_witness.deployment_store_seal_lock(
 p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; result uuid;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF d.phase NOT IN ('active','fenced') OR d.epoch IS DISTINCT FROM p_epoch
 OR NOT EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND slot=p_slot
  AND generation=p_generation AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_child_slots link
  JOIN organization_witness.slots child ON child.environment_id=link.environment_id
   AND child.slot=link.child_slot AND child.generation=link.child_generation
  WHERE link.deployment_id=p_deployment AND link.parent_slot=p_slot AND link.parent_generation=p_generation AND child.pending)
 THEN RAISE EXCEPTION 'seal completion owner refused'; END IF;
 SELECT seal INTO STRICT result FROM organization_witness.deployment_store_seals WHERE deployment_id=p_deployment AND epoch=p_epoch;
 RETURN result;
END $$;

CREATE FUNCTION organization_witness.deployment_store_seal_advance(
 p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_previous uuid,p_next uuid)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
BEGIN
 IF p_previous IS DISTINCT FROM organization_witness.deployment_store_seal_lock(p_deployment,p_slot,p_generation,p_epoch,p_worker)
 OR p_next IS NULL OR p_next='00000000-0000-0000-0000-000000000000' OR p_next=p_previous
 OR NOT EXISTS(SELECT FROM organization_witness.deployment_store_observations WHERE deployment_id=p_deployment AND slot=p_slot
  AND generation=p_generation AND epoch=p_epoch AND worker_id=p_worker AND principal=session_user AND finished_wal IS NOT NULL)
 THEN RAISE EXCEPTION 'seal advancement refused'; END IF;
 UPDATE organization_witness.deployment_store_seals SET seal=p_next WHERE deployment_id=p_deployment AND epoch=p_epoch;
 INSERT INTO organization_witness.deployment_store_completions VALUES(p_deployment,p_slot,p_generation,p_epoch,p_worker,session_user,p_next)
 ON CONFLICT(deployment_id,slot) DO UPDATE SET generation=excluded.generation,epoch=excluded.epoch,
  worker_id=excluded.worker_id,principal=excluded.principal,seal=excluded.seal;
 RETURN p_next;
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
 IF EXISTS(SELECT FROM organization_witness.deployment_store_observations
  WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation)
 AND NOT EXISTS(SELECT FROM organization_witness.deployment_store_completions
  WHERE deployment_id=p_deployment AND slot=p_slot AND generation=p_generation AND epoch=p_epoch
   AND worker_id=p_worker AND principal=session_user)
 THEN RAISE EXCEPTION 'deployment durable seal completion required'; END IF;
 UPDATE organization_witness.deployment_slots SET pending=false WHERE deployment_id=p_deployment AND slot=p_slot;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

-- An incomplete preparation is neither active nor a source of pending work.
-- Keep the existing lifecycle/replay contract and require its exact epoch seal.
CREATE OR REPLACE FUNCTION organization_witness.deployment_activate(p_deployment uuid,p_operation uuid,p_expected bigint,p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint;
BEGIN
 IF p_operation IS NULL OR p_expected IS NULL OR p_acceptance IS NULL THEN RAISE EXCEPTION 'invalid deployment activation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending) THEN RAISE EXCEPTION 'maintenance still pending'; END IF;
 SELECT activate_from INTO STRICT old_from FROM organization_witness.deployment_operations WHERE deployment_id=p_deployment AND operation_id=p_operation;
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_store_seals WHERE deployment_id=p_deployment AND epoch=d.epoch)
 THEN RAISE EXCEPTION 'deployment durable seal required'; END IF;
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
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_store_seals WHERE deployment_id=p_deployment AND epoch=p_epoch)
 THEN RAISE EXCEPTION 'deployment durable seal required'; END IF;
 IF EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND worker_id=p_worker AND pending) THEN RAISE EXCEPTION 'deployment admission already pending'; END IF;
 SELECT * INTO STRICT s FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND NOT pending AND generation<9223372036854775807 ORDER BY slot LIMIT 1;
 UPDATE organization_witness.deployment_slots SET generation=generation+1,pending=true,epoch=p_epoch,worker_id=p_worker,principal=session_user WHERE deployment_id=p_deployment AND slot=s.slot RETURNING * INTO s;
 RETURN to_jsonb(s);
END $$;

-- The independent lock excludes both new admissions and other restart/finalize
-- operations while the caller compares actual durable seals. No data seal is
-- ever rewritten by restart acceptance.
CREATE FUNCTION organization_witness.deployment_store_restart_lock(
 p_deployment uuid,p_selection jsonb,p_primary jsonb,p_token jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; c organization_witness.deployment_store_checkpoints%ROWTYPE;
 current jsonb; position numeric;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 PERFORM 1 FROM organization_witness.authorities WHERE deployment_id=p_deployment ORDER BY environment_id FOR UPDATE;
 current:=organization_witness.deployment_store_continuity(p_deployment,p_selection);
 IF NOT organization_witness.store_observation_valid(p_primary,p_token)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 OR EXISTS(SELECT FROM organization_witness.slots s JOIN organization_witness.authorities a USING(environment_id)
  WHERE a.deployment_id=p_deployment AND s.pending)
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)
 THEN RAISE EXCEPTION USING ERRCODE='P0R01',MESSAGE='restart requires drained store owners'; END IF;
 SELECT * INTO STRICT c FROM organization_witness.deployment_store_checkpoints WHERE deployment_id=p_deployment AND epoch=d.epoch;
 position:=(p_primary->>'wal_position')::numeric;
 IF p_primary-ARRAY['started_us','wal_position'] IS DISTINCT FROM c.primary_incarnation-'started_us'
 OR p_token->'database' IS DISTINCT FROM c.token_incarnation->'database' OR position<c.wal_position
 OR EXISTS(SELECT FROM organization_witness.authorities a WHERE a.deployment_id=p_deployment AND a.phase='active'
  AND NOT EXISTS(SELECT FROM organization_witness.deployment_children b WHERE b.deployment_id=p_deployment
   AND b.deployment_epoch=d.epoch AND b.environment_id=a.environment_id AND b.child_epoch=a.epoch))
 OR EXISTS(SELECT FROM organization_witness.deployment_children b
  LEFT JOIN organization_witness.authorities a ON a.environment_id=b.environment_id
  LEFT JOIN organization_witness.store_checkpoints child ON child.environment_id=b.environment_id AND child.epoch=b.child_epoch
  WHERE b.deployment_id=p_deployment AND b.deployment_epoch=d.epoch AND
   (a.epoch IS DISTINCT FROM b.child_epoch OR ROW(a.primary_id,a.token_store_id) IS DISTINCT FROM ROW(d.primary_id,d.token_store_id)
    OR child.primary_incarnation IS DISTINCT FROM c.primary_incarnation OR child.token_incarnation IS DISTINCT FROM c.token_incarnation
    OR child.wal_position IS NULL OR position<child.wal_position))
 THEN RAISE EXCEPTION 'restart store identity or progress differs'; END IF;
 RETURN current;
END $$;

CREATE FUNCTION organization_witness.deployment_store_restart_finish(
 p_deployment uuid,p_selection jsonb,p_primary jsonb,p_token jsonb,p_seal uuid,p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE current jsonb; before jsonb; next_generation integer; selected_epoch uuid;
BEGIN
 current:=organization_witness.deployment_store_restart_lock(p_deployment,p_selection,p_primary,p_token);
 IF p_seal IS DISTINCT FROM (current->>'seal')::uuid OR p_operation IS NULL
 OR p_operation='00000000-0000-0000-0000-000000000000'
 THEN RAISE EXCEPTION 'restart seal differs'; END IF;
 IF p_primary-'wal_position'=current->'primary_incarnation' AND p_token=current->'token_incarnation'
 THEN RETURN current; END IF;
 next_generation:=(current->>'restart_generation')::integer+1;
 IF next_generation>65536 THEN RAISE EXCEPTION 'restart history capacity exhausted'; END IF;
 selected_epoch:=(p_selection->>'epoch')::uuid;
 SELECT jsonb_build_object('parent',to_jsonb(c),'children',COALESCE((
  SELECT jsonb_agg(to_jsonb(child) ORDER BY child.environment_id) FROM organization_witness.deployment_children b
  JOIN organization_witness.store_checkpoints child ON child.environment_id=b.environment_id AND child.epoch=b.child_epoch
  WHERE b.deployment_id=p_deployment AND b.deployment_epoch=selected_epoch),'[]'::jsonb)) INTO STRICT before
  FROM organization_witness.deployment_store_checkpoints c WHERE c.deployment_id=p_deployment AND c.epoch=selected_epoch;
 INSERT INTO organization_witness.deployment_store_restarts VALUES(p_deployment,selected_epoch,next_generation,p_operation,
  p_seal,before,p_primary,p_token,session_user);
 UPDATE organization_witness.deployment_store_checkpoints SET primary_incarnation=p_primary-'wal_position',token_incarnation=p_token,
  wal_position=greatest(wal_position,(p_primary->>'wal_position')::numeric)
  WHERE deployment_id=p_deployment AND epoch=selected_epoch;
 UPDATE organization_witness.store_checkpoints child SET primary_incarnation=p_primary-'wal_position',token_incarnation=p_token,
  wal_position=greatest(child.wal_position,(p_primary->>'wal_position')::numeric)
  FROM organization_witness.deployment_children b WHERE b.deployment_id=p_deployment AND b.deployment_epoch=selected_epoch
   AND child.environment_id=b.environment_id AND child.epoch=b.child_epoch;
 UPDATE organization_witness.deployment_store_seals SET restart_generation=next_generation
  WHERE deployment_id=p_deployment AND epoch=selected_epoch;
 RETURN organization_witness.deployment_store_continuity(p_deployment,p_selection);
END $$;

REVOKE ALL ON FUNCTION
 organization_witness.deployment_store_seal_preparation(uuid,uuid,bigint),
 organization_witness.deployment_store_seal_pin(uuid,uuid,bigint,uuid),
 organization_witness.deployment_store_continuity(uuid,jsonb),
 organization_witness.deployment_store_seal_lock(uuid,integer,bigint,uuid,uuid),
 organization_witness.deployment_store_seal_advance(uuid,integer,bigint,uuid,uuid,uuid,uuid),
 organization_witness.deployment_store_restart_lock(uuid,jsonb,jsonb,jsonb),
 organization_witness.deployment_store_restart_finish(uuid,jsonb,jsonb,jsonb,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 organization_witness.deployment_store_seal_preparation(uuid,uuid,bigint),
 organization_witness.deployment_store_seal_pin(uuid,uuid,bigint,uuid) TO aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION
 organization_witness.deployment_store_continuity(uuid,jsonb),
 organization_witness.deployment_store_seal_lock(uuid,integer,bigint,uuid,uuid),
 organization_witness.deployment_store_seal_advance(uuid,integer,bigint,uuid,uuid,uuid,uuid),
 organization_witness.deployment_store_restart_lock(uuid,jsonb,jsonb,jsonb),
 organization_witness.deployment_store_restart_finish(uuid,jsonb,jsonb,jsonb,uuid,uuid) TO aegaeon_organization_witness_runtime;
COMMIT;
