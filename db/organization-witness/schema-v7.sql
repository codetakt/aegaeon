-- Deployment ownership precedes Environment ownership. Install after v1-v6
-- with every writer stopped and every existing child fenced and drained.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 THEN RAISE EXCEPTION 'deployment migration requires drained child fences'; END IF;
 IF (SELECT count(DISTINCT deployment_id) FROM organization_witness.authorities)>1
 THEN RAISE EXCEPTION 'deployment migration requires one existing deployment'; END IF;
END $$;

CREATE TABLE organization_witness.deployments (
 singleton boolean NOT NULL DEFAULT true CHECK(singleton) UNIQUE,
 deployment_id uuid PRIMARY KEY CHECK(deployment_id<>'00000000-0000-0000-0000-000000000000'),
 revision bigint NOT NULL CHECK(revision>0),
 phase text NOT NULL CHECK(phase IN ('fenced','prepared','active')),
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 epoch uuid, primary_id uuid, token_store_id uuid,
 source_sha256 text, history_sha256 text, acceptance_sha256 text,
 CHECK(phase='fenced' OR (epoch IS NOT NULL AND primary_id IS NOT NULL AND token_store_id IS NOT NULL
  AND source_sha256 IS NOT NULL AND history_sha256 IS NOT NULL AND acceptance_sha256 IS NOT NULL))
);
CREATE TABLE organization_witness.deployment_operations (
 deployment_id uuid NOT NULL REFERENCES organization_witness.deployments(deployment_id),
 operation_id uuid NOT NULL, fence_from bigint NOT NULL CHECK(fence_from>=0),
 prepare_from bigint, activate_from bigint,
 fence_principal name NOT NULL DEFAULT session_user, prepare_principal name, activate_principal name,
 fenced_at timestamptz NOT NULL DEFAULT clock_timestamp(), prepared_at timestamptz, activated_at timestamptz,
 PRIMARY KEY(deployment_id,operation_id)
);
CREATE TABLE organization_witness.deployment_epochs (
 deployment_id uuid NOT NULL REFERENCES organization_witness.deployments(deployment_id),
 epoch uuid NOT NULL, operation_id uuid NOT NULL,
 PRIMARY KEY(deployment_id,epoch),
 FOREIGN KEY(deployment_id,operation_id) REFERENCES organization_witness.deployment_operations(deployment_id,operation_id)
);
CREATE TABLE organization_witness.deployment_slots (
 deployment_id uuid NOT NULL REFERENCES organization_witness.deployments(deployment_id),
 slot integer NOT NULL CHECK(slot BETWEEN 0 AND 63),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0), pending boolean NOT NULL DEFAULT false,
 epoch uuid, worker_id uuid, principal name,
 PRIMARY KEY(deployment_id,slot),
 CHECK(NOT pending OR (generation>0 AND epoch IS NOT NULL AND worker_id IS NOT NULL AND principal IS NOT NULL))
);
CREATE TABLE organization_witness.deployment_children (
 environment_id uuid NOT NULL, child_epoch uuid NOT NULL,
 deployment_id uuid NOT NULL, deployment_epoch uuid NOT NULL,
 principal name NOT NULL DEFAULT session_user, bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment_id,child_epoch),
 FOREIGN KEY(environment_id,child_epoch) REFERENCES organization_witness.epochs(environment_id,epoch),
 FOREIGN KEY(deployment_id,deployment_epoch) REFERENCES organization_witness.deployment_epochs(deployment_id,epoch)
);
CREATE TABLE organization_witness.deployment_child_slots (
 environment_id uuid NOT NULL, child_slot integer NOT NULL, child_generation bigint NOT NULL CHECK(child_generation>0),
 deployment_id uuid NOT NULL, parent_slot integer NOT NULL, parent_generation bigint NOT NULL CHECK(parent_generation>0),
 PRIMARY KEY(environment_id,child_slot),
 FOREIGN KEY(environment_id,child_slot) REFERENCES organization_witness.slots(environment_id,slot),
 FOREIGN KEY(deployment_id,parent_slot) REFERENCES organization_witness.deployment_slots(deployment_id,slot)
);

CREATE FUNCTION organization_witness.deployment_state(p_deployment uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; n integer;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR SHARE;
 SELECT count(*) INTO n FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending;
 RETURN to_jsonb(d)||jsonb_build_object('pending',n);
END $$;

CREATE FUNCTION organization_witness.deployment_initialize(p_deployment uuid,p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
BEGIN
 LOCK TABLE organization_witness.deployments IN SHARE ROW EXCLUSIVE MODE;
 IF EXISTS(SELECT FROM organization_witness.authorities WHERE deployment_id IS DISTINCT FROM p_deployment)
 THEN RAISE EXCEPTION 'deployment conflicts with existing child ownership'; END IF;
 INSERT INTO organization_witness.deployments(deployment_id,revision,phase,operation_id) VALUES(p_deployment,1,'fenced',p_operation);
 INSERT INTO organization_witness.deployment_operations(deployment_id,operation_id,fence_from) VALUES(p_deployment,p_operation,0);
 INSERT INTO organization_witness.deployment_slots(deployment_id,slot) SELECT p_deployment,n FROM generate_series(0,63) n;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

CREATE FUNCTION organization_witness.deployment_fence(p_deployment uuid,p_operation uuid,p_expected bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint; terminal boolean;
BEGIN
 IF p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid operation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT fence_from INTO old_from FROM organization_witness.deployment_operations WHERE deployment_id=p_deployment AND operation_id=p_operation;
 IF FOUND THEN
  IF d.operation_id=p_operation AND d.phase='fenced' AND old_from=p_expected THEN RETURN organization_witness.deployment_state(p_deployment); END IF;
  RAISE EXCEPTION 'conflicting deployment fence replay';
 END IF;
 IF p_expected IS NULL OR d.revision<>p_expected OR d.revision=9223372036854775807 THEN RAISE EXCEPTION 'deployment fence revision refused'; END IF;
 terminal := (SELECT count(*) FROM organization_witness.deployment_operations WHERE deployment_id=p_deployment)>=65536;
 INSERT INTO organization_witness.deployment_operations(deployment_id,operation_id,fence_from) VALUES(p_deployment,p_operation,p_expected);
 UPDATE organization_witness.deployments SET phase='fenced',operation_id=p_operation,revision=CASE WHEN terminal THEN 9223372036854775807 ELSE revision+1 END WHERE deployment_id=p_deployment;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

CREATE FUNCTION organization_witness.deployment_prepare(p_deployment uuid,p_operation uuid,p_expected bigint,
 p_epoch uuid,p_primary uuid,p_token uuid,p_source text,p_history text,p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint;
BEGIN
 IF p_operation IS NULL OR p_expected IS NULL OR p_epoch IS NULL OR p_primary IS NULL OR p_token IS NULL
 OR p_epoch='00000000-0000-0000-0000-000000000000' OR p_primary='00000000-0000-0000-0000-000000000000' OR p_token='00000000-0000-0000-0000-000000000000'
 OR NOT organization_witness.creation_digest(p_source) OR NOT organization_witness.creation_digest(p_history) OR NOT organization_witness.creation_digest(p_acceptance)
 THEN RAISE EXCEPTION 'invalid deployment preparation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT prepare_from INTO STRICT old_from FROM organization_witness.deployment_operations WHERE deployment_id=p_deployment AND operation_id=p_operation;
 IF d.operation_id=p_operation AND d.phase='prepared' AND old_from=p_expected
 AND ROW(d.epoch,d.primary_id,d.token_store_id,d.source_sha256,d.history_sha256,d.acceptance_sha256)
  IS NOT DISTINCT FROM ROW(p_epoch,p_primary,p_token,p_source,p_history,p_acceptance)
 THEN RETURN organization_witness.deployment_state(p_deployment); END IF;
 IF d.operation_id<>p_operation OR d.phase<>'fenced' OR d.revision<>p_expected OR d.revision>=9223372036854775806
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE deployment_id=p_deployment AND phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.slots s JOIN organization_witness.authorities a USING(environment_id) WHERE a.deployment_id=p_deployment AND s.pending)
 THEN RAISE EXCEPTION 'deployment preparation boundary refused'; END IF;
 INSERT INTO organization_witness.deployment_epochs(deployment_id,epoch,operation_id) VALUES(p_deployment,p_epoch,p_operation);
 UPDATE organization_witness.deployment_operations SET prepare_from=p_expected,prepare_principal=session_user,prepared_at=clock_timestamp() WHERE deployment_id=p_deployment AND operation_id=p_operation;
 UPDATE organization_witness.deployments SET phase='prepared',revision=revision+1,epoch=p_epoch,primary_id=p_primary,token_store_id=p_token,
 source_sha256=p_source,history_sha256=p_history,acceptance_sha256=p_acceptance WHERE deployment_id=p_deployment;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

CREATE FUNCTION organization_witness.deployment_activate(p_deployment uuid,p_operation uuid,p_expected bigint,p_acceptance text)
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
 UPDATE organization_witness.deployment_operations SET activate_from=p_expected,activate_principal=session_user,activated_at=clock_timestamp() WHERE deployment_id=p_deployment AND operation_id=p_operation;
 UPDATE organization_witness.deployments SET phase='active',revision=revision+1 WHERE deployment_id=p_deployment;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

CREATE FUNCTION organization_witness.deployment_bind_child(p_deployment uuid,p_epoch uuid,p_environment uuid,p_child_epoch uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; a organization_witness.authorities%ROWTYPE;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
 IF p_epoch IS NULL OR p_child_epoch IS NULL OR d.phase<>'active' OR d.epoch<>p_epoch OR a.phase<>'prepared' OR a.epoch<>p_child_epoch
 OR ROW(a.primary_id,a.token_store_id) IS DISTINCT FROM ROW(d.primary_id,d.token_store_id)
 THEN RAISE EXCEPTION 'deployment child selection refused'; END IF;
 INSERT INTO organization_witness.deployment_children(environment_id,child_epoch,deployment_id,deployment_epoch) VALUES(p_environment,p_child_epoch,p_deployment,p_epoch) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_children WHERE environment_id=p_environment AND child_epoch=p_child_epoch AND deployment_id=p_deployment AND deployment_epoch=p_epoch)
 THEN RAISE EXCEPTION 'deployment child epoch already bound'; END IF;
END $$;

CREATE FUNCTION organization_witness.deployment_acquire(p_deployment uuid,p_epoch uuid,p_primary uuid,p_token uuid,p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; s organization_witness.deployment_slots%ROWTYPE;
BEGIN
 IF p_epoch IS NULL OR p_primary IS NULL OR p_token IS NULL OR p_worker IS NULL OR p_worker='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid deployment admission'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF d.phase<>'active' OR ROW(d.epoch,d.primary_id,d.token_store_id) IS DISTINCT FROM ROW(p_epoch,p_primary,p_token) THEN RAISE EXCEPTION 'inactive deployment selection'; END IF;
 IF EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND worker_id=p_worker AND pending) THEN RAISE EXCEPTION 'deployment admission already pending'; END IF;
 SELECT * INTO STRICT s FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND NOT pending AND generation<9223372036854775807 ORDER BY slot LIMIT 1;
 UPDATE organization_witness.deployment_slots SET generation=generation+1,pending=true,epoch=p_epoch,worker_id=p_worker,principal=session_user WHERE deployment_id=p_deployment AND slot=s.slot RETURNING * INTO s;
 RETURN to_jsonb(s);
END $$;

CREATE FUNCTION organization_witness.deployment_acquire_child(p_deployment uuid,p_parent_slot integer,p_parent_generation bigint,p_parent_epoch uuid,p_parent_worker uuid,
 p_environment uuid,p_child_epoch uuid,p_primary uuid,p_token uuid,p_child_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; s organization_witness.deployment_slots%ROWTYPE; child jsonb;
BEGIN
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT s FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND slot=p_parent_slot FOR UPDATE;
 IF d.phase<>'active' OR NOT s.pending OR ROW(s.generation,s.epoch,s.worker_id,s.principal) IS DISTINCT FROM ROW(p_parent_generation,p_parent_epoch,p_parent_worker,session_user)
 OR d.epoch IS DISTINCT FROM p_parent_epoch OR ROW(d.primary_id,d.token_store_id) IS DISTINCT FROM ROW(p_primary,p_token)
 OR NOT EXISTS(SELECT FROM organization_witness.deployment_children WHERE environment_id=p_environment AND child_epoch=p_child_epoch AND deployment_id=p_deployment AND deployment_epoch=p_parent_epoch)
 THEN RAISE EXCEPTION 'deployment parent admission refused'; END IF;
 child := organization_witness.acquire(p_environment,p_deployment,p_child_epoch,p_primary,p_token,p_child_worker);
 INSERT INTO organization_witness.deployment_child_slots VALUES(p_environment,(child->>'slot')::integer,(child->>'generation')::bigint,p_deployment,p_parent_slot,p_parent_generation)
 ON CONFLICT(environment_id,child_slot) DO UPDATE SET child_generation=excluded.child_generation,deployment_id=excluded.deployment_id,parent_slot=excluded.parent_slot,parent_generation=excluded.parent_generation;
 RETURN child;
END $$;

CREATE FUNCTION organization_witness.deployment_release(p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid)
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
 UPDATE organization_witness.deployment_slots SET pending=false WHERE deployment_id=p_deployment AND slot=p_slot;
 RETURN organization_witness.deployment_state(p_deployment);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA organization_witness FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA organization_witness FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION organization_witness.acquire(uuid,uuid,uuid,uuid,uuid,uuid) FROM aegaeon_organization_witness_runtime;
GRANT EXECUTE ON FUNCTION organization_witness.deployment_state(uuid) TO aegaeon_organization_witness_runtime,aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.deployment_initialize(uuid,uuid),organization_witness.deployment_fence(uuid,uuid,bigint),
 organization_witness.deployment_prepare(uuid,uuid,bigint,uuid,uuid,uuid,text,text,text),organization_witness.deployment_activate(uuid,uuid,bigint,text),
 organization_witness.deployment_bind_child(uuid,uuid,uuid,uuid) TO aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.deployment_acquire(uuid,uuid,uuid,uuid,uuid),
 organization_witness.deployment_acquire_child(uuid,integer,bigint,uuid,uuid,uuid,uuid,uuid,uuid,uuid),
 organization_witness.deployment_release(uuid,integer,bigint,uuid,uuid) TO aegaeon_organization_witness_runtime;
COMMIT;
