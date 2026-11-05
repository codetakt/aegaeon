-- Exclusive retained maintenance ownership; no runtime or activation permission.
-- Install only after v8 with all parent/child admissions fenced and drained.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 THEN RAISE EXCEPTION 'maintenance migration requires drained fences'; END IF;
END $$;

-- Exactly one bounded row per deployment, with a nonwrapping generation.
-- Reuse does not resurrect an old capability. Uncertain work remains pending.
CREATE TABLE organization_witness.maintenance_slots (
 deployment_id uuid PRIMARY KEY REFERENCES organization_witness.deployments(deployment_id),
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 pending boolean NOT NULL DEFAULT false,
 fence_operation_id uuid, fence_revision bigint, work_id uuid, principal name,
 kind text CHECK(kind IN ('history-import','history-inspect','history-restore',
   'snapshot-inspect','snapshot-prepare','subject-inventory','subject-adopt','schema-migration')),
 plan_sha256 text CHECK(plan_sha256 ~ '^[0-9a-f]{64}$'),
 completion_sha256 text CHECK(completion_sha256 ~ '^[0-9a-f]{64}$'),
 CHECK(NOT pending OR (generation>0 AND fence_operation_id IS NOT NULL
   AND fence_revision>0 AND work_id IS NOT NULL AND principal IS NOT NULL
   AND kind IS NOT NULL AND plan_sha256 IS NOT NULL AND completion_sha256 IS NULL))
);

CREATE FUNCTION organization_witness.maintenance_state(p_deployment uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE s organization_witness.maintenance_slots%ROWTYPE;
BEGIN
 PERFORM 1 FROM organization_witness.deployments WHERE deployment_id=p_deployment;
 IF NOT FOUND THEN RAISE EXCEPTION 'deployment missing'; END IF;
 SELECT * INTO s FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment;
 IF NOT FOUND THEN RETURN jsonb_build_object('deployment_id',p_deployment,'generation',0,'pending',false); END IF;
 RETURN to_jsonb(s);
END $$;

CREATE FUNCTION organization_witness.maintenance_acquire(p_deployment uuid,p_fence uuid,p_revision bigint,
 p_work uuid,p_kind text,p_plan text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; s organization_witness.maintenance_slots%ROWTYPE;
BEGIN
 IF p_fence IS NULL OR p_fence='00000000-0000-0000-0000-000000000000'
 OR p_work IS NULL OR p_work='00000000-0000-0000-0000-000000000000'
 OR p_revision IS NULL OR p_revision<=0 OR p_kind IS NULL OR p_plan IS NULL
 THEN RAISE EXCEPTION 'explicit maintenance plan and fence required'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF d.phase<>'fenced' OR d.operation_id<>p_fence OR d.revision<>p_revision
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 THEN RAISE EXCEPTION 'drained deployment fence required'; END IF;
 PERFORM 1 FROM organization_witness.authorities WHERE deployment_id=p_deployment ORDER BY environment_id FOR UPDATE;
 IF EXISTS(SELECT FROM organization_witness.authorities WHERE deployment_id=p_deployment AND phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.slots child_slot JOIN organization_witness.authorities child_authority USING(environment_id)
   WHERE child_authority.deployment_id=p_deployment AND child_slot.pending)
 THEN RAISE EXCEPTION 'drained child fences required'; END IF;
 INSERT INTO organization_witness.maintenance_slots(deployment_id) VALUES(p_deployment) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT s FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment FOR UPDATE;
 IF s.pending OR s.generation>=9223372036854775807 THEN RAISE EXCEPTION 'maintenance unavailable'; END IF;
 UPDATE organization_witness.maintenance_slots SET generation=generation+1,pending=true,
   fence_operation_id=p_fence,fence_revision=p_revision,work_id=p_work,principal=session_user,
   kind=p_kind,plan_sha256=p_plan,completion_sha256=NULL WHERE deployment_id=p_deployment RETURNING * INTO s;
 RETURN to_jsonb(s);
END $$;

-- Own-Pre: the trusted maintenance coordinator has stopped/closed every actual
-- worker and store connection and retained the bounded completion receipt.
-- The SQL transition is NOT evidence that those external conditions occurred.
-- Do not expose a CLI that takes a caller-provided completed boolean or digest.
CREATE FUNCTION organization_witness.maintenance_complete(p_deployment uuid,p_generation bigint,
 p_work uuid,p_plan text,p_completion text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE s organization_witness.maintenance_slots%ROWTYPE;
BEGIN
 PERFORM 1 FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT s FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment FOR UPDATE;
 IF ROW(s.generation,s.work_id,s.plan_sha256,s.principal) IS DISTINCT FROM ROW(p_generation,p_work,p_plan,session_user)
 OR p_completion IS NULL OR p_completion !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'maintenance completion differs'; END IF;
 IF NOT s.pending THEN
   IF s.completion_sha256=p_completion THEN RETURN to_jsonb(s); END IF;
   RAISE EXCEPTION 'maintenance completion conflicts';
 END IF;
 UPDATE organization_witness.maintenance_slots SET pending=false,completion_sha256=p_completion
   WHERE deployment_id=p_deployment RETURNING * INTO s;
 RETURN to_jsonb(s);
END $$;

CREATE OR REPLACE FUNCTION organization_witness.deployment_prepare(p_deployment uuid,p_operation uuid,p_expected bigint,
 p_epoch uuid,p_primary uuid,p_token uuid,p_source text,p_history text,p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint;
BEGIN
 IF p_operation IS NULL OR p_expected IS NULL OR p_epoch IS NULL OR p_primary IS NULL OR p_token IS NULL
 OR p_epoch='00000000-0000-0000-0000-000000000000' OR p_primary='00000000-0000-0000-0000-000000000000' OR p_token='00000000-0000-0000-0000-000000000000'
 OR NOT organization_witness.creation_digest(p_source) OR NOT organization_witness.creation_digest(p_history) OR NOT organization_witness.creation_digest(p_acceptance)
 THEN RAISE EXCEPTION 'invalid deployment preparation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending) THEN RAISE EXCEPTION 'maintenance still pending'; END IF;
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

CREATE OR REPLACE FUNCTION organization_witness.deployment_activate(p_deployment uuid,p_operation uuid,p_expected bigint,p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE; old_from bigint;
BEGIN
 IF p_operation IS NULL OR p_expected IS NULL OR p_acceptance IS NULL THEN RAISE EXCEPTION 'invalid deployment activation'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 IF EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending) THEN RAISE EXCEPTION 'maintenance still pending'; END IF;
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

REVOKE ALL ON TABLE organization_witness.maintenance_slots FROM PUBLIC;
REVOKE ALL ON FUNCTION organization_witness.maintenance_state(uuid),
 organization_witness.maintenance_acquire(uuid,uuid,bigint,uuid,text,text),
 organization_witness.maintenance_complete(uuid,bigint,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.maintenance_state(uuid),
 organization_witness.maintenance_acquire(uuid,uuid,bigint,uuid,text,text),
 organization_witness.maintenance_complete(uuid,bigint,uuid,text,text)
 TO aegaeon_organization_witness_maintenance;
COMMIT;
