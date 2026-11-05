-- Registered all-child activation inventory. No runtime activation privilege.
-- Install before starting a new cutover; preserve every older catalog/migration.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.cutover_operations WHERE NOT completed)
 THEN RAISE EXCEPTION 'activation migration requires drained fences without pending cutover'; END IF;
END $$;

CREATE FUNCTION organization_witness.cutover_activation_selection(
 p_deployment uuid,p_operation uuid,p_epoch_intent text,p_manifest text,p_activation text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE;
 c organization_witness.cutover_operations%ROWTYPE;
 a organization_witness.authorities%ROWTYPE;
 children jsonb:='[]'::jsonb;
 bindings jsonb;
 parent_checkpoint jsonb;
 child_checkpoints jsonb;
BEGIN
 IF p_deployment IS NULL OR p_operation IS NULL
 OR NOT organization_witness.creation_digest(p_epoch_intent)
 OR NOT organization_witness.creation_digest(p_manifest)
 OR NOT organization_witness.creation_digest(p_activation)
 THEN RAISE EXCEPTION 'exact registered activation intent required'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT c FROM organization_witness.cutover_operations
   WHERE deployment_id=p_deployment AND operation_id=p_operation FOR UPDATE;
 IF c.completed OR c.step<>12 OR c.receipts->>7 IS DISTINCT FROM p_epoch_intent
 OR c.receipts->>9 IS DISTINCT FROM p_manifest OR c.receipts->>11 IS DISTINCT FROM p_activation
 OR d.operation_id<>c.fence_operation_id OR d.phase NOT IN ('prepared','active')
 OR d.revision<>c.fence_revision+(CASE WHEN d.phase='active' THEN 2 ELSE 1 END)
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 THEN RAISE EXCEPTION 'registered activation intent differs'; END IF;
 IF NOT EXISTS(SELECT FROM organization_witness.deployment_store_checkpoints
   WHERE deployment_id=p_deployment AND epoch=d.epoch AND principal=session_user
   AND operation_id=d.operation_id AND prepared_revision=c.fence_revision+1
   AND primary_id=d.primary_id AND token_store_id=d.token_store_id)
 THEN RAISE EXCEPTION 'selected checkpoint principal required'; END IF;
 FOR a IN SELECT * FROM organization_witness.authorities
   WHERE deployment_id=p_deployment ORDER BY environment_id FOR UPDATE LOOP
   IF jsonb_array_length(children)>=64 OR a.phase<>d.phase
   OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=a.environment_id AND pending)
   OR NOT EXISTS(SELECT FROM organization_witness.store_checkpoints
     WHERE environment_id=a.environment_id AND epoch=a.epoch AND principal=session_user
     AND operation_id=a.operation_id
     AND prepared_revision=a.revision-(CASE WHEN a.phase='active' THEN 1 ELSE 0 END)
     AND primary_id=a.primary_id AND token_store_id=a.token_store_id)
   THEN RAISE EXCEPTION 'complete drained activation inventory required'; END IF;
   children:=children||jsonb_build_array(organization_witness.current_state(a.environment_id,p_deployment));
 END LOOP;
 IF jsonb_array_length(children)=0 THEN RAISE EXCEPTION 'complete drained activation inventory required'; END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY b.environment_id),'[]'::jsonb) INTO bindings
   FROM organization_witness.deployment_children b
   JOIN organization_witness.authorities selected_authority USING(environment_id)
   WHERE selected_authority.deployment_id=p_deployment AND b.child_epoch=selected_authority.epoch;
 SELECT to_jsonb(cp) INTO STRICT parent_checkpoint
   FROM organization_witness.deployment_store_checkpoints cp
   WHERE cp.deployment_id=p_deployment AND cp.epoch=d.epoch;
 SELECT COALESCE(jsonb_agg(to_jsonb(cp) ORDER BY cp.environment_id),'[]'::jsonb) INTO child_checkpoints
   FROM organization_witness.store_checkpoints cp
   JOIN organization_witness.authorities selected_authority USING(environment_id,epoch)
   WHERE selected_authority.deployment_id=p_deployment;
 RETURN jsonb_build_object('parent',organization_witness.deployment_state(p_deployment),
   'children',children,'bindings',bindings,'parentCheckpoint',parent_checkpoint,
   'childCheckpoints',child_checkpoints,'publicationSha256',c.receipts->>10);
END $$;
REVOKE ALL ON FUNCTION organization_witness.cutover_activation_selection(uuid,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.cutover_activation_selection(uuid,uuid,text,text,text)
 TO aegaeon_organization_witness_maintenance;
COMMIT;
