-- Bind native epoch preparation to an independently registered offline intent.
-- The complete child inventory is locked with the parent; no table-read grant
-- or runtime privilege is added. Install only before a new cutover begins.
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
 THEN RAISE EXCEPTION 'epoch migration requires drained fences without pending cutover'; END IF;
END $$;

CREATE FUNCTION organization_witness.cutover_selection(p_deployment uuid,p_operation uuid,p_intent text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,organization_witness AS $$
DECLARE d organization_witness.deployments%ROWTYPE;
 c organization_witness.cutover_operations%ROWTYPE;
 a organization_witness.authorities%ROWTYPE;
 children jsonb:='[]'::jsonb;
BEGIN
 IF p_deployment IS NULL OR p_operation IS NULL OR NOT organization_witness.creation_digest(p_intent)
 THEN RAISE EXCEPTION 'exact epoch intent required'; END IF;
 SELECT * INTO STRICT d FROM organization_witness.deployments WHERE deployment_id=p_deployment FOR UPDATE;
 SELECT * INTO STRICT c FROM organization_witness.cutover_operations
   WHERE deployment_id=p_deployment AND operation_id=p_operation FOR UPDATE;
 IF c.completed OR c.step<>8 OR c.receipts->>7 IS DISTINCT FROM p_intent
 OR d.operation_id<>c.fence_operation_id OR d.phase NOT IN ('fenced','prepared')
 OR d.revision<>c.fence_revision+(CASE WHEN d.phase='prepared' THEN 1 ELSE 0 END)
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE deployment_id=p_deployment AND pending)
 THEN RAISE EXCEPTION 'registered epoch intent differs'; END IF;
 FOR a IN SELECT * FROM organization_witness.authorities WHERE deployment_id=p_deployment ORDER BY environment_id FOR UPDATE LOOP
   IF jsonb_array_length(children)>=64 OR a.phase NOT IN ('fenced','prepared')
   OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=a.environment_id AND pending)
   THEN RAISE EXCEPTION 'complete drained child inventory required'; END IF;
   children:=children||jsonb_build_array(organization_witness.current_state(a.environment_id,p_deployment));
 END LOOP;
 IF jsonb_array_length(children)=0 THEN RAISE EXCEPTION 'complete drained child inventory required'; END IF;
 RETURN jsonb_build_object('parent',organization_witness.deployment_state(p_deployment),'children',children);
END $$;
REVOKE ALL ON FUNCTION organization_witness.cutover_selection(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.cutover_selection(uuid,uuid,text) TO aegaeon_organization_witness_maintenance;
COMMIT;
