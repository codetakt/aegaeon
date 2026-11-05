-- Read-only startup diagnosis. This snapshot never grants serving authority.
-- Install after v14 with all writers stopped and parent/children fenced/drained.
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
 THEN RAISE EXCEPTION 'startup preflight migration requires drained fenced state'; END IF;
END $$;

CREATE FUNCTION organization_witness.startup_preflight(
 p_deployment uuid,p_environment uuid,p_parent jsonb,p_child jsonb)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,organization_witness AS $$
DECLARE
 d organization_witness.deployments%ROWTYPE;
 a organization_witness.authorities%ROWTYPE;
 dc organization_witness.deployment_store_checkpoints%ROWTYPE;
 ec organization_witness.store_checkpoints%ROWTYPE;
 parent_selection jsonb;
 child_selection jsonb;
BEGIN
 IF p_deployment IS NULL OR p_environment IS NULL
  OR p_deployment='00000000-0000-0000-0000-000000000000'
  OR p_environment='00000000-0000-0000-0000-000000000000'
 THEN RAISE EXCEPTION 'startup preflight scope refused'; END IF;
 -- STABLE uses the calling statement's snapshot for these SELECTs. No row locks
 -- extend across network I/O; actual admission must validate current state again.
 SELECT * INTO STRICT d FROM organization_witness.deployments
  WHERE deployment_id=p_deployment;
 SELECT * INTO STRICT a FROM organization_witness.authorities
  WHERE environment_id=p_environment AND deployment_id=p_deployment;
 parent_selection:=jsonb_build_object('epoch',d.epoch,'primary',d.primary_id,
  'token_store',d.token_store_id,'source_sha256',d.source_sha256,
  'history_sha256',d.history_sha256,'acceptance_sha256',d.acceptance_sha256);
 child_selection:=jsonb_build_object('epoch',a.epoch,'primary',a.primary_id,
  'token_store',a.token_store_id,'source_sha256',a.source_sha256,
  'history_sha256',a.history_sha256,'acceptance_sha256',a.acceptance_sha256);
 -- Exact JSON equality refuses extra, missing, null and differently typed fields.
 IF d.phase<>'active' OR a.phase<>'active'
  OR p_parent IS DISTINCT FROM parent_selection
  OR p_child IS DISTINCT FROM child_selection
  OR ROW(a.primary_id,a.token_store_id) IS DISTINCT FROM ROW(d.primary_id,d.token_store_id)
  OR NOT EXISTS(SELECT FROM organization_witness.deployment_children
   WHERE deployment_id=p_deployment AND deployment_epoch=d.epoch
    AND environment_id=p_environment AND child_epoch=a.epoch)
 THEN RAISE EXCEPTION 'startup preflight selection refused'; END IF;
 SELECT * INTO STRICT dc FROM organization_witness.deployment_store_checkpoints
  WHERE deployment_id=p_deployment AND epoch=d.epoch;
 SELECT * INTO STRICT ec FROM organization_witness.store_checkpoints
  WHERE environment_id=p_environment AND epoch=a.epoch;
 IF ROW(dc.primary_id,dc.token_store_id) IS DISTINCT FROM ROW(d.primary_id,d.token_store_id)
  OR ROW(ec.primary_id,ec.token_store_id) IS DISTINCT FROM ROW(a.primary_id,a.token_store_id)
  OR dc.primary_incarnation ? 'wal_position' OR ec.primary_incarnation ? 'wal_position'
  OR NOT organization_witness.store_observation_valid(
   dc.primary_incarnation||jsonb_build_object('wal_position',dc.wal_position),dc.token_incarnation)
  OR NOT organization_witness.store_observation_valid(
   ec.primary_incarnation||jsonb_build_object('wal_position',ec.wal_position),ec.token_incarnation)
 THEN RAISE EXCEPTION 'startup preflight checkpoint refused'; END IF;
 -- No principal, worker, slot/generation, pending inventory or permit is returned.
 RETURN jsonb_build_object('version',1,'deployment_id',p_deployment,
  'environment_id',p_environment,
  'parent',jsonb_build_object('selection',parent_selection,
   'primary_incarnation',dc.primary_incarnation,'token_incarnation',dc.token_incarnation,
   'minimum_wal',dc.wal_position),
  'child',jsonb_build_object('selection',child_selection,
   'primary_incarnation',ec.primary_incarnation,'token_incarnation',ec.token_incarnation,
   'minimum_wal',ec.wal_position));
END $$;
REVOKE ALL ON FUNCTION organization_witness.startup_preflight(uuid,uuid,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.startup_preflight(uuid,uuid,jsonb,jsonb)
 TO aegaeon_organization_witness_runtime;
COMMIT;
