-- Synthetic SQL-only state. This does not qualify actual store observations.
DO $$
DECLARE
 deployment uuid:='10000000-0000-0000-0000-000000000001';
 environment uuid:='10000000-0000-0000-0000-000000000002';
 parent_epoch uuid:='10000000-0000-0000-0000-000000000003';
 child_epoch uuid:='10000000-0000-0000-0000-000000000004';
 primary_id uuid:='10000000-0000-0000-0000-000000000005';
 token_id uuid:='10000000-0000-0000-0000-000000000006';
 operation uuid:='10000000-0000-0000-0000-000000000007';
 parent_worker uuid:='10000000-0000-0000-0000-000000000008';
 child_worker uuid:='10000000-0000-0000-0000-000000000009';
 primary_observation jsonb:=jsonb_build_object('cluster_id',1,'database_oid',1,
  'database_name','startup_preflight_fixture','started_us',1,'timeline',1,'wal_position',10);
 token_observation jsonb:=jsonb_build_object('run_id',repeat('d',40),'database',0);
 parent_slot jsonb;
 child_slot jsonb;
BEGIN
 PERFORM organization_witness.deployment_initialize(deployment,operation);
 PERFORM organization_witness.deployment_prepare(deployment,operation,1,
  parent_epoch,primary_id,token_id,repeat('a',64),repeat('b',64),repeat('c',64));
 PERFORM organization_witness.deployment_store_progress_pin(
  deployment,operation,2,primary_observation,token_observation);
 -- The same diagnostic fixture also exercises historical v14/v15 upgrades.
 IF to_regprocedure('organization_witness.deployment_store_seal_pin(uuid,uuid,bigint,uuid)') IS NOT NULL THEN
  PERFORM organization_witness.deployment_store_seal_pin(
   deployment,operation,2,'10000000-0000-0000-0000-000000000011');
 END IF;
 PERFORM organization_witness.deployment_activate(deployment,operation,2,repeat('c',64));
 PERFORM organization_witness.initialize(environment,deployment,operation);
 PERFORM organization_witness.prepare(environment,deployment,operation,1,
  child_epoch,primary_id,token_id,repeat('a',64),repeat('b',64),repeat('c',64));
 PERFORM organization_witness.store_progress_pin(environment,deployment,operation,2,
  primary_observation||jsonb_build_object('wal_position',20),token_observation);
 PERFORM organization_witness.deployment_bind_child(deployment,parent_epoch,environment,child_epoch);
 PERFORM organization_witness.activate(environment,deployment,operation,2,repeat('c',64));
 parent_slot:=organization_witness.deployment_acquire(
  deployment,parent_epoch,primary_id,token_id,parent_worker);
 child_slot:=organization_witness.deployment_acquire_child(deployment,
  (parent_slot->>'slot')::integer,(parent_slot->>'generation')::bigint,parent_epoch,
  parent_worker,environment,child_epoch,primary_id,token_id,child_worker);
 PERFORM organization_witness.deployment_store_progress_begin(deployment,
  (parent_slot->>'slot')::integer,(parent_slot->>'generation')::bigint,parent_epoch,parent_worker);
 PERFORM organization_witness.store_progress_begin(environment,deployment,
  (child_slot->>'slot')::integer,(child_slot->>'generation')::bigint,child_epoch,child_worker);
END $$;
