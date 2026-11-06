-- Synthetic SQL-only store state. Actual durable seal checks belong to Rust.
DO $$
DECLARE
 deployment uuid:='10000000-0000-0000-0000-000000000001';
 environment uuid:='10000000-0000-0000-0000-000000000002';
 second_environment uuid:='10000000-0000-0000-0000-000000000010';
 parent_epoch uuid:='10000000-0000-0000-0000-000000000003';
 child_epoch uuid:='10000000-0000-0000-0000-000000000004';
 second_epoch uuid:='10000000-0000-0000-0000-000000000012';
 primary_id uuid:='10000000-0000-0000-0000-000000000005';
 token_id uuid:='10000000-0000-0000-0000-000000000006';
 operation uuid:='10000000-0000-0000-0000-000000000007';
 primary_observation jsonb:=jsonb_build_object('cluster_id',1,'database_oid',1,
  'database_name','store_continuity_fixture','started_us',1,'timeline',1,'wal_position',10);
 token_observation jsonb:=jsonb_build_object('run_id',repeat('d',40),'database',0);
BEGIN
 PERFORM organization_witness.deployment_initialize(deployment,operation);
 PERFORM organization_witness.deployment_prepare(deployment,operation,1,
  parent_epoch,primary_id,token_id,repeat('a',64),repeat('b',64),repeat('c',64));
 PERFORM organization_witness.deployment_store_progress_pin(
  deployment,operation,2,primary_observation,token_observation);
 PERFORM organization_witness.deployment_store_seal_pin(
  deployment,operation,2,'10000000-0000-0000-0000-000000000011');
 PERFORM organization_witness.deployment_activate(deployment,operation,2,repeat('c',64));
 PERFORM organization_witness.initialize(environment,deployment,operation);
 PERFORM organization_witness.prepare(environment,deployment,operation,1,
  child_epoch,primary_id,token_id,repeat('a',64),repeat('b',64),repeat('c',64));
 PERFORM organization_witness.store_progress_pin(environment,deployment,operation,2,
  primary_observation||jsonb_build_object('wal_position',20),token_observation);
 PERFORM organization_witness.deployment_bind_child(deployment,parent_epoch,environment,child_epoch);
 PERFORM organization_witness.activate(environment,deployment,operation,2,repeat('c',64));
 PERFORM organization_witness.initialize(second_environment,deployment,operation);
 PERFORM organization_witness.prepare(second_environment,deployment,operation,1,
  second_epoch,primary_id,token_id,repeat('a',64),repeat('b',64),repeat('c',64));
 PERFORM organization_witness.store_progress_pin(second_environment,deployment,operation,2,
  primary_observation||jsonb_build_object('wal_position',30),token_observation);
 PERFORM organization_witness.deployment_bind_child(deployment,parent_epoch,second_environment,second_epoch);
 PERFORM organization_witness.activate(second_environment,deployment,operation,2,repeat('c',64));
END $$;
