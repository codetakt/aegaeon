-- Offline cutover plans are retained outside every restored store. These rows
-- record progress; they confer neither runtime admission nor activation rights.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.deployment_slots WHERE pending)
 OR EXISTS(SELECT FROM organization_witness.slots WHERE pending)
 THEN RAISE EXCEPTION 'cutover migration requires drained fenced state'; END IF;
END $$;

CREATE TABLE organization_witness.cutover_operations (
 deployment_id uuid NOT NULL REFERENCES organization_witness.deployments(deployment_id),
 operation_id uuid NOT NULL CHECK(operation_id<>'00000000-0000-0000-0000-000000000000'),
 fence_operation_id uuid NOT NULL,
 fence_revision bigint NOT NULL CHECK(fence_revision>0),
 fence_sha256 text NOT NULL CHECK(fence_sha256 ~ '^[0-9a-f]{64}$'),
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[0-9a-f]{64}$'),
 step smallint NOT NULL DEFAULT 0 CHECK(step BETWEEN 0 AND 16),
 receipts jsonb NOT NULL DEFAULT '[]'::jsonb
   CHECK(jsonb_typeof(receipts)='array' AND jsonb_array_length(receipts)=step
     AND octet_length(receipts::text)<=2048),
 completed boolean NOT NULL DEFAULT false CHECK(NOT completed OR step=16),
 principal name NOT NULL DEFAULT session_user,
 registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(deployment_id,operation_id),
 FOREIGN KEY(deployment_id,fence_operation_id) REFERENCES organization_witness.deployment_operations(deployment_id,operation_id)
);
CREATE UNIQUE INDEX cutover_one_pending ON organization_witness.cutover_operations(deployment_id) WHERE NOT completed;
REVOKE ALL ON TABLE organization_witness.cutover_operations FROM PUBLIC;
COMMIT;
