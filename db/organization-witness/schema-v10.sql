-- Offline runtime recovery receipts. No runtime/maintenance grants or API.
-- Install with all application writers stopped; a fenced pending owner may
-- survive this migration so that offline recovery can reconcile it afterward.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
LOCK TABLE organization_witness.deployments,organization_witness.authorities IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 IF EXISTS(SELECT FROM organization_witness.deployments WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.authorities WHERE phase<>'fenced')
 OR EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE pending)
 THEN RAISE EXCEPTION 'offline recovery migration requires fenced, non-maintenance state'; END IF;
END $$;

CREATE TABLE organization_witness.runtime_recoveries (
 deployment_id uuid NOT NULL REFERENCES organization_witness.deployments(deployment_id),
 recovery_id uuid NOT NULL CHECK(recovery_id<>'00000000-0000-0000-0000-000000000000'),
 fence_operation_id uuid NOT NULL,
 fence_revision bigint NOT NULL CHECK(fence_revision>0),
 plan_sha256 text NOT NULL CHECK(plan_sha256 ~ '^[0-9a-f]{64}$'),
 state_sha256 text NOT NULL CHECK(state_sha256 ~ '^[0-9a-f]{64}$'),
 completion_sha256 text NOT NULL CHECK(completion_sha256 ~ '^[0-9a-f]{64}$'),
 prior_state jsonb NOT NULL CHECK(jsonb_typeof(prior_state)='object' AND octet_length(prior_state::text)<=33554432),
 principal name NOT NULL DEFAULT session_user,
 recovered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(deployment_id,recovery_id),
 FOREIGN KEY(deployment_id,fence_operation_id) REFERENCES organization_witness.deployment_operations(deployment_id,operation_id)
);
REVOKE ALL ON TABLE organization_witness.runtime_recoveries FROM PUBLIC;
COMMIT;
