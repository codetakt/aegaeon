-- A failed serving start is terminal only after retained, confirmed closure.
-- Preserve the original step/receipt chain and every pending runtime owner.
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
 OR EXISTS(SELECT FROM organization_witness.cutover_operations WHERE NOT completed)
 THEN RAISE EXCEPTION 'serving recovery migration requires drained fenced state'; END IF;
END $$;
ALTER TABLE organization_witness.cutover_operations
 ADD COLUMN aborted boolean NOT NULL DEFAULT false,
 ADD COLUMN abort_receipt_sha256 text,
 ADD CONSTRAINT cutover_abort_receipt CHECK (
   (NOT aborted AND abort_receipt_sha256 IS NULL)
   OR (aborted AND NOT completed AND step IN (14,15)
     AND abort_receipt_sha256 IS NOT NULL
     AND abort_receipt_sha256 ~ '^[0-9a-f]{64}$'));
DROP INDEX organization_witness.cutover_one_pending;
CREATE UNIQUE INDEX cutover_one_pending ON organization_witness.cutover_operations(deployment_id)
 WHERE NOT completed AND NOT aborted;
COMMIT;
