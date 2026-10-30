-- Explicit target-scoped resource server identities. No implicit recipient.
-- Apply with the successor catalog while all runtimes are stopped and drained.
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domain_targets
  ADD COLUMN introspection_clients jsonb NOT NULL DEFAULT '[]'::jsonb
  CHECK (jsonb_typeof(introspection_clients) = 'array'
    AND jsonb_array_length(introspection_clients) <= 8
    AND octet_length(introspection_clients::text) <= 8192);
RESET ROLE;
END
$installation$;
