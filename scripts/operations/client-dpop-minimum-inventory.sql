-- OFFLINE upgrade inventory. Run on the new schema, with all issuers/writers stopped.
-- Preserve this receipt privately; no complete row JSON or credential material is output.
BEGIN READ ONLY;
SET LOCAL TIME ZONE 'UTC';
SELECT current_setting('server_version') AS server_version,
       current_setting('server_encoding') AS server_encoding,
       current_setting('client_encoding') AS client_encoding;
SELECT c.environment_id, c.id AS client_id, c.configuration_version_id,
       c.status, pg_catalog.encode(
         pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(c)::text, 'UTF8')),
         'hex'
       ) AS expected_row_sha256
FROM aegaeon.clients c
WHERE c.dpop_bound_access_tokens IS NULL
ORDER BY c.environment_id, c.id;
ROLLBACK;
