-- Aggregate diagnostics only; never infer account ownership from these counts.
BEGIN TRANSACTION READ ONLY;
-- Known legacy diagnostic accepts ordinary surrounding spaces only. The review
-- query below also catches values with other whitespace without duplicating the
-- runtime parser's Unicode trimming rules.
SELECT cv.status AS configuration_status,
       count(*) AS enabled_legacy_policy_versions,
       count(*) FILTER (WHERE e.active_configuration_version_id = cv.id) AS currently_active_versions
FROM aegaeon.configuration_versions cv
JOIN aegaeon.environments e ON e.id = cv.environment_id
WHERE cv.configuration_document #>> '{federation,jitProvisioning,enabled}' = 'true'
  AND btrim(cv.configuration_document #>> '{federation,jitProvisioning,collisionPolicy}') = 'reuse_existing_email'
GROUP BY cv.status
ORDER BY cv.status;
-- Review candidates, not a validity judgment. Missing policy uses the default;
-- explicit JSON null, non-string and noncanonical string values require review.
-- These counts may overlap the known legacy diagnostic above.
SELECT cv.status AS configuration_status,
       count(*) AS noncanonical_policy_review_versions,
       count(*) FILTER (
         WHERE cv.configuration_document #>> '{federation,jitProvisioning,enabled}' = 'true'
       ) AS enabled_review_versions,
       count(*) FILTER (WHERE e.active_configuration_version_id = cv.id) AS currently_active_review_versions
FROM aegaeon.configuration_versions cv
JOIN aegaeon.environments e ON e.id = cv.environment_id
WHERE cv.configuration_document #> '{federation,jitProvisioning,collisionPolicy}' IS NOT NULL
  AND cv.configuration_document #> '{federation,jitProvisioning,collisionPolicy}' NOT IN (
    '"reject_existing_email"'::jsonb, '"reuse_existing_email"'::jsonb
  )
GROUP BY cv.status
ORDER BY cv.status;
SELECT EXISTS (
  SELECT 1 FROM information_schema.columns
  WHERE table_schema = 'aegaeon' AND table_name = 'account_links'
    AND column_name = 'binding_provenance'
) AS has_binding_provenance \gset
\if :has_binding_provenance
SELECT binding_provenance, count(*) AS bindings
FROM aegaeon.account_links GROUP BY binding_provenance ORDER BY binding_provenance;
\else
SELECT 'schema_without_provenance' AS binding_provenance, count(*) AS bindings
FROM aegaeon.account_links;
\endif
SELECT EXISTS (
  SELECT 1 FROM information_schema.tables
  WHERE table_schema = 'aegaeon' AND table_name = 'upstream_subject_reservations'
) AS has_subject_reservations \gset
\if :has_subject_reservations
SELECT count(*) AS reserved_upstream_subjects FROM aegaeon.upstream_subject_reservations;
\else
SELECT 'schema_without_subject_reservations' AS reservation_inventory;
\endif
COMMIT;
