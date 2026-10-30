-- ORG-R12 / ORG-G08 / ORG-P09: absent policy never grants temporary support.
-- Stop and drain serving processes through the complete forward catalog stage.
DO $preflight$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$preflight$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $installation$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
ALTER TABLE aegaeon.authorization_domains
  ADD COLUMN support_policy jsonb,
  ADD COLUMN support_policy_revision bigint NOT NULL DEFAULT 1 CHECK (support_policy_revision > 0),
  ADD CONSTRAINT organization_support_policy_object CHECK
    (support_policy IS NULL OR (jsonb_typeof(support_policy)='object' AND octet_length(support_policy::text)<=65536));
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_support_policy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.support_policy_revision < OLD.support_policy_revision THEN
    RAISE EXCEPTION 'organization support policy cannot roll back';
  END IF;
  IF NEW.support_policy IS DISTINCT FROM OLD.support_policy THEN
    IF OLD.support_policy_revision = 9223372036854775807 AND NEW.support_policy IS NOT NULL THEN
      RAISE EXCEPTION 'exhausted support policy cannot be enabled';
    END IF;
    NEW.support_policy_revision := GREATEST(NEW.support_policy_revision,
      CASE WHEN OLD.support_policy_revision < 9223372036854775807
        THEN OLD.support_policy_revision + 1 ELSE OLD.support_policy_revision END);
  END IF;
  RETURN NEW;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_support_policy_guard() FROM PUBLIC;
CREATE TRIGGER organization_support_policy_guard BEFORE UPDATE ON aegaeon.authorization_domains
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_support_policy_guard();
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
