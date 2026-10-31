-- ORG-R12 / ORG-G08 / ORG-P09: explicit, short-lived and permanently revocable.
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
CREATE TABLE aegaeon.organization_admin_access_grants (
  id uuid PRIMARY KEY,
  environment_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  user_id uuid NOT NULL,
  client_registration_id uuid NOT NULL,
  root_id text COLLATE "C" NOT NULL CHECK (octet_length(root_id) BETWEEN 1 AND 2048),
  authority jsonb NOT NULL CHECK (jsonb_typeof(authority)='object' AND octet_length(authority::text)<=65536),
  revision bigint NOT NULL DEFAULT 1 CHECK (revision IN (1,2)),
  active boolean NOT NULL DEFAULT true,
  issued_at bigint NOT NULL CHECK (issued_at > 0),
  expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at-issued_at<=300),
  creation_key text COLLATE "C" NOT NULL CHECK (octet_length(creation_key) BETWEEN 1 AND 128),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  revocation_key text COLLATE "C" CHECK (octet_length(revocation_key) BETWEEN 1 AND 128),
  revocation_digest bytea CHECK (octet_length(revocation_digest)=32),
  UNIQUE(environment_id,domain_id,user_id,client_registration_id,root_id,creation_key),
  FOREIGN KEY(environment_id,domain_id,organization_id) REFERENCES aegaeon.application_organizations(environment_id,domain_id,id),
  CHECK ((active AND revision=1 AND revocation_key IS NULL AND revocation_digest IS NULL)
    OR (NOT active AND revision=2 AND revocation_key IS NOT NULL AND revocation_digest IS NOT NULL))
);
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_admin_access_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'administrative grant history cannot be deleted'; END IF;
  IF (to_jsonb(NEW)-ARRAY['active','revision','revocation_key','revocation_digest']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['active','revision','revocation_key','revocation_digest']) THEN
    RAISE EXCEPTION 'administrative grant bindings and lifetime are immutable';
  END IF;
  IF NOT OLD.active OR NEW.active OR NEW.revision<>2 THEN
    RAISE EXCEPTION 'administrative grant can only be revoked once';
  END IF;
  RETURN NEW;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_admin_access_guard() FROM PUBLIC;
CREATE TRIGGER organization_admin_access_guard BEFORE UPDATE OR DELETE ON aegaeon.organization_admin_access_grants
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_admin_access_guard();
RESET ROLE;
END
$installation$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
