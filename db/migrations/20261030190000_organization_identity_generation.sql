-- ORG-R05/R06/R10/R14, ORG-G05/G07/G09: restoring ACTIVE never restores grants.
-- Drain serving processes before the complete forward migration/catalog stage.
ALTER TABLE aegaeon.end_users
  ADD COLUMN organization_identity_revision bigint NOT NULL DEFAULT 1
    CHECK (organization_identity_revision > 0),
  ADD COLUMN organization_reauthentication_after bigint NOT NULL DEFAULT 0
    CHECK (organization_reauthentication_after >= 0);

-- Historical authentication predating this new enforcement boundary cannot
-- supply a fresh Organizations approval. New user defaults remain zero.
UPDATE aegaeon.end_users SET organization_reauthentication_after =
  GREATEST(0, floor(extract(epoch FROM clock_timestamp()))::bigint);

CREATE FUNCTION aegaeon.organization_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.organization_identity_revision < OLD.organization_identity_revision
     OR NEW.organization_reauthentication_after < OLD.organization_reauthentication_after THEN
    RAISE EXCEPTION 'organization identity authority cannot roll back';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status OR NEW.subject IS DISTINCT FROM OLD.subject THEN
    NEW.organization_identity_revision := GREATEST(NEW.organization_identity_revision,
      CASE WHEN OLD.organization_identity_revision < 9223372036854775807
        THEN OLD.organization_identity_revision + 1 ELSE OLD.organization_identity_revision END);
    NEW.organization_reauthentication_after := GREATEST(NEW.organization_reauthentication_after,
      OLD.organization_reauthentication_after, floor(extract(epoch FROM clock_timestamp()))::bigint);
  END IF;
  RETURN NEW;
END
$function$;

CREATE FUNCTION aegaeon.organization_identity_credential_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE affected uuid;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.end_user_id IS DISTINCT FROM OLD.end_user_id THEN
      RAISE EXCEPTION 'password credential identity cannot be reassigned';
    END IF;
    IF NEW.password_hash IS NOT DISTINCT FROM OLD.password_hash
       AND NEW.status IS NOT DISTINCT FROM OLD.status THEN RETURN NEW; END IF;
  END IF;
  affected := CASE WHEN TG_OP='DELETE' THEN OLD.end_user_id ELSE NEW.end_user_id END;
  UPDATE aegaeon.end_users SET
    organization_identity_revision = CASE WHEN organization_identity_revision < 9223372036854775807
      THEN organization_identity_revision + 1 ELSE organization_identity_revision END,
    organization_reauthentication_after = GREATEST(organization_reauthentication_after,
      floor(extract(epoch FROM clock_timestamp()))::bigint)
    WHERE id=affected;
  RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$function$;

REVOKE ALL ON FUNCTION aegaeon.organization_identity_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION aegaeon.organization_identity_credential_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_guard BEFORE UPDATE ON aegaeon.end_users
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_guard();
CREATE TRIGGER organization_identity_credential_guard
  AFTER INSERT OR UPDATE OR DELETE ON aegaeon.end_user_password_credentials
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_credential_guard();

DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_guard() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_credential_guard() OWNER TO aegaeon_subject_owner;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
