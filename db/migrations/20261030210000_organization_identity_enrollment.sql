-- ORG-R14 / ORG-G04/G09: explicit Environment policy and protected self-service.
ALTER TABLE aegaeon.environments
  ADD COLUMN organization_identity_policy jsonb,
  ADD COLUMN organization_identity_policy_revision bigint NOT NULL DEFAULT 1
    CHECK (organization_identity_policy_revision > 0),
  ADD CONSTRAINT organization_identity_policy_object CHECK
    (organization_identity_policy IS NULL OR jsonb_typeof(organization_identity_policy)='object');
ALTER TABLE aegaeon.end_user_profiles ADD COLUMN verified_delivery_address text COLLATE "C"
  CHECK (verified_delivery_address IS NULL OR octet_length(verified_delivery_address) BETWEEN 3 AND 254);

CREATE FUNCTION aegaeon.organization_identity_policy_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.organization_identity_policy_revision < OLD.organization_identity_policy_revision THEN
    RAISE EXCEPTION 'organization identity policy cannot roll back';
  END IF;
  IF NEW.organization_identity_policy IS DISTINCT FROM OLD.organization_identity_policy THEN
    NEW.organization_identity_policy_revision := GREATEST(NEW.organization_identity_policy_revision,
      CASE WHEN OLD.organization_identity_policy_revision < 9223372036854775807
        THEN OLD.organization_identity_policy_revision + 1 ELSE OLD.organization_identity_policy_revision END);
  END IF;
  RETURN NEW;
END
$function$;
REVOKE ALL ON FUNCTION aegaeon.organization_identity_policy_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_policy_guard BEFORE UPDATE ON aegaeon.environments
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_policy_guard();


CREATE FUNCTION aegaeon.organization_identity_profile_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE affected uuid;
BEGIN
  IF TG_OP='UPDATE' THEN
    IF NEW.end_user_id IS DISTINCT FROM OLD.end_user_id THEN
      RAISE EXCEPTION 'profile identity cannot be reassigned';
    END IF;
    IF NEW.verified_delivery_address IS NOT DISTINCT FROM OLD.verified_delivery_address
       AND NEW.email_verified IS NOT DISTINCT FROM OLD.email_verified THEN RETURN NEW; END IF;
  END IF;
  IF TG_OP='INSERT' AND NEW.verified_delivery_address IS NULL AND NOT NEW.email_verified THEN RETURN NEW; END IF;
  IF TG_OP='DELETE' AND OLD.verified_delivery_address IS NULL AND NOT OLD.email_verified THEN RETURN OLD; END IF;
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
REVOKE ALL ON FUNCTION aegaeon.organization_identity_profile_guard() FROM PUBLIC;
CREATE TRIGGER organization_identity_profile_guard AFTER INSERT OR UPDATE OR DELETE ON aegaeon.end_user_profiles
  FOR EACH ROW EXECUTE FUNCTION aegaeon.organization_identity_profile_guard();

DO $installation$
BEGIN
  IF pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'subject owner has preexisting schema CREATE; remediation required';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $tables$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE TABLE aegaeon.organization_identity_requests (
  id uuid PRIMARY KEY,
  environment_id uuid NOT NULL,
  domain_id uuid NOT NULL,
  invitation_id uuid NOT NULL,
  invitation_delivery_revision bigint NOT NULL CONSTRAINT organization_identity_invitation_revision_positive CHECK (invitation_delivery_revision > 0),
  policy_revision bigint NOT NULL CHECK (policy_revision > 0),
  purpose text NOT NULL CHECK (purpose IN ('registration','password_recovery')),
  request_key text COLLATE "C" NOT NULL CHECK (octet_length(request_key) BETWEEN 1 AND 128),
  request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
  target_user_id uuid,
  target_identity_revision bigint CHECK (target_identity_revision > 0),
  issued_at bigint NOT NULL CHECK (issued_at >= 0),
  expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at-issued_at <= 600),
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','completed')),
  result jsonb,
  delivery_revision bigint NOT NULL DEFAULT 0 CHECK (delivery_revision BETWEEN 0 AND 5),
  delivered_at bigint,
  delivery_outcome text NOT NULL DEFAULT 'unclaimed' CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected')),
  capability_hash bytea CHECK (octet_length(capability_hash)=32),
  FOREIGN KEY(environment_id,domain_id,invitation_id)
    REFERENCES aegaeon.organization_invitations(environment_id,domain_id,id),
  UNIQUE(environment_id,domain_id,invitation_id,request_key),
  CHECK ((target_user_id IS NULL) = (target_identity_revision IS NULL)),
  CHECK ((state='pending' AND result IS NULL) OR (state='completed' AND jsonb_typeof(result)='object')),
  CHECK ((delivery_revision=0 AND delivered_at IS NULL AND capability_hash IS NULL AND delivery_outcome='unclaimed')
    OR (delivery_revision>0 AND delivered_at IS NOT NULL AND capability_hash IS NOT NULL AND delivery_outcome<>'unclaimed'))
);
CREATE INDEX organization_identity_requests_environment ON aegaeon.organization_identity_requests(environment_id,id);

REVOKE ALL ON TABLE aegaeon.organization_identity_requests FROM PUBLIC;
$definition$;
RESET ROLE;
END
$tables$;

DO $replacement$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
EXECUTE $definition$
CREATE OR REPLACE FUNCTION aegaeon.organization_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF NEW.organization_identity_revision < OLD.organization_identity_revision
     OR NEW.organization_reauthentication_after < OLD.organization_reauthentication_after THEN
    RAISE EXCEPTION 'organization identity authority cannot roll back';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status OR NEW.subject IS DISTINCT FROM OLD.subject
     OR NEW.email IS DISTINCT FROM OLD.email THEN
    NEW.organization_identity_revision := GREATEST(NEW.organization_identity_revision,
      CASE WHEN OLD.organization_identity_revision < 9223372036854775807
        THEN OLD.organization_identity_revision + 1 ELSE OLD.organization_identity_revision END);
    NEW.organization_reauthentication_after := GREATEST(NEW.organization_reauthentication_after,
      OLD.organization_reauthentication_after, floor(extract(epoch FROM clock_timestamp()))::bigint);
  END IF;
  RETURN NEW;
END
$function$;
$definition$;
RESET ROLE;
END
$replacement$;

ALTER FUNCTION aegaeon.organization_identity_profile_guard() OWNER TO aegaeon_subject_owner;
ALTER FUNCTION aegaeon.organization_identity_policy_guard() OWNER TO aegaeon_subject_owner;

REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;
