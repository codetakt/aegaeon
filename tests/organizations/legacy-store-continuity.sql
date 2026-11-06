-- Retired control fixture only. Never installed by the product migration.
-- BEGIN ORGANIZATIONS COMPONENT organization_store_continuity
-- Post-work continuity seals; not authority admission or uncertain-work recovery.
-- Apply transactionally with every runtime/maintenance writer stopped and drained.
DO $installation$
BEGIN
  IF (SELECT count(*) FROM pg_catalog.pg_roles
      WHERE rolname IN ('aegaeon_subject_owner','aegaeon_subject_maintenance')
        AND NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls))<>2
      OR EXISTS (SELECT FROM pg_catalog.pg_auth_members
        WHERE member IN ('aegaeon_subject_owner'::regrole,'aegaeon_subject_maintenance'::regrole))
      OR pg_catalog.has_schema_privilege('aegaeon_subject_owner','aegaeon','CREATE') THEN
    RAISE EXCEPTION 'continuity authority requires checked administrator provisioning';
  END IF;
END
$installation$;
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $continuity$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
CREATE TABLE aegaeon.organization_store_continuity (
 singleton boolean NOT NULL DEFAULT true,
 deployment_id uuid NOT NULL,
 seal uuid NOT NULL,
 CONSTRAINT organization_store_continuity_pkey PRIMARY KEY(singleton),
 CONSTRAINT organization_store_continuity_singleton CHECK(singleton),
 CONSTRAINT organization_store_continuity_deployment CHECK(deployment_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CONSTRAINT organization_store_continuity_seal CHECK(seal<>'00000000-0000-0000-0000-000000000000'::uuid)
);
REVOKE ALL ON aegaeon.organization_store_continuity FROM PUBLIC;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_store_continuity_read_v1(deployment uuid) RETURNS uuid
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE current_deployment uuid; current_seal uuid;
BEGIN
  IF deployment IS NULL OR deployment='00000000-0000-0000-0000-000000000000'::uuid THEN
    RAISE EXCEPTION 'explicit continuity deployment required';
  END IF;
  SELECT s.deployment_id,s.seal INTO current_deployment,current_seal
    FROM aegaeon.organization_store_continuity s WHERE s.singleton;
  IF FOUND AND current_deployment IS DISTINCT FROM deployment THEN
    RAISE EXCEPTION 'continuity store belongs to another deployment';
  END IF;
  RETURN current_seal;
END
$function$;
$definition$;
EXECUTE $definition$
CREATE FUNCTION aegaeon.organization_store_continuity_replace_v1(deployment uuid, expected uuid, next_seal uuid) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
  IF deployment IS NULL OR deployment='00000000-0000-0000-0000-000000000000'::uuid
    OR next_seal IS NULL OR next_seal='00000000-0000-0000-0000-000000000000'::uuid
    OR expected='00000000-0000-0000-0000-000000000000'::uuid OR next_seal=expected THEN
    RAISE EXCEPTION 'fresh explicit continuity seal required';
  END IF;
  IF expected IS NULL THEN
    IF NOT pg_catalog.pg_has_role(session_user,'aegaeon_subject_maintenance','USAGE') THEN
      RAISE EXCEPTION 'continuity initialization requires maintenance authority';
    END IF;
    INSERT INTO aegaeon.organization_store_continuity(singleton,deployment_id,seal)
      VALUES(true,deployment,next_seal) ON CONFLICT(singleton) DO NOTHING;
  ELSE
    UPDATE aegaeon.organization_store_continuity s SET seal=next_seal
      WHERE s.singleton AND s.deployment_id=deployment AND s.seal=expected;
  END IF;
  IF NOT FOUND THEN RAISE EXCEPTION 'continuity seal compare-and-swap refused'; END IF;
  RETURN next_seal;
END
$function$;
$definition$;
REVOKE ALL ON FUNCTION aegaeon.organization_store_continuity_read_v1(uuid),
  aegaeon.organization_store_continuity_replace_v1(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegaeon.organization_store_continuity_read_v1(uuid),
  aegaeon.organization_store_continuity_replace_v1(uuid,uuid,uuid) TO aegaeon_subject_maintenance;
RESET ROLE;
END
$continuity$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- Advance only the exact Atlas prefix in the existing physical contract.
GRANT CREATE ON SCHEMA aegaeon TO aegaeon_subject_owner;
DO $replacement$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;


RESET ROLE;
END
$replacement$;
REVOKE CREATE ON SCHEMA aegaeon FROM aegaeon_subject_owner;

-- END ORGANIZATIONS COMPONENT organization_store_continuity
