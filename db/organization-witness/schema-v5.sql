-- Read retained creation settlement under an exact live work admission.
-- Apply after v1-v4 with service writers stopped; previous rows remain unchanged.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
CREATE FUNCTION organization_witness.creation_lookup(p_environment uuid,p_deployment uuid,p_slot integer,p_generation bigint,p_epoch uuid,p_worker uuid,p_kind text,p_selector text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE c organization_witness.creations%ROWTYPE;
BEGIN
 PERFORM organization_witness.history_require_admission(p_environment,p_deployment,p_slot,p_generation,p_epoch,p_worker);
 IF p_kind IS NULL OR p_kind NOT IN ('management_create','management_invite','management_csv','registration','upstream')
  OR p_selector IS NULL OR NOT organization_witness.creation_digest(p_selector)
 THEN RAISE EXCEPTION 'creation lookup refused'; END IF;
 SELECT * INTO c FROM organization_witness.creations
  WHERE environment_id=p_environment AND kind=p_kind COLLATE "C" AND selector_sha256=p_selector COLLATE "C";
 IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
 RETURN to_jsonb(c);
END $$;
REVOKE ALL ON FUNCTION organization_witness.creation_lookup(uuid,uuid,integer,bigint,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.creation_lookup(uuid,uuid,integer,bigint,uuid,uuid,text,text) TO aegaeon_organization_witness_runtime;
COMMIT;
