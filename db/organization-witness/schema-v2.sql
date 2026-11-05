-- Forward addition to schema-v1.sql in the independently provisioned control
-- database. It changes no existing authority, admission or transition function.
BEGIN;
SET LOCAL ROLE aegaeon_organization_witness_owner;
CREATE FUNCTION organization_witness.pending_work(p_environment uuid, p_deployment uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; admissions jsonb;
BEGIN
    SELECT * INTO STRICT a FROM organization_witness.authorities
        WHERE environment_id=p_environment AND deployment_id=p_deployment FOR SHARE;
    -- All admission/transition writers lock this same authority row exclusively.
    -- This observation therefore contains one state and its exact pending set.
    SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY s.slot),'[]'::jsonb)
        INTO admissions FROM organization_witness.slots s
        WHERE s.environment_id=p_environment AND s.pending;
    RETURN jsonb_build_object('state',to_jsonb(a) || jsonb_build_object('pending',jsonb_array_length(admissions)),
                              'admissions',admissions);
END $$;
REVOKE ALL ON FUNCTION organization_witness.pending_work(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_witness.pending_work(uuid,uuid) TO aegaeon_organization_witness_maintenance;
COMMIT;
