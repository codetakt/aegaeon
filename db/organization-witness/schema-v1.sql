-- Separately provisioned control database. Never apply to the primary database.
-- Installation requires the deployment administrator; service logins only inherit
-- the fixed runtime or maintenance group. No service login may inherit the owner.
BEGIN;
CREATE ROLE aegaeon_organization_witness_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE aegaeon_organization_witness_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE aegaeon_organization_witness_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA organization_witness AUTHORIZATION aegaeon_organization_witness_owner;
REVOKE ALL ON SCHEMA organization_witness FROM PUBLIC;
SET LOCAL ROLE aegaeon_organization_witness_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA organization_witness REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
CREATE TABLE organization_witness.authorities (
    environment_id uuid PRIMARY KEY CHECK (environment_id <> '00000000-0000-0000-0000-000000000000'),
    deployment_id uuid NOT NULL CHECK (deployment_id <> '00000000-0000-0000-0000-000000000000'),
    revision bigint NOT NULL CHECK (revision > 0),
    phase text NOT NULL CHECK (phase IN ('fenced','prepared','active')),
    operation_id uuid NOT NULL CHECK (operation_id <> '00000000-0000-0000-0000-000000000000'),
    epoch uuid,
    primary_id uuid,
    token_store_id uuid,
    source_sha256 text,
    history_sha256 text,
    acceptance_sha256 text,
    CHECK (phase = 'fenced' OR (epoch IS NOT NULL AND primary_id IS NOT NULL AND token_store_id IS NOT NULL AND source_sha256 IS NOT NULL AND history_sha256 IS NOT NULL AND acceptance_sha256 IS NOT NULL))
);
CREATE TABLE organization_witness.operations (
    environment_id uuid NOT NULL REFERENCES organization_witness.authorities(environment_id),
    id uuid NOT NULL,
    fence_from bigint NOT NULL CHECK (fence_from >= 0),
    fence_principal name NOT NULL DEFAULT session_user,
    fenced_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    prepare_from bigint,
    prepare_principal name,
    prepared_at timestamptz,
    activate_from bigint,
    activate_principal name,
    activated_at timestamptz,
    PRIMARY KEY (environment_id,id)
);
CREATE TABLE organization_witness.epochs (
    environment_id uuid NOT NULL REFERENCES organization_witness.authorities(environment_id),
    epoch uuid NOT NULL CHECK (epoch <> '00000000-0000-0000-0000-000000000000'),
    operation_id uuid NOT NULL,
    PRIMARY KEY (environment_id,epoch),
    FOREIGN KEY (environment_id,operation_id) REFERENCES organization_witness.operations(environment_id,id)
);
CREATE TABLE organization_witness.slots (
    environment_id uuid NOT NULL REFERENCES organization_witness.authorities(environment_id),
    slot integer NOT NULL CHECK (slot BETWEEN 0 AND 63),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    pending boolean NOT NULL DEFAULT false,
    epoch uuid,
    worker_id uuid,
    principal name,
    PRIMARY KEY (environment_id,slot),
    CHECK (NOT pending OR (generation > 0 AND epoch IS NOT NULL AND worker_id IS NOT NULL AND principal IS NOT NULL))
);

CREATE FUNCTION organization_witness.current_state(p_environment uuid, p_deployment uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; n integer;
BEGIN
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR SHARE;
    SELECT count(*) INTO n FROM organization_witness.slots WHERE environment_id=p_environment AND pending;
    RETURN to_jsonb(a) || jsonb_build_object('pending',n);
END $$;

CREATE FUNCTION organization_witness.initialize(p_environment uuid, p_deployment uuid, p_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
BEGIN
    -- Creation is explicit and never changes an existing authority. Its lost reply
    -- is reconciled through current_state, not an idempotent reinitialization.
    LOCK TABLE organization_witness.authorities IN SHARE ROW EXCLUSIVE MODE;
    IF (SELECT count(*) FROM organization_witness.authorities)>=1024 THEN RAISE EXCEPTION 'environment capacity exhausted'; END IF;
    INSERT INTO organization_witness.authorities(environment_id,deployment_id,revision,phase,operation_id)
        VALUES(p_environment,p_deployment,1,'fenced',p_operation);
    INSERT INTO organization_witness.operations(environment_id,id,fence_from) VALUES(p_environment,p_operation,0);
    INSERT INTO organization_witness.slots(environment_id,slot) SELECT p_environment,n FROM generate_series(0,63) n;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

CREATE FUNCTION organization_witness.fence(p_environment uuid, p_deployment uuid, p_operation uuid, p_expected bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; old_from bigint; terminal boolean;
BEGIN
    IF p_operation IS NULL OR p_operation='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid operation'; END IF;
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
    SELECT fence_from INTO old_from FROM organization_witness.operations WHERE environment_id=p_environment AND id=p_operation;
    IF FOUND THEN
        IF a.operation_id=p_operation AND a.phase='fenced' AND old_from=p_expected THEN
            RETURN organization_witness.current_state(p_environment,p_deployment);
        END IF;
        RAISE EXCEPTION 'conflicting fence replay';
    END IF;
    IF p_expected IS NULL OR a.revision<>p_expected OR a.revision=9223372036854775807 THEN RAISE EXCEPTION 'fence revision refused'; END IF;
    terminal := (SELECT count(*) FROM organization_witness.operations WHERE environment_id=p_environment)>=65536;
    INSERT INTO organization_witness.operations(environment_id,id,fence_from) VALUES(p_environment,p_operation,p_expected);
    UPDATE organization_witness.authorities SET phase='fenced',revision=CASE WHEN terminal THEN 9223372036854775807 ELSE revision+1 END,operation_id=p_operation WHERE environment_id=p_environment;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

CREATE FUNCTION organization_witness.prepare(p_environment uuid, p_deployment uuid, p_operation uuid, p_expected bigint,
    p_epoch uuid, p_primary uuid, p_token_store uuid, p_source text, p_history text, p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; old_from bigint;
BEGIN
    IF p_epoch IS NULL OR p_primary IS NULL OR p_token_store IS NULL
       OR p_epoch='00000000-0000-0000-0000-000000000000' OR p_primary='00000000-0000-0000-0000-000000000000' OR p_token_store='00000000-0000-0000-0000-000000000000'
       OR p_source IS NULL OR p_history IS NULL OR p_acceptance IS NULL
       OR p_source COLLATE "C" !~ '^[0-9a-f]{64}$' OR p_history COLLATE "C" !~ '^[0-9a-f]{64}$' OR p_acceptance COLLATE "C" !~ '^[0-9a-f]{64}$'
       OR p_operation IS NULL OR p_expected IS NULL THEN RAISE EXCEPTION 'invalid preparation'; END IF;
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
    SELECT prepare_from INTO STRICT old_from FROM organization_witness.operations WHERE environment_id=p_environment AND id=p_operation;
    IF a.operation_id=p_operation AND a.phase='prepared' AND old_from=p_expected
       AND a.epoch=p_epoch AND a.primary_id=p_primary AND a.token_store_id=p_token_store
       AND a.source_sha256=p_source AND a.history_sha256=p_history AND a.acceptance_sha256=p_acceptance THEN
        RETURN organization_witness.current_state(p_environment,p_deployment);
    END IF;
    IF a.operation_id<>p_operation OR a.phase<>'fenced' OR a.revision<>p_expected OR a.revision>=9223372036854775806
       OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND pending) THEN RAISE EXCEPTION 'preparation boundary refused'; END IF;
    INSERT INTO organization_witness.epochs(environment_id,epoch,operation_id) VALUES(p_environment,p_epoch,p_operation);
    UPDATE organization_witness.operations SET prepare_from=p_expected,prepare_principal=session_user,prepared_at=clock_timestamp() WHERE environment_id=p_environment AND id=p_operation;
    UPDATE organization_witness.authorities SET phase='prepared',revision=revision+1,epoch=p_epoch,primary_id=p_primary,token_store_id=p_token_store,
        source_sha256=p_source,history_sha256=p_history,acceptance_sha256=p_acceptance WHERE environment_id=p_environment;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

CREATE FUNCTION organization_witness.activate(p_environment uuid, p_deployment uuid, p_operation uuid, p_expected bigint, p_acceptance text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; old_from bigint;
BEGIN
    IF p_operation IS NULL OR p_expected IS NULL OR p_acceptance IS NULL THEN RAISE EXCEPTION 'invalid activation'; END IF;
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
    SELECT activate_from INTO STRICT old_from FROM organization_witness.operations WHERE environment_id=p_environment AND id=p_operation;
    IF a.operation_id=p_operation AND a.phase='active' AND old_from=p_expected AND a.acceptance_sha256=p_acceptance THEN
        RETURN organization_witness.current_state(p_environment,p_deployment);
    END IF;
    IF a.operation_id<>p_operation OR a.phase<>'prepared' OR a.revision<>p_expected OR a.revision>=9223372036854775806
       OR a.acceptance_sha256<>p_acceptance OR EXISTS(SELECT FROM organization_witness.slots WHERE environment_id=p_environment AND pending)
       THEN RAISE EXCEPTION 'activation boundary refused'; END IF;
    UPDATE organization_witness.operations SET activate_from=p_expected,activate_principal=session_user,activated_at=clock_timestamp() WHERE environment_id=p_environment AND id=p_operation;
    UPDATE organization_witness.authorities SET phase='active',revision=revision+1 WHERE environment_id=p_environment;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

CREATE FUNCTION organization_witness.acquire(p_environment uuid, p_deployment uuid, p_epoch uuid, p_primary uuid, p_token_store uuid, p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; s organization_witness.slots%ROWTYPE;
BEGIN
    IF p_epoch IS NULL OR p_primary IS NULL OR p_token_store IS NULL OR p_worker IS NULL OR p_worker='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'invalid admission'; END IF;
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
    IF a.phase<>'active' OR a.epoch<>p_epoch OR a.primary_id<>p_primary OR a.token_store_id<>p_token_store THEN RAISE EXCEPTION 'inactive selection'; END IF;
    SELECT * INTO s FROM organization_witness.slots WHERE environment_id=p_environment AND worker_id=p_worker AND pending;
    -- An admission is an execution capability, not an idempotent command
    -- receipt. Returning it twice would let one owner release another's work.
    IF FOUND THEN RAISE EXCEPTION 'admission already pending'; END IF;
    SELECT * INTO STRICT s FROM organization_witness.slots WHERE environment_id=p_environment AND NOT pending AND generation<9223372036854775807 ORDER BY slot LIMIT 1;
    UPDATE organization_witness.slots SET generation=generation+1,pending=true,epoch=p_epoch,worker_id=p_worker,principal=session_user
        WHERE environment_id=p_environment AND slot=s.slot RETURNING * INTO s;
    RETURN to_jsonb(s);
END $$;

CREATE FUNCTION organization_witness.release(p_environment uuid, p_deployment uuid, p_slot integer, p_generation bigint, p_epoch uuid, p_worker uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, organization_witness AS $$
DECLARE a organization_witness.authorities%ROWTYPE; s organization_witness.slots%ROWTYPE;
BEGIN
    SELECT * INTO STRICT a FROM organization_witness.authorities WHERE environment_id=p_environment AND deployment_id=p_deployment FOR UPDATE;
    SELECT * INTO STRICT s FROM organization_witness.slots WHERE environment_id=p_environment AND slot=p_slot;
    IF p_generation IS NULL OR p_epoch IS NULL OR p_worker IS NULL OR p_generation<=0
       OR s.generation<>p_generation OR s.epoch IS DISTINCT FROM p_epoch OR s.worker_id IS DISTINCT FROM p_worker OR s.principal IS DISTINCT FROM session_user
       THEN RAISE EXCEPTION 'admission completion refused'; END IF;
    UPDATE organization_witness.slots SET pending=false WHERE environment_id=p_environment AND slot=p_slot;
    RETURN organization_witness.current_state(p_environment,p_deployment);
END $$;

REVOKE ALL ON ALL TABLES IN SCHEMA organization_witness FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA organization_witness FROM PUBLIC;
GRANT USAGE ON SCHEMA organization_witness TO aegaeon_organization_witness_runtime,aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.current_state(uuid,uuid) TO aegaeon_organization_witness_runtime,aegaeon_organization_witness_maintenance;
GRANT EXECUTE ON FUNCTION organization_witness.acquire(uuid,uuid,uuid,uuid,uuid,uuid),organization_witness.release(uuid,uuid,integer,bigint,uuid,uuid) TO aegaeon_organization_witness_runtime;
GRANT EXECUTE ON FUNCTION organization_witness.initialize(uuid,uuid,uuid),organization_witness.fence(uuid,uuid,uuid,bigint),organization_witness.prepare(uuid,uuid,uuid,bigint,uuid,uuid,uuid,text,text,text),organization_witness.activate(uuid,uuid,uuid,bigint,text) TO aegaeon_organization_witness_maintenance;
COMMIT;
