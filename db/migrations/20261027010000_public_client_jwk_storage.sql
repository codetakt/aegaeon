-- Keep replay and Atlas apply atomic, including when no outer transaction exists.
-- Block concurrent writers through preflight, projection and constraint installation.
-- Preserve triggers and every row that does not contain private JWK members.
DO $migration$
BEGIN
LOCK TABLE aegaeon.dynamic_client_registrations IN SHARE ROW EXCLUSIVE MODE;

    IF EXISTS (
        SELECT 1 FROM aegaeon.dynamic_client_registrations
        WHERE jwks IS NOT NULL AND (
            jsonb_typeof(jwks) IS DISTINCT FROM 'object'
            OR jsonb_typeof(jwks -> 'keys') IS DISTINCT FROM 'array'
            OR EXISTS (
                SELECT 1 FROM jsonb_array_elements(
                    CASE WHEN jsonb_typeof(jwks -> 'keys') = 'array'
                         THEN jwks -> 'keys' ELSE '[]'::jsonb END
                ) AS members(member)
                WHERE jsonb_typeof(member) IS DISTINCT FROM 'object'
            )
        )
    ) THEN
        RAISE EXCEPTION 'public client JWKS upgrade blocked by malformed stored envelope or key member';
    END IF;

-- Public-client ownership only; this is not a cryptographic JWK validator.
CREATE FUNCTION aegaeon.client_jwks_are_public(value jsonb) RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE
    AS $$
DECLARE
    member jsonb;
BEGIN
    IF value IS NULL THEN
        RETURN true;
    END IF;
    IF jsonb_typeof(value) IS DISTINCT FROM 'object'
       OR jsonb_typeof(value -> 'keys') IS DISTINCT FROM 'array' THEN
        RETURN false;
    END IF;
    FOR member IN SELECT element FROM jsonb_array_elements(value -> 'keys') AS elements(element)
    LOOP
        IF jsonb_typeof(member) IS DISTINCT FROM 'object'
           OR member ?| ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

-- Include inactive environments/clients. Change only JWKS and only affected rows.
-- jsonb preserves remaining values; WITH ORDINALITY preserves key array order.
UPDATE aegaeon.dynamic_client_registrations AS registration
SET jwks = jsonb_set(registration.jwks, '{keys}', (
    SELECT COALESCE(jsonb_agg(member - ARRAY['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']
                              ORDER BY ordinal), '[]'::jsonb)
    FROM jsonb_array_elements(registration.jwks -> 'keys') WITH ORDINALITY AS members(member, ordinal)
))
WHERE NOT aegaeon.client_jwks_are_public(registration.jwks);

ALTER TABLE aegaeon.dynamic_client_registrations
    ADD CONSTRAINT dynamic_client_registrations_public_jwks
    CHECK (aegaeon.client_jwks_are_public(jwks));

END;
$migration$;
