-- Existing retained clients require an explicit offline policy decision.
ALTER TABLE aegaeon.clients ADD COLUMN dpop_bound_access_tokens boolean;
ALTER TABLE aegaeon.clients ALTER COLUMN dpop_bound_access_tokens SET DEFAULT false;

CREATE FUNCTION aegaeon.guard_client_dpop_minimum() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.dpop_bound_access_tokens IS NULL THEN
        IF TG_OP = 'INSERT' THEN
            RAISE EXCEPTION 'Client DPoP requirement must be resolved' USING ERRCODE = '23514';
        ELSIF OLD.dpop_bound_access_tokens IS NOT NULL THEN
            RAISE EXCEPTION 'Client DPoP requirement must be resolved' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER clients_dpop_minimum_guard BEFORE INSERT OR UPDATE ON aegaeon.clients
    FOR EACH ROW EXECUTE FUNCTION aegaeon.guard_client_dpop_minimum();
