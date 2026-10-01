-- atlas:txmode file
-- Apply this whole file in one transaction. Only migration holds this table lock.
LOCK TABLE aegaeon.end_users IN SHARE ROW EXCLUSIVE MODE;

-- Allocation only: no owner or historical trust assertion. No end-user cascade.
CREATE TABLE aegaeon.upstream_subject_reservations (
    environment_id uuid NOT NULL REFERENCES aegaeon.environments(id) ON DELETE CASCADE,
    subject text COLLATE "C" NOT NULL,
    PRIMARY KEY (environment_id, subject),
    CONSTRAINT upstream_subject_reservations_namespace CHECK (
        pg_catalog.left(subject, 12) = 'upstream:v2:'
    )
);

-- Preserve all historical rows, including duplicate/deleted reserved spellings.
INSERT INTO aegaeon.upstream_subject_reservations (environment_id, subject)
SELECT DISTINCT environment_id, subject COLLATE "C"
FROM aegaeon.end_users
WHERE pg_catalog.left(subject, 12) COLLATE "C" = 'upstream:v2:';

CREATE FUNCTION aegaeon.reserve_upstream_subject() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.environment_id IS NOT DISTINCT FROM OLD.environment_id
       AND NEW.subject COLLATE "C" IS NOT DISTINCT FROM OLD.subject COLLATE "C" THEN
        RETURN NEW;
    END IF;
    IF pg_catalog.left(NEW.subject, 12) COLLATE "C" <> 'upstream:v2:' THEN
        RETURN NEW;
    END IF;
    BEGIN
        INSERT INTO aegaeon.upstream_subject_reservations (environment_id, subject)
        VALUES (NEW.environment_id, NEW.subject);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'upstream subject allocation conflicts with an existing reservation',
            CONSTRAINT = 'upstream_subject_reservations_pkey';
    END;
    RETURN NEW;
END;
$$;

-- Observe final NEW values after any BEFORE trigger, including old writers.
CREATE TRIGGER end_users_reserve_upstream_subject
AFTER INSERT OR UPDATE ON aegaeon.end_users
FOR EACH ROW EXECUTE FUNCTION aegaeon.reserve_upstream_subject();
