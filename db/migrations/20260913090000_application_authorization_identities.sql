-- Text identifiers may be reassigned. Never infer ownership of an existing
-- projection from whichever client or end user currently has its identifier.
-- Unbound projections fail closed until an explicit, audited authorization update.
ALTER TABLE aegaeon.application_authorizations
    ADD COLUMN client_record_id uuid REFERENCES aegaeon.clients(id) ON DELETE SET NULL,
    ADD COLUMN end_user_record_id uuid REFERENCES aegaeon.end_users(id) ON DELETE SET NULL;
