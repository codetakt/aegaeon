-- Empty authority denies all new client-credentials issuance.
ALTER TABLE aegaeon.environment_policies
    ADD COLUMN client_credentials jsonb NOT NULL
    DEFAULT '{"version":1,"resourceServers":[],"rules":[]}'::jsonb;
