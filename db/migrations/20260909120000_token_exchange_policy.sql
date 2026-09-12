-- An empty issuer-owned policy grants no cross-target token exchange authority.
ALTER TABLE aegaeon.environment_policies
    ADD COLUMN token_exchange jsonb NOT NULL
    DEFAULT '{"version":1,"targets":[],"rules":[]}'::jsonb;
