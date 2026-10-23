-- Attribute ownership uses immutable local IDs, independently of editable claims.
ALTER TABLE aegaeon.end_users
  ADD CONSTRAINT end_users_environment_id_id_unique UNIQUE (environment_id, id);
ALTER TABLE aegaeon.connections
  ADD CONSTRAINT connections_environment_id_id_unique UNIQUE (environment_id, id);

CREATE TABLE aegaeon.user_attribute_sources (
  environment_id uuid NOT NULL,
  end_user_id uuid NOT NULL,
  source_namespace text NOT NULL,
  connection_id uuid,
  source_kind text NOT NULL CHECK (source_kind IN ('LOCAL', 'EXTERNAL')),
  source_authority text NOT NULL CHECK (length(source_authority) BETWEEN 1 AND 512),
  source_revision text NOT NULL CHECK (length(source_revision) BETWEEN 1 AND 512),
  observed_at bigint NOT NULL CHECK (observed_at >= 0),
  expires_at bigint CHECK (expires_at > observed_at),
  attribute_values jsonb NOT NULL CHECK (jsonb_typeof(attribute_values) = 'object'),
  revision bigint NOT NULL CHECK (revision > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (environment_id, end_user_id, source_namespace),
  FOREIGN KEY (environment_id, end_user_id)
    REFERENCES aegaeon.end_users (environment_id, id),
  FOREIGN KEY (environment_id, connection_id)
    REFERENCES aegaeon.connections (environment_id, id),
  CHECK (
    (source_kind = 'LOCAL' AND source_namespace = 'local' AND connection_id IS NULL)
    OR
    (source_kind = 'EXTERNAL' AND connection_id IS NOT NULL
      AND source_namespace = 'connection:' || connection_id::text)
  )
);

-- No legacy profile is backfilled: old values have no established source
-- provenance or recipient grants. Adoption is an explicit later operation.
