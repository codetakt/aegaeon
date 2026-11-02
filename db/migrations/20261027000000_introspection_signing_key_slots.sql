-- Introspection signing alone has independent RS256 and EdDSA slots.
-- Existing identities, ciphertext, history and retirement deadlines are unchanged.
ALTER TABLE aegaeon.runtime_keys DROP CONSTRAINT runtime_keys_algorithm_matches_usage;
ALTER TABLE aegaeon.runtime_keys ADD CONSTRAINT runtime_keys_algorithm_matches_usage CHECK ((((usage = 'OIDC_ID_TOKEN_SIGNING'::aegaeon.runtime_key_usage) AND (algorithm = 'RS256'::text)) OR ((usage = 'OIDC_REQUEST_OBJECT_DECRYPTION'::aegaeon.runtime_key_usage) AND (algorithm = 'RSA-OAEP+A256GCM'::text)) OR ((usage = 'JWT_ACCESS_TOKEN_SIGNING'::aegaeon.runtime_key_usage) AND (algorithm = 'EdDSA'::text)) OR ((usage = 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage) AND (algorithm = ANY (ARRAY['RS256'::text, 'EdDSA'::text])))));
DROP INDEX aegaeon.runtime_keys_one_active_per_environment_usage;
CREATE UNIQUE INDEX runtime_keys_one_active_per_environment_usage ON aegaeon.runtime_keys USING btree (environment_id, usage) WHERE ((status = 'ACTIVE'::aegaeon.runtime_key_status) AND (usage <> 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage));
CREATE UNIQUE INDEX runtime_keys_introspection_one_active_per_algorithm ON aegaeon.runtime_keys USING btree (environment_id, usage, algorithm) WHERE ((status = 'ACTIVE'::aegaeon.runtime_key_status) AND (usage = 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage));
DROP INDEX aegaeon.runtime_keys_one_next_per_environment_usage;
CREATE UNIQUE INDEX runtime_keys_one_next_per_environment_usage ON aegaeon.runtime_keys USING btree (environment_id, usage) WHERE ((status = 'NEXT'::aegaeon.runtime_key_status) AND (usage <> 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage));
CREATE UNIQUE INDEX runtime_keys_introspection_one_next_per_algorithm ON aegaeon.runtime_keys USING btree (environment_id, usage, algorithm) WHERE ((status = 'NEXT'::aegaeon.runtime_key_status) AND (usage = 'JWT_INTROSPECTION_SIGNING'::aegaeon.runtime_key_usage));
