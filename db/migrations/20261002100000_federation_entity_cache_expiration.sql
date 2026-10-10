-- Administrative retention must not extend a signed Entity Configuration expiry.
-- Cache readers still reject expires_at at or before their current time sample.
ALTER TABLE aegaeon.federation_entity_cache
    DROP CONSTRAINT federation_entity_cache_expires_after_fetch;
