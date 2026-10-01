-- Existing links and inserts from older writers remain explicitly unreviewed.
-- No owner, identity key, timestamp or stored credential is rewritten.
ALTER TABLE aegaeon.account_links
    ADD COLUMN binding_provenance text NOT NULL DEFAULT 'legacy_unreviewed',
    ADD COLUMN binding_revision bigint NOT NULL DEFAULT 1,
    ADD CONSTRAINT account_links_binding_provenance_valid CHECK (
        binding_provenance IN ('legacy_unreviewed', 'jit_v2', 'administrator_confirmed')
    ),
    ADD CONSTRAINT account_links_binding_revision_positive CHECK (binding_revision > 0);
