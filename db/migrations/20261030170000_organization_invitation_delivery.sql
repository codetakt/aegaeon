-- Stop and drain serving runtimes before changing the physical authority.
DO $migration$
BEGIN
SET LOCAL ROLE aegaeon_subject_owner;
ALTER TABLE aegaeon.authorization_domains ADD COLUMN invitation_delivery jsonb
    CHECK (invitation_delivery IS NULL OR (jsonb_typeof(invitation_delivery)='object' AND octet_length(invitation_delivery::text)<=4096));
ALTER TABLE aegaeon.organization_invitations ADD COLUMN delivery_outcome text NOT NULL DEFAULT 'unclaimed'
    CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected'));
ALTER TABLE aegaeon.organization_invitation_challenges ADD COLUMN delivery_outcome text NOT NULL DEFAULT 'unclaimed'
    CHECK (delivery_outcome IN ('unclaimed','uncertain','acknowledged','rejected'));
UPDATE aegaeon.organization_invitations SET delivery_outcome='uncertain' WHERE delivery_revision>0;
UPDATE aegaeon.organization_invitation_challenges SET delivery_outcome='uncertain' WHERE delivery_revision>0;
ALTER TABLE aegaeon.organization_invitations ADD CONSTRAINT organization_invitation_delivery_state
    CHECK ((delivery_revision=0)=(delivery_outcome='unclaimed'));
ALTER TABLE aegaeon.organization_invitation_challenges ADD CONSTRAINT organization_challenge_delivery_state
    CHECK ((delivery_revision=0)=(delivery_outcome='unclaimed'));
RESET ROLE;
END
$migration$;
