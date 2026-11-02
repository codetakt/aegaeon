-- Bound admission scans to this Environment and the fixed recent window.
CREATE INDEX lti_launch_intents_admission_idx
  ON aegaeon.lti_launch_intents(environment_id,created_at)
  INCLUDE (producer_client_id,owner_id);
