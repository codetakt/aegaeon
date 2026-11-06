-- Activate an operator-selected database generation after restore/reset isolation.
-- This does not perform PITR, restore credentials, replay audit or stop workers.
-- Supply deployment_id, previous_generation (empty for first activation),
-- generation (fresh UUID generated outside the restored DB), operation_id.
-- An optional proof_policy.initial_install=true asserts first-ever installation.
-- It is never valid for PITR, including PITR to an empty pre-Environment state.
-- Default ROLLBACK. Use commit=true only for the intended activation.
\set ON_ERROR_STOP on
\if :{?deployment_id}
\else
  \echo 'deployment_id is required'
  \quit 3
\endif
\if :{?previous_generation}
\else
  \echo 'previous_generation is required (empty only for first activation)'
  \quit 3
\endif
\if :{?generation}
\else
  \echo 'generation is required'
  \quit 3
\endif
\if :{?operation_id}
\else
  \echo 'operation_id is required'
  \quit 3
\endif
\if :{?commit}
\else
  \set commit false
\endif
\if :{?proof_policy}
\else
  \set proof_policy '{"assertion_window":3600,"request_object_window":3600,"clock_error":300}'
\endif
BEGIN;
SET LOCAL statement_timeout='5s';
SET LOCAL lock_timeout='1s';
SET LOCAL search_path=pg_catalog,pg_temp;
SELECT aegaeon_lifecycle.activate_v1(
  :'deployment_id'::uuid, NULLIF(:'previous_generation','')::uuid,
  :'generation'::uuid, :'operation_id'::uuid, :'proof_policy'::jsonb);
SELECT deployment_id, previous_generation, generation, activated_at,
  assertions_after, request_objects_after, dpop_after, proof_policy, operation_id, actor
FROM aegaeon_lifecycle.activations WHERE operation_id=:'operation_id'::uuid;
\if :commit
COMMIT;
\else
ROLLBACK;
\endif
