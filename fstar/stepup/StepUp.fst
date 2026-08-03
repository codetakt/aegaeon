module StepUp

open FStar.All
open FStar.Bytes
open Random

type session_id = string
type client_id = string
type request_id = string
type timestamp = nat

type stepup_challenge = {
  id: challenge_id;
  client: client_id;
  session: session_id;
  request: request_id;
  issued_at: timestamp;
  expires_at: timestamp;
  completed: bool;
}

let issued_before_expires (c: stepup_challenge) : Tot bool =
  c.issued_at <= c.expires_at

let challenge_valid_at (c: stepup_challenge) (now: timestamp) : Tot bool =
  c.issued_at <= now && now <= c.expires_at

let issue_challenge
  (client: client_id)
  (session: session_id)
  (request: request_id)
  (now: timestamp)
  (ttl: nat)
  (entropy: bytes{Bytes.length entropy = 32})
  : Tot stepup_challenge =
  {
    id = fresh_challenge_id entropy;
    client;
    session;
    request;
    issued_at = now;
    expires_at = now + ttl;
    completed = false;
  }

let can_consume_challenge (c: stepup_challenge) (now: timestamp) : Tot bool =
  not c.completed && challenge_valid_at c now

let complete_challenge
  (c: stepup_challenge)
  (now: timestamp)
  : Tot (option stepup_challenge) =
  if can_consume_challenge c now then
    Some { c with completed = true }
  else
    None

let stepup_satisfied (c: stepup_challenge) (now: timestamp) : Tot bool =
  c.completed && challenge_valid_at c now

let can_issue_token
  (requires_stepup: bool)
  (challenge: option stepup_challenge)
  (now: timestamp)
  : Tot bool =
  if requires_stepup then
    match challenge with
    | Some c -> stepup_satisfied c now
    | None -> false
  else
    true

let lemma_issue_binds_inputs
  (client: client_id)
  (session: session_id)
  (request: request_id)
  (now: timestamp)
  (ttl: nat)
  (entropy: bytes{Bytes.length entropy = 32})
  : Lemma
    (ensures (let c = issue_challenge client session request now ttl entropy in
      c.client = client /\
      c.session = session /\
      c.request = request /\
      c.issued_at = now /\
      c.expires_at = now + ttl /\
      c.completed = false))
  = ()

let lemma_issue_bounds
  (client: client_id)
  (session: session_id)
  (request: request_id)
  (now: timestamp)
  (ttl: nat)
  (entropy: bytes{Bytes.length entropy = 32})
  : Lemma
    (ensures (let c = issue_challenge client session request now ttl entropy in
      issued_before_expires c))
  = ()

let lemma_complete_rejects_replay
  (c: stepup_challenge)
  (now: timestamp)
  : Lemma
    (requires c.completed)
    (ensures (complete_challenge c now = None))
  = ()

let lemma_stepup_enforced
  (c: stepup_challenge)
  (now: timestamp)
  : Lemma
    (requires (can_issue_token true (Some c) now))
    (ensures (stepup_satisfied c now))
  = ()
