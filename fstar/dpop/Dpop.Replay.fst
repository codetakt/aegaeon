module Dpop.Replay

open FStar.All

(** Replay ticket emitted by the Verified Core.

    The runtime is responsible for enforcing replay prevention by combining
    this ticket with its environment identifier (namespace) and delegating the
    actual storage to Redis. *)
type replay_ticket = {
  jti: string;
}

inline_for_extraction let make_ticket (jti:string) : replay_ticket = { jti }
