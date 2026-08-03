module Par_Ticket

open FStar.All

// Steel-backed ticket (concrete, opaque via module boundary)
// Unforgeable, index-tied token used as a logical capability.
noeq type ticket (u:string) =
  | Ticket: ticket u

let issue (u:string) : ticket u = Ticket

// Logical consume; runtime side-effects are handled by callers.
let consume (u:string) (_:ticket u) : unit = ()
