module Par_Ticket_Unit

open FStar.All

// Unit-backed ticket (legacy fallback; not used by default)
type ticket (u:string) = unit

let issue (u:string) : ticket u = ()
let consume (u:string) (_:ticket u) : unit = ()
