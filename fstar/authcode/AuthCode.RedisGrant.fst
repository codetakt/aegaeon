module AuthCode.RedisGrant

(* Reviewed finite-domain transcription of COMMIT_AUTHORIZATION_CODE_GRANT.
   This models Redis command effects (including writes before runtime errors),
   not a refinement of Lua, cjson, numeric parsing, or the Rust key constructor.
   The fixture adapter supplies exact finite numeric and concatenation domains;
   the comparator checks these against the actual strings sent to Redis.
   Expiry is observed as persistent/expiring: wall-clock scheduling is separate.
*)
open FStar.List.Tot

type value =
 | Missing
 | Text : string -> value
 | Members : list string -> value
 | Fields : list (string * string) -> value
 | Scores : list (string * int) -> value

type entry = { data:value; expiring:bool }
type state = list (string * entry)
type result (a:Type0) = | Done : a -> state -> result a | Failed : string -> state -> result a
type comp (a:Type0) = state -> Tot (result a)
let empty = {data=Missing; expiring=false}
let rec lookup #a (k:string) (xs:list (string * a)) : Tot (option a) =
 match xs with | [] -> None | (key,v)::tl -> if k=key then Some v else lookup k tl
let rec replace #a (k:string) (v:a) (xs:list (string * a)) : Tot (list (string * a)) =
 match xs with | [] -> [(k,v)] | (key,old)::tl -> if k=key then (k,v)::tl else (key,old)::replace k v tl
let cell (s:state) (k:string) : Tot entry = match lookup k s with | None -> empty | Some e -> e
let ret #a (x:a) : comp a = fun s -> Done x s
let fail #a (reason:string) : comp a = fun s -> Failed reason s
let bind #a #b (c:comp a) (f:a -> comp b) : comp b = fun s ->
 match c s with | Failed e s' -> Failed e s' | Done x s' -> f x s'
let exists_key (k:string) : comp bool = fun s -> Done ((cell s k).data <> Missing) s
let get (k:string) : comp (option string) = fun s ->
 match (cell s k).data with
 | Missing -> Done None s | Text v -> Done (Some v) s | _ -> Failed "WRONGTYPE" s
let hget (k:string) (field:string) : comp (option string) = fun s ->
 match (cell s k).data with
 | Missing -> Done None s | Fields fs -> Done (lookup field fs) s | _ -> Failed "WRONGTYPE" s
let set (k:string) (v:string) : comp unit = fun s -> Done () (replace k {data=Text v; expiring=false} s)
let del (k:string) : comp unit = fun s -> Done () (replace k empty s)
let sadd (k:string) (v:string) : comp unit = fun s ->
 let e=cell s k in
 match e.data with
 | Missing -> Done () (replace k {data=Members [v]; expiring=false} s)
 | Members vs -> Done () (replace k {e with data=Members (if mem v vs then vs else v::vs)} s)
 | _ -> Failed "WRONGTYPE" s
let srem (k:string) (v:string) : comp unit = fun s ->
 let e=cell s k in
 match e.data with
 | Missing -> Done () s
 | Members vs -> let rest=filter (fun x -> x<>v) vs in
     Done () (replace k (if rest=[] then empty else {e with data=Members rest}) s)
 | _ -> Failed "WRONGTYPE" s
let zadd (k:string) (score:int) (v:string) : comp unit = fun s ->
 let e=cell s k in
 match e.data with
 | Missing -> Done () (replace k {data=Scores [(v,score)]; expiring=false} s)
 | Scores vs -> Done () (replace k {e with data=Scores (replace v score vs)} s)
 | _ -> Failed "WRONGTYPE" s
let zrem (k:string) (v:string) : comp unit = fun s ->
 let e=cell s k in
 match e.data with
 | Missing -> Done () s
 | Scores vs -> let rest=filter (fun (x,_) -> x<>v) vs in
     Done () (replace k (if rest=[] then empty else {e with data=Scores rest}) s)
 | _ -> Failed "WRONGTYPE" s
let rec update_fields xs current = match xs with
 | [] -> current | (key,v)::tl -> update_fields tl (replace key v current)
let hset (k:string) (fields:list (string * string)) : comp unit = fun s ->
 let e=cell s k in
 match e.data with
 | Missing -> Done () (replace k {data=Fields fields; expiring=false} s)
 | Fields fs -> Done () (replace k {e with data=Fields (update_fields fields fs)} s)
 | _ -> Failed "WRONGTYPE" s
let rec steps (cs:list (comp unit)) : comp unit = match cs with
 | [] -> ret () | c::tl -> bind c (fun _ -> steps tl)

type request = {
 keys:list string; args:list string;
 numbers:list (string * int);
 increments:list (string * string);
 concatenations:list (string * string);
 children:string
}
let rec nth (xs:list string) (n:nat) : Tot string = match xs with
 | [] -> "<outside-domain>" | x::tl -> if n=0 then x else nth tl (n-1)
let k r (n:pos) = nth r.keys (n-1)
let a r (n:pos) = nth r.args (n-1)
let number r t = lookup t r.numbers
let integer r t : comp int = match number r t with | None -> fail "NUMBER" | Some n -> ret n
let increment r key : comp unit = bind (get key) (fun current ->
 let v=match current with | None -> "0" | Some t -> t in
 match lookup v r.increments with
 | None -> fail "INTEGER" | Some next -> (fun s -> Done () (replace key {(cell s key) with data=Text next} s)))
let concat r prefix sid : comp string =
 match lookup (prefix ^ sid) r.concatenations with
 | None -> fail "DOMAIN" | Some key -> ret key
let when_ (condition:bool) (c:comp unit) : comp unit = if condition then c else ret ()
let cleanup r sid : comp unit =
 bind (concat r (a r 18) sid) (fun session_key ->
 bind (concat r (a r 19) sid) (fun clients_key ->
 bind (hget session_key "auth_session_key") (fun auth ->
 bind (hget session_key "user_sessions_key") (fun users ->
 bind (match auth with | None -> ret () | Some key ->
     bind (get key) (fun value -> when_ (value=Some sid) (del key))) (fun _ ->
 steps [(match users with | None -> ret () | Some key -> srem key sid);
        del session_key; del clients_key; zrem (k r 16) sid])))))
let logged_out_expired r now ttl text = match number r text with
 | None -> true | Some n -> n>now || now-n>=ttl
let oidc_current r now ttl : comp bool =
 bind (get (k r 14)) (fun current -> match current with
 | None -> ret true
 | Some sid -> bind (concat r (a r 18) sid) (fun sk ->
 bind (hget sk "user_id") (fun user ->
 bind (hget sk "auth_session_key") (fun auth ->
 bind (hget sk "user_sessions_key") (fun users ->
 bind (hget sk "logout_jti") (fun jti ->
 bind (hget sk "logged_out_at_epoch_secs") (fun at ->
 match user,auth,users,jti,at with
 | Some u,Some au,Some us,Some j,Some t ->
   if u=a r 12 && au=a r 13 && us=a r 14 then
     if j="" && t="" then
       if sid<>a r 15 then fail "oidc_session_conflict" else ret false
     else if j<>"" && t<>"" && not (logged_out_expired r now ttl t) then
       bind (del (k r 14)) (fun _ -> ret true)
     else bind (cleanup r sid) (fun _ -> ret true)
   else bind (if au=a r 13 then cleanup r sid else del (k r 14)) (fun _ -> ret true)
 | _ -> bind (cleanup r sid) (fun _ -> ret true))))))))
let oidc_preflight r : comp bool =
 if a r 11<>"1" then ret false
 else if a r 12="" || a r 13="" || a r 14="" || a r 15="" || a r 20="" || a r 18="" || a r 19="" then fail "oidc_session_invalid"
 else match number r (a r 16), number r (a r 17) with
 | Some now,Some ttl -> if ttl<1 then fail "oidc_session_invalid" else
     bind (oidc_current r now ttl) (fun create ->
     bind (exists_key (k r 15)) (fun occupied ->
     if create && occupied then fail "oidc_session_collision" else ret create))
 | _ -> fail "oidc_session_invalid"
let collision key : comp unit = bind (exists_key key) (fun present -> if present then fail "token_collision" else ret ())
let zadd_arg r key time member = bind (integer r time) (fun n -> zadd key n member)
let publish r create : comp unit = steps [
 del (k r 1);
 set (k r 4) (a r 1); sadd (k r 5) (a r 4); zadd_arg r (k r 6) (a r 5) (a r 4);
 when_ (a r 6="1") (steps [set (k r 7) (a r 2); sadd (k r 8) (a r 7);
     zadd_arg r (k r 9) (a r 8) (a r 7); set (k r 10) r.children]);
 set (k r 11) (a r 3); sadd (k r 12) (a r 9); zadd_arg r (k r 13) (a r 10) (a r 9);
 when_ (a r 11="1") (steps [
   when_ create (steps [hset (k r 15) [("user_id",a r 12);("auth_session_key",a r 13);("user_sessions_key",a r 14);("logout_jti","");("logged_out_at_epoch_secs","")];
                       set (k r 14) (a r 15); sadd (k r 17) (a r 15)]);
   sadd (k r 18) (a r 20)]);
 increment r (k r 2); increment r (k r 3)]
let commit r : comp string =
 bind (get (k r 1)) (fun raw -> match raw with
 | None -> fail "missing_code"
 | Some payload -> if payload<>a r 21 then fail "code_mismatch" else
 bind (steps [collision (k r 4);when_ (a r 6="1") (collision (k r 7));
              when_ (a r 6="1") (collision (k r 10));collision (k r 11)]) (fun _ ->
 (* The children key is absent after collision preflight in this atomic slice.
    The singleton cjson object is supplied by the validated fixture adapter. *)
 bind (oidc_preflight r) (fun create -> bind (publish r create) (fun _ -> ret "ok"))))

let rec every #a (f:a -> Tot bool) (xs:list a) : Tot bool = match xs with | [] -> true | x::tl -> f x && every f tl
let same_value v w = match v,w with
 | Missing,Missing -> true | Text x,Text y -> x=y
 | Members xs,Members ys -> every (fun x -> mem x ys) xs && every (fun y -> mem y xs) ys
 | Fields xs,Fields ys -> every (fun (k,v) -> lookup k ys=Some v) xs && every (fun (k,v) -> lookup k xs=Some v) ys
 | Scores xs,Scores ys -> every (fun (k,v) -> lookup k ys=Some v) xs && every (fun (k,v) -> lookup k xs=Some v) ys
 | _ -> false
let same_entry x y = x.expiring=y.expiring && same_value x.data y.data
let same_state s t = every (fun (k,_) -> same_entry (cell s k) (cell t k)) s && every (fun (k,_) -> same_entry (cell s k) (cell t k)) t
let observe r s = match commit r s with | Done reply after -> (reply,after) | Failed reply after -> (reply,after)
let rec trace (requests:list request) (s:state) : Tot (list string * state) = match requests with
 | [] -> ([],s)
 | r::tl -> let reply,after=observe r s in let replies,final=trace tl after in (reply::replies,final)
let matches requests initial replies expected =
 let actual,final=trace requests initial in actual=replies && same_state final expected
