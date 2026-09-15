module TestAuthCodeRedisFlag

open AuthCode.RedisFlag

(* Each rejected candidate is tested against the same exact byte relation. *)
[@@expect_failure [19]]
let reversed () : Lemma (relation true [0x30uy]) = ()

[@@expect_failure [19]]
let spelled_out () : Lemma (relation true [0x74uy; 0x72uy; 0x75uy; 0x65uy]) = ()

[@@expect_failure [19]]
let empty () : Lemma (relation false []) = ()

[@@expect_failure [19]]
let extra_byte () : Lemma (relation true [0x31uy; 0x30uy]) = ()
