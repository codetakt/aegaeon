module TestAuthorizationProjectionRevision

open Authorization.ProjectionRevision

[@@expect_failure [19]]
let enable_cannot_use_reserved_revision ()
  : Lemma (next (max_i64 - 2) 1 true <> None) = ()

[@@expect_failure [19]]
let enable_cannot_use_reserved_source ()
  : Lemma (next 0 (max_i64 - 1) true <> None) = ()

[@@expect_failure [19]]
let negative_base_is_not_creation ()
  : Lemma (next (-1) 1 true <> None) = ()

[@@expect_failure [19]]
let exhausted_counter_does_not_saturate ()
  : Lemma (next max_i64 1 false = Some max_i64) = ()
