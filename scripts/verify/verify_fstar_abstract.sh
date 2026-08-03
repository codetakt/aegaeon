#!/usr/bin/env bash
set -euo pipefail

echo "[INFO] Running F* (abstract experiment, no --expose_interfaces)..."
work_dir="${AEG_FSTAR_ABSTRACT_TMPDIR:-}"
if [ -n "${work_dir}" ]; then
	rm -rf "${work_dir}"
	mkdir -p "${work_dir}"
else
	work_dir="$(mktemp -d "${TMPDIR:-/tmp}/aegaeon-fstar-abstract.XXXXXX")"
fi
cp -R fstar "${work_dir}/"
cd "${work_dir}/fstar"

cat >Par.fsti <<'EOF'
module Par

// Abstract types (hidden in Par.fst)
type par_store
type ticket: string -> Type0

val in_store  : par_store -> string -> Tot bool
val consumed  : par_store -> string -> Tot bool
val stored    : par_store -> string -> string -> string -> string -> Tot bool

val empty_store : par_store

val store_request_uri: s:par_store -> uri:string -> Pure par_store
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun s' -> in_store s' uri))

val store_request: s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Pure (par_store * ticket uri)
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun r -> let s' = fst r in in_store s' uri && stored s' uri state cc ru))

val consume_request_uri: s:par_store -> uri:string -> ticket uri -> Pure par_store
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (fun s' -> consumed s' uri))

val lemma_consume_removes:
  s:par_store -> uri:string -> t:ticket uri -> Lemma
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri)))

val lemma_par_binding:
  s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Lemma
  (requires (stored s uri state cc ru))
  (ensures  (in_store s uri))
EOF

# Implement abstract types concretely with no extra top-level declarations
cat >Par.fst <<'EOF'
module Par

type par_store = | PS : Par_Internal.par_store -> par_store
type ticket (u:string) = | TK : Par_Ticket.ticket u -> ticket u

let in_store (s:par_store) (u:string) =
  match s with | PS s0 -> Par_Internal.in_store s0 u

let consumed (s:par_store) (u:string) =
  match s with | PS s0 -> Par_Internal.consumed s0 u

let stored (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) =
  match s with | PS s0 -> Par_Internal.stored s0 uri state cc ru

let empty_store : par_store = PS Par_Internal.empty_store

let store_request_uri (s:par_store) (uri:string) =
  match s with | PS s0 -> PS (Par_Internal.store_request_uri s0 uri)

let store_request (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) =
  match s with | PS s0 ->
    let (s1, t1) = Par_Internal.store_request s0 uri state cc ru in
    (PS s1, TK t1)

let consume_request_uri (s:par_store) (uri:string) (t:ticket uri) =
  match s, t with | PS s0, TK t0 -> PS (Par_Internal.consume_request_uri s0 uri t0)

let lemma_consume_removes (s:par_store) (uri:string) (t:ticket uri) : Lemma
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri))) =
  match s, t with | PS s0, TK t0 -> Par_Internal.lemma_consume_removes s0 uri t0

let lemma_par_binding (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) : Lemma
  (requires (stored s uri state cc ru))
  (ensures  (in_store s uri)) =
  match s with | PS s0 -> Par_Internal.lemma_par_binding s0 uri state cc ru
EOF

FSTAR_SOURCES=(
	pkce/Pkce.fst
	par/Par_Ticket.fst
	par/Par_Internal.fst
	Par.fst
	par/Par_Steel.fst
	dpop/Dpop.fst
	token/Token.fst
	jose/Jose.fst
	auth/Pkjwt.fst
	token/Bearer_validation.fst
	Steel.Effect.fst
)
FSTAR_INCLUDES=()
if [ -n "${HACL_FSTAR_PATH:-}" ]; then FSTAR_INCLUDES+=(--include "$HACL_FSTAR_PATH"); fi
if [ -n "${STEEL_PATH:-}" ]; then FSTAR_INCLUDES+=(--include "$STEEL_PATH"); fi

# No --expose_interfaces for this experiment
set +e
fstar.exe --use_hints --hint_dir . "${FSTAR_INCLUDES[@]}" "${FSTAR_SOURCES[@]}"
STATUS=$?
set -e
if [ $STATUS -eq 0 ]; then
	echo "[OK] Abstract experiment passed"
else
	echo "[WARN] Abstract experiment failed (expected during exploration)"
fi
#!/usr/bin/env bash
set -euo pipefail

set +e
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
REPO_ROOT=$(dirname "$(dirname "$SCRIPT_DIR")")
ART="${OUT_DIR:-$REPO_ROOT}"
RUN_LOG="$ART/artifacts/fstar/abstract/run.log"
mkdir -p "$ART"/artifacts/fstar/abstract
echo "[INFO] Running F* (abstract experiment matrix)..." | tee "$RUN_LOG"

run_case() {
	local CASE_ID="$1"
	shift
	local GEN_IMPL="$1"
	shift
	local EXPOSE="$1"
	shift

	local base_dir="${AEG_FSTAR_ABSTRACT_TMP_BASE:-${TMPDIR:-/tmp}/aegaeon-fstar-abstract}"
	local work_dir="${base_dir}/fstar_abstract_${CASE_ID}_${GEN_IMPL}_${EXPOSE}"
	rm -rf "${work_dir}"
	mkdir -p "${work_dir}"
	cp -R "$REPO_ROOT"/fstar "${work_dir}/"
	cd "${work_dir}/fstar"

	cat >Par2.fsti <<'EOF'
module Par2

// Abstract types (hidden in Par.fst)
type par_store
type ticket: string -> Type0

val in_store  : par_store -> string -> Tot bool
val consumed  : par_store -> string -> Tot bool
val stored    : par_store -> string -> string -> string -> string -> Tot bool

val empty_store : par_store

val store_request_uri: s:par_store -> uri:string -> Pure par_store
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun s' -> in_store s' uri))

val store_request: s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Pure (par_store * ticket uri)
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun r -> let s' = fst r in in_store s' uri && stored s' uri state cc ru))

val consume_request_uri: s:par_store -> uri:string -> ticket uri -> Pure par_store
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (fun s' -> consumed s' uri))

val lemma_consume_removes:
  s:par_store -> uri:string -> t:ticket uri -> Lemma
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri)))

val lemma_par_binding:
  s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Lemma
  (requires (stored s uri state cc ru))
  (ensures  (in_store s uri))
EOF

	if [ "$GEN_IMPL" = "wrap" ]; then
		cat >Par2.fst <<'EOF'
module Par2
type par_store = | PS : Par_Internal.par_store -> par_store
type ticket (u:string) = | TK : Par_Ticket.ticket u -> ticket u
let in_store (s:par_store) (u:string) = match s with | PS s0 -> Par_Internal.in_store s0 u
let consumed (s:par_store) (u:string) = match s with | PS s0 -> Par_Internal.consumed s0 u
let stored (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) = match s with | PS s0 -> Par_Internal.stored s0 uri state cc ru
let empty_store : par_store = PS Par_Internal.empty_store
let store_request_uri (s:par_store) (uri:string) = match s with | PS s0 -> PS (Par_Internal.store_request_uri s0 uri)
let store_request (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) = match s with | PS s0 -> let (s1, t1) = Par_Internal.store_request s0 uri state cc ru in (PS s1, TK t1)
let consume_request_uri (s:par_store) (uri:string) (t:ticket uri) = match s, t with | PS s0, TK t0 -> PS (Par_Internal.consume_request_uri s0 uri t0)
let lemma_consume_removes (s:par_store) (uri:string) (t:ticket uri) : Lemma (requires (in_store s uri && not (consumed s uri))) (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri))) = match s, t with | PS s0, TK t0 -> Par_Internal.lemma_consume_removes s0 uri t0
let lemma_par_binding (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) : Lemma (requires (stored s uri state cc ru)) (ensures  (in_store s uri)) = match s with | PS s0 -> Par_Internal.lemma_par_binding s0 uri state cc ru
EOF
	else
		cat >Par2.fst <<'EOF'
module Par2
type par_store = Par_Internal.par_store
type ticket (u:string) = Par_Ticket.ticket u
let in_store    = Par_Internal.in_store
let consumed    = Par_Internal.consumed
let stored      = Par_Internal.stored
let empty_store = Par_Internal.empty_store
let store_request_uri   = Par_Internal.store_request_uri
let store_request       = Par_Internal.store_request
let consume_request_uri = Par_Internal.consume_request_uri
let lemma_consume_removes = Par_Internal.lemma_consume_removes
let lemma_par_binding     = Par_Internal.lemma_par_binding
EOF
	fi

	FSTAR_SOURCES=(
		pkce/Pkce.fst
		par/Par_Ticket.fst
		par/Par_Internal.fst
		Par2.fsti
		Par2.fst
		par/Par_Steel.fst
		dpop/Dpop.fst
		token/Token.fst
		jose/Jose.fst
		auth/Pkjwt.fst
		token/Bearer_validation.fst
		Steel.Effect.fst
	)
	FSTAR_INCLUDES=()
	if [ -n "${HACL_FSTAR_PATH:-}" ]; then FSTAR_INCLUDES+=(--include "$HACL_FSTAR_PATH"); fi
	if [ -n "${STEEL_PATH:-}" ]; then FSTAR_INCLUDES+=(--include "$STEEL_PATH"); fi

	if [ "$EXPOSE" = "on" ]; then
		CMD=(fstar.exe --use_hints --hint_dir . --expose_interfaces "${FSTAR_INCLUDES[@]}" "${FSTAR_SOURCES[@]}")
	else
		CMD=(fstar.exe --use_hints --hint_dir . "${FSTAR_INCLUDES[@]}" "${FSTAR_SOURCES[@]}")
	fi
	LOG="$ART/artifacts/fstar/abstract/case_${CASE_ID}_${GEN_IMPL}_${EXPOSE}.log"
	echo "[CASE $CASE_ID] impl=$GEN_IMPL expose=$EXPOSE" | tee -a "$RUN_LOG"
	"${CMD[@]}" >"$LOG" 2>&1
	if [ $? -eq 0 ]; then
		echo "  - PASS" | tee -a "$RUN_LOG"
	else
		echo "  - FAIL (see $(basename "${LOG##*/}"))" | tee -a "$RUN_LOG"
	fi
	cd "$REPO_ROOT" >/dev/null
}

run_case 1 wrap off
run_case 1 wrap on
run_case 2 alias off
run_case 2 alias on
echo "[INFO] Abstract experiment matrix complete. See $ART." | tee -a "$RUN_LOG"
