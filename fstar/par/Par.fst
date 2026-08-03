module Par

// Re-export values and predicates (ordered to satisfy .fsti)
let in_store    = Par_Internal.in_store
let consumed    = Par_Internal.consumed
let stored      = Par_Internal.stored
let empty_store = Par_Internal.empty_store

// Public API wrappers (ordered to satisfy .fsti)
let store_request_uri   = Par_Internal.store_request_uri
let store_request       = Par_Internal.store_request
let consume_request_uri = Par_Internal.consume_request_uri

// Public lemmas (forwarders)
let lemma_consume_removes = Par_Internal.lemma_consume_removes
let lemma_par_binding     = Par_Internal.lemma_par_binding
