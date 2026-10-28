#![allow(dead_code)] // OpenAPI marker functions.
use crate::web::management::lti::{ActivateLtiRegistrationRequest, ReplaceLtiRegistrationRequest};

#[utoipa::path(get,path="/api/v1/teams/{teamId}/environments/{environmentId}/lti/registrations",tag="lti",
    params(("teamId"=String,Path),("environmentId"=String,Path),("clientId"=String,Query)),
    responses((status=200,description="Latest registration and Platform endpoints; activeRevision identifies the effective document",body=Object),
    (status=401,description="Authentication required"),(status=403,description="Human OWNER or ADMINISTRATOR required"),(status=404,description="Registration not found"),(status=503,description="Dependency unavailable")))]
pub(super) fn read() {}

#[utoipa::path(put,path="/api/v1/teams/{teamId}/environments/{environmentId}/lti/registrations",tag="lti",
    params(("teamId"=String,Path),("environmentId"=String,Path),("Origin"=String,Header),("X-CSRF-Token"=String,Header)),request_body=ReplaceLtiRegistrationRequest,
    responses((status=200,description="Immutable revision saved; secure default requires activation",body=Object),
    (status=400,description="Invalid configuration"),(status=401,description="Authentication required"),(status=403,description="Human lifecycle role, Origin and CSRF required"),
    (status=404,description="Current client not found"),(status=409,description="Stale baseRevision or permanent identity conflict"),(status=422,description="Malformed or unknown fields"),(status=503,description="Dependency or mandatory audit failed; transaction not released")))]
pub(super) fn replace() {}

#[utoipa::path(post,path="/api/v1/teams/{teamId}/environments/{environmentId}/lti/registrations/activate",tag="lti",
    params(("teamId"=String,Path),("environmentId"=String,Path),("Origin"=String,Header),("X-CSRF-Token"=String,Header)),request_body=ActivateLtiRegistrationRequest,
    responses((status=200,description="Exact latest revision activated",body=Object),
    (status=401,description="Authentication required"),(status=403,description="Human lifecycle role, Origin and CSRF required"),
    (status=404,description="Current registration or client not found"),(status=409,description="Stale revision"),(status=503,description="Dependency or mandatory audit failed")))]
pub(super) fn activate() {}
