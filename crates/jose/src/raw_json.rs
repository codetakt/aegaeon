use serde::de::DeserializeOwned;
#[cfg(test)]
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;
#[cfg(test)]
use std::sync::{LazyLock, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawJsonSurface {
    #[cfg(test)]
    GenericObject,
    JoseHeader,
    RequestObject,
    ClientRegistration,
    SoftwareStatement,
    PrivateKeyJwtPayload,
    JwtBearerAssertionPayload,
    OidcIdTokenPayload,
    JwtAccessTokenHeader,
    JwtAccessTokenPayload,
    FederationEntityStatement,
    FederationTrustMark,
}

#[cfg(test)]
pub const ALL_RAW_JSON_SURFACES: [RawJsonSurface; 12] = [
    RawJsonSurface::GenericObject,
    RawJsonSurface::JoseHeader,
    RawJsonSurface::RequestObject,
    RawJsonSurface::ClientRegistration,
    RawJsonSurface::SoftwareStatement,
    RawJsonSurface::PrivateKeyJwtPayload,
    RawJsonSurface::JwtBearerAssertionPayload,
    RawJsonSurface::OidcIdTokenPayload,
    RawJsonSurface::JwtAccessTokenHeader,
    RawJsonSurface::JwtAccessTokenPayload,
    RawJsonSurface::FederationEntityStatement,
    RawJsonSurface::FederationTrustMark,
];

#[cfg(not(test))]
pub const ALL_RAW_JSON_SURFACES: [RawJsonSurface; 11] = [
    RawJsonSurface::JoseHeader,
    RawJsonSurface::RequestObject,
    RawJsonSurface::ClientRegistration,
    RawJsonSurface::SoftwareStatement,
    RawJsonSurface::PrivateKeyJwtPayload,
    RawJsonSurface::JwtBearerAssertionPayload,
    RawJsonSurface::OidcIdTokenPayload,
    RawJsonSurface::JwtAccessTokenHeader,
    RawJsonSurface::JwtAccessTokenPayload,
    RawJsonSurface::FederationEntityStatement,
    RawJsonSurface::FederationTrustMark,
];

pub const PROMOTED_RAW_JSON_SURFACES: [RawJsonSurface; 11] = [
    RawJsonSurface::JoseHeader,
    RawJsonSurface::RequestObject,
    RawJsonSurface::ClientRegistration,
    RawJsonSurface::SoftwareStatement,
    RawJsonSurface::PrivateKeyJwtPayload,
    RawJsonSurface::JwtBearerAssertionPayload,
    RawJsonSurface::OidcIdTokenPayload,
    RawJsonSurface::JwtAccessTokenHeader,
    RawJsonSurface::JwtAccessTokenPayload,
    RawJsonSurface::FederationEntityStatement,
    RawJsonSurface::FederationTrustMark,
];

#[cfg(test)]
pub const COMPAT_ONLY_RAW_JSON_SURFACES: [RawJsonSurface; 1] = [RawJsonSurface::GenericObject];

#[cfg(not(test))]
pub const COMPAT_ONLY_RAW_JSON_SURFACES: [RawJsonSurface; 0] = [];

impl RawJsonSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        raw_json_surface_metadata(self).name
    }

    #[must_use]
    pub const fn uses_verified_structural_v1(self) -> bool {
        matches!(
            self,
            RawJsonSurface::JoseHeader
                | RawJsonSurface::RequestObject
                | RawJsonSurface::ClientRegistration
                | RawJsonSurface::SoftwareStatement
                | RawJsonSurface::PrivateKeyJwtPayload
                | RawJsonSurface::JwtBearerAssertionPayload
                | RawJsonSurface::OidcIdTokenPayload
                | RawJsonSurface::JwtAccessTokenHeader
                | RawJsonSurface::JwtAccessTokenPayload
                | RawJsonSurface::FederationEntityStatement
                | RawJsonSurface::FederationTrustMark
        )
    }

    #[must_use]
    pub const fn is_promoted(self) -> bool {
        self.uses_verified_structural_v1()
    }

    #[must_use]
    pub const fn is_compat_only(self) -> bool {
        !self.is_promoted()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJsonBackend {
    SerdeCompat,
    // Verified structural parser backend. This is wired only for promoted
    // surfaces; all other surfaces must still fail closed.
    VerifiedStructuralV1,
}

impl RawJsonBackend {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RawJsonBackend::SerdeCompat => "serde-compat",
            RawJsonBackend::VerifiedStructuralV1 => "verified-structural-v1",
        }
    }

    #[must_use]
    pub const fn is_verified(self) -> bool {
        match self {
            RawJsonBackend::SerdeCompat => false,
            RawJsonBackend::VerifiedStructuralV1 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJsonClaimBoundary {
    TopLevelObjectMembers,
    RawBytes,
}

impl RawJsonClaimBoundary {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RawJsonClaimBoundary::TopLevelObjectMembers => "top-level-object-members",
            RawJsonClaimBoundary::RawBytes => "raw-bytes",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawJsonClaimPosture {
    pub surface: RawJsonSurface,
    pub backend: RawJsonBackend,
    pub boundary: RawJsonClaimBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJsonBackendPolicySource {
    Default,
    GlobalOverride,
    SurfaceOverride,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJsonBackendPolicy {
    pub surface: RawJsonSurface,
    pub backend: RawJsonBackend,
    pub source: RawJsonBackendPolicySource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJsonBackendPolicyError {
    pub surface: RawJsonSurface,
    pub source_var: &'static str,
    pub requested: String,
}

impl fmt::Display for RawJsonBackendPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unsupported raw JSON backend `{}` for surface `{}` via {}",
            self.requested,
            self.surface.as_str(),
            self.source_var
        )
    }
}

impl std::error::Error for RawJsonBackendPolicyError {}

#[derive(Debug, Clone, PartialEq)]
pub struct RawJsonParseReport<T> {
    pub value: T,
    pub backend: RawJsonBackend,
    pub surface: RawJsonSurface,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawJsonObjectMember {
    pub key: String,
    pub value: Value,
}

#[cfg(test)]
struct RawJsonObjectMembers(Vec<RawJsonObjectMember>);

#[cfg(test)]
impl<'de> Deserialize<'de> for RawJsonObjectMembers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawJsonObjectMembersVisitor;

        impl<'de> Visitor<'de> for RawJsonObjectMembersVisitor {
            type Value = RawJsonObjectMembers;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut members = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value = map.next_value::<Value>()?;
                    members.push(RawJsonObjectMember { key, value });
                }
                Ok(RawJsonObjectMembers(members))
            }
        }

        deserializer.deserialize_map(RawJsonObjectMembersVisitor)
    }
}

#[derive(Debug)]
pub enum RawJsonObjectError {
    InvalidBackendPolicy(RawJsonBackendPolicyError),
    InvalidJson(serde_json::Error),
    TrailingBytes(serde_json::Error),
    DuplicateKey,
    InvalidShape(serde_json::Error),
}

impl std::fmt::Display for RawJsonObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawJsonObjectError::InvalidBackendPolicy(err) => {
                write!(f, "invalid backend policy: {err}")
            }
            RawJsonObjectError::InvalidJson(err) => write!(f, "invalid json: {err}"),
            RawJsonObjectError::TrailingBytes(err) => write!(f, "trailing bytes: {err}"),
            RawJsonObjectError::DuplicateKey => f.write_str("duplicate key"),
            RawJsonObjectError::InvalidShape(err) => write!(f, "invalid shape: {err}"),
        }
    }
}

impl std::error::Error for RawJsonObjectError {}

#[cfg(test)]
fn classify_object_member_error(err: serde_json::Error) -> RawJsonObjectError {
    match err.classify() {
        serde_json::error::Category::Data => RawJsonObjectError::InvalidShape(err),
        serde_json::error::Category::Io
        | serde_json::error::Category::Syntax
        | serde_json::error::Category::Eof => RawJsonObjectError::InvalidJson(err),
    }
}

#[cfg(test)]
fn parse_json_object_members_serde(
    payload: &[u8],
) -> Result<Vec<RawJsonObjectMember>, RawJsonObjectError> {
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let RawJsonObjectMembers(members) = RawJsonObjectMembers::deserialize(&mut deserializer)
        .map_err(classify_object_member_error)?;
    deserializer
        .end()
        .map_err(RawJsonObjectError::TrailingBytes)?;
    Ok(members)
}

fn parse_json_object_members_verified_structural_v1_for_jose_header(
    payload: &[u8],
) -> Result<Vec<RawJsonObjectMember>, RawJsonObjectError> {
    crate::json_lowstar::parse_json_header_members_via_structural_ffi_for_raw_json(payload)
}

fn parse_json_object_members_verified_structural_v1_generic(
    payload: &[u8],
) -> Result<Vec<RawJsonObjectMember>, RawJsonObjectError> {
    crate::json_lowstar::parse_json_members_via_structural_ffi_for_raw_json(payload)
}

type RawJsonMembersParser = fn(&[u8]) -> Result<Vec<RawJsonObjectMember>, RawJsonObjectError>;

#[derive(Clone, Copy)]
struct RawJsonBackendSelection {
    backend: RawJsonBackend,
    parse_members: RawJsonMembersParser,
}

#[derive(Clone, Copy)]
struct RawJsonSurfaceMetadata {
    name: &'static str,
    env_var: &'static str,
    default_backend: RawJsonBackend,
    current_claim_boundary: RawJsonClaimBoundary,
}

const RAW_JSON_BACKEND_ENV: &str = "AEGAEON_RAW_JSON_BACKEND";
#[cfg(test)]
const RAW_JSON_BACKEND_GENERIC_ENV: &str = "AEGAEON_RAW_JSON_BACKEND_GENERIC_OBJECT";
const RAW_JSON_BACKEND_JOSE_HEADER_ENV: &str = "AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER";
const RAW_JSON_BACKEND_REQUEST_OBJECT_ENV: &str = "AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT";
const RAW_JSON_BACKEND_CLIENT_REGISTRATION_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION";
const RAW_JSON_BACKEND_SOFTWARE_STATEMENT_ENV: &str = "AEGAEON_RAW_JSON_BACKEND_SOFTWARE_STATEMENT";
const RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD";
const RAW_JSON_BACKEND_JWT_BEARER_ASSERTION_PAYLOAD_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_JWT_BEARER_ASSERTION_PAYLOAD";
const RAW_JSON_BACKEND_OIDC_ID_TOKEN_PAYLOAD_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_OIDC_ID_TOKEN_PAYLOAD";
const RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER";
const RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_PAYLOAD_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_PAYLOAD";
const RAW_JSON_BACKEND_FEDERATION_ENTITY_STATEMENT_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_FEDERATION_ENTITY_STATEMENT";
const RAW_JSON_BACKEND_FEDERATION_TRUST_MARK_ENV: &str =
    "AEGAEON_RAW_JSON_BACKEND_FEDERATION_TRUST_MARK";

#[cfg(test)]
pub(crate) static RAW_JSON_TEST_ENV_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[must_use]
pub const fn raw_json_backend_env_var() -> &'static str {
    RAW_JSON_BACKEND_ENV
}

const fn raw_json_surface_metadata(surface: RawJsonSurface) -> RawJsonSurfaceMetadata {
    match surface {
        #[cfg(test)]
        RawJsonSurface::GenericObject => RawJsonSurfaceMetadata {
            name: "generic-object",
            env_var: RAW_JSON_BACKEND_GENERIC_ENV,
            default_backend: RawJsonBackend::SerdeCompat,
            current_claim_boundary: RawJsonClaimBoundary::TopLevelObjectMembers,
        },
        RawJsonSurface::JoseHeader => RawJsonSurfaceMetadata {
            name: "jose-header",
            env_var: RAW_JSON_BACKEND_JOSE_HEADER_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::RequestObject => RawJsonSurfaceMetadata {
            name: "request-object",
            env_var: RAW_JSON_BACKEND_REQUEST_OBJECT_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::ClientRegistration => RawJsonSurfaceMetadata {
            name: "client-registration",
            env_var: RAW_JSON_BACKEND_CLIENT_REGISTRATION_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::SoftwareStatement => RawJsonSurfaceMetadata {
            name: "software-statement",
            env_var: RAW_JSON_BACKEND_SOFTWARE_STATEMENT_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::PrivateKeyJwtPayload => RawJsonSurfaceMetadata {
            name: "private-key-jwt-payload",
            env_var: RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::JwtBearerAssertionPayload => RawJsonSurfaceMetadata {
            name: "jwt-bearer-assertion-payload",
            env_var: RAW_JSON_BACKEND_JWT_BEARER_ASSERTION_PAYLOAD_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::OidcIdTokenPayload => RawJsonSurfaceMetadata {
            name: "oidc-id-token-payload",
            env_var: RAW_JSON_BACKEND_OIDC_ID_TOKEN_PAYLOAD_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::JwtAccessTokenHeader => RawJsonSurfaceMetadata {
            name: "jwt-access-token-header",
            env_var: RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::JwtAccessTokenPayload => RawJsonSurfaceMetadata {
            name: "jwt-access-token-payload",
            env_var: RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_PAYLOAD_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::FederationEntityStatement => RawJsonSurfaceMetadata {
            name: "federation-entity-statement",
            env_var: RAW_JSON_BACKEND_FEDERATION_ENTITY_STATEMENT_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
        RawJsonSurface::FederationTrustMark => RawJsonSurfaceMetadata {
            name: "federation-trust-mark",
            env_var: RAW_JSON_BACKEND_FEDERATION_TRUST_MARK_ENV,
            default_backend: RawJsonBackend::VerifiedStructuralV1,
            current_claim_boundary: RawJsonClaimBoundary::RawBytes,
        },
    }
}

#[must_use]
pub const fn raw_json_backend_env_var_for_surface(surface: RawJsonSurface) -> &'static str {
    raw_json_surface_metadata(surface).env_var
}

fn parse_backend_name_for_surface(
    surface: RawJsonSurface,
    source_var: &'static str,
    raw: &str,
) -> Result<RawJsonBackend, RawJsonBackendPolicyError> {
    let normalized = raw.trim();
    match normalized {
        #[cfg(test)]
        "serde-compat" | "serde_compat" => Ok(RawJsonBackend::SerdeCompat),
        "verified-structural-v1" | "verified_structural_v1" => {
            if surface.uses_verified_structural_v1() {
                Ok(RawJsonBackend::VerifiedStructuralV1)
            } else {
                Err(raw_json_backend_policy_error(
                    surface, source_var, normalized,
                ))
            }
        }
        _ => Err(raw_json_backend_policy_error(
            surface, source_var, normalized,
        )),
    }
}

fn raw_json_backend_policy_error(
    surface: RawJsonSurface,
    source_var: &'static str,
    requested: &str,
) -> RawJsonBackendPolicyError {
    RawJsonBackendPolicyError {
        surface,
        source_var,
        requested: requested.to_string(),
    }
}

/// Resolve the backend policy for a surface from explicit override values.
///
/// # Errors
///
/// Returns [`RawJsonBackendPolicyError`] when either override requests an
/// unsupported backend name.
pub fn backend_policy_for_surface_from_values(
    surface: RawJsonSurface,
    surface_value: Option<&str>,
    global_value: Option<&str>,
) -> Result<RawJsonBackendPolicy, RawJsonBackendPolicyError> {
    if let Some(raw) = surface_value {
        let backend = parse_backend_name_for_surface(
            surface,
            raw_json_backend_env_var_for_surface(surface),
            raw,
        )?;
        return Ok(RawJsonBackendPolicy {
            surface,
            backend,
            source: RawJsonBackendPolicySource::SurfaceOverride,
        });
    }

    if let Some(raw) = global_value {
        let backend = parse_backend_name_for_surface(surface, raw_json_backend_env_var(), raw)?;
        return Ok(RawJsonBackendPolicy {
            surface,
            backend,
            source: RawJsonBackendPolicySource::GlobalOverride,
        });
    }

    Ok(RawJsonBackendPolicy {
        surface,
        backend: raw_json_surface_metadata(surface).default_backend,
        source: RawJsonBackendPolicySource::Default,
    })
}

/// Resolve the backend policy for a surface from environment variables.
///
/// # Errors
///
/// Returns [`RawJsonBackendPolicyError`] when an override environment variable
/// requests an unsupported backend name.
pub fn backend_policy_for_surface(
    surface: RawJsonSurface,
) -> Result<RawJsonBackendPolicy, RawJsonBackendPolicyError> {
    let surface_value = std::env::var(raw_json_backend_env_var_for_surface(surface)).ok();
    let global_value = std::env::var(raw_json_backend_env_var()).ok();
    backend_policy_for_surface_from_values(
        surface,
        surface_value.as_deref(),
        global_value.as_deref(),
    )
}

#[cfg(test)]
fn serde_compat_backend_selection() -> RawJsonBackendSelection {
    RawJsonBackendSelection {
        backend: RawJsonBackend::SerdeCompat,
        parse_members: parse_json_object_members_serde,
    }
}

fn surface_specific_backend_selection_for_surface(
    surface: RawJsonSurface,
    backend: RawJsonBackend,
) -> Option<RawJsonBackendSelection> {
    match (surface, backend) {
        (RawJsonSurface::JoseHeader, RawJsonBackend::VerifiedStructuralV1) => {
            Some(RawJsonBackendSelection {
                backend: RawJsonBackend::VerifiedStructuralV1,
                parse_members: parse_json_object_members_verified_structural_v1_for_jose_header,
            })
        }
        (
            RawJsonSurface::RequestObject
            | RawJsonSurface::ClientRegistration
            | RawJsonSurface::SoftwareStatement
            | RawJsonSurface::PrivateKeyJwtPayload
            | RawJsonSurface::JwtBearerAssertionPayload
            | RawJsonSurface::OidcIdTokenPayload
            | RawJsonSurface::JwtAccessTokenHeader
            | RawJsonSurface::JwtAccessTokenPayload
            | RawJsonSurface::FederationEntityStatement
            | RawJsonSurface::FederationTrustMark,
            RawJsonBackend::VerifiedStructuralV1,
        ) => Some(RawJsonBackendSelection {
            backend: RawJsonBackend::VerifiedStructuralV1,
            parse_members: parse_json_object_members_verified_structural_v1_generic,
        }),
        _ => None,
    }
}

fn backend_selection_for_surface_and_backend(
    backend: RawJsonBackend,
    surface: RawJsonSurface,
) -> Option<RawJsonBackendSelection> {
    let selection = surface_specific_backend_selection_for_surface(surface, backend);
    #[cfg(test)]
    {
        if selection.is_none() && backend == RawJsonBackend::SerdeCompat {
            return Some(serde_compat_backend_selection());
        }
    }
    selection
}

pub(crate) fn parse_json_object_members_with_backend_for_surface(
    surface: RawJsonSurface,
    backend: RawJsonBackend,
    payload: &[u8],
) -> Result<RawJsonParseReport<Vec<RawJsonObjectMember>>, RawJsonObjectError> {
    let selection =
        backend_selection_for_surface_and_backend(backend, surface).ok_or_else(|| {
            RawJsonObjectError::InvalidJson(serde_json::Error::io(std::io::Error::other(format!(
                "backend `{}` is not wired for surface `{}`",
                backend.as_str(),
                surface.as_str()
            ))))
        })?;
    let value = (selection.parse_members)(payload)?;
    Ok(RawJsonParseReport {
        value,
        backend: selection.backend,
        surface,
    })
}

#[must_use]
pub fn current_backend_for_surface(surface: RawJsonSurface) -> RawJsonBackend {
    raw_json_surface_metadata(surface).default_backend
}

#[must_use]
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer current_backend_for_surface(...)"
)]
pub fn current_backend() -> RawJsonBackend {
    current_backend_for_surface(RawJsonSurface::GenericObject)
}

#[must_use]
pub fn current_claim_boundary_for_surface(surface: RawJsonSurface) -> RawJsonClaimBoundary {
    raw_json_surface_metadata(surface).current_claim_boundary
}

#[must_use]
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer current_claim_boundary_for_surface(...)"
)]
pub fn current_claim_boundary() -> RawJsonClaimBoundary {
    current_claim_boundary_for_surface(RawJsonSurface::GenericObject)
}

#[must_use]
pub fn current_claim_posture_for_surface(surface: RawJsonSurface) -> RawJsonClaimPosture {
    RawJsonClaimPosture {
        surface,
        backend: current_backend_for_surface(surface),
        boundary: current_claim_boundary_for_surface(surface),
    }
}

#[must_use]
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer current_claim_posture_for_surface(...)"
)]
pub fn current_claim_posture() -> RawJsonClaimPosture {
    current_claim_posture_for_surface(RawJsonSurface::GenericObject)
}

/// Parse a JSON object into ordered members while recording backend metadata.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when backend policy resolution fails or the
/// selected backend rejects the payload.
pub fn parse_json_object_members_with_report_for_surface(
    surface: RawJsonSurface,
    payload: &[u8],
) -> Result<RawJsonParseReport<Vec<RawJsonObjectMember>>, RawJsonObjectError> {
    let policy =
        backend_policy_for_surface(surface).map_err(RawJsonObjectError::InvalidBackendPolicy)?;
    parse_json_object_members_with_backend_for_surface(surface, policy.backend, payload)
}

/// Parse a JSON object into ordered members while recording backend metadata.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when backend policy resolution fails or the
/// selected backend rejects the payload.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer parse_json_object_members_with_report_for_surface(...)"
)]
pub fn parse_json_object_members_with_report(
    payload: &[u8],
) -> Result<RawJsonParseReport<Vec<RawJsonObjectMember>>, RawJsonObjectError> {
    parse_json_object_members_with_report_for_surface(RawJsonSurface::GenericObject, payload)
}

/// Parse a JSON object into ordered members.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when backend policy resolution fails or the
/// selected backend rejects the payload.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer parse_json_object_members_with_report_for_surface(...)"
)]
pub fn parse_json_object_members(
    payload: &[u8],
) -> Result<Vec<RawJsonObjectMember>, RawJsonObjectError> {
    parse_json_object_members_with_report_for_surface(RawJsonSurface::GenericObject, payload)
        .map(|report| report.value)
}

/// Reject duplicate object keys.
///
/// # Errors
///
/// Returns [`RawJsonObjectError::DuplicateKey`] when `members` contains the
/// same key more than once.
pub fn ensure_unique_object_keys(
    members: &[RawJsonObjectMember],
) -> Result<(), RawJsonObjectError> {
    let mut seen = HashSet::with_capacity(members.len());
    for member in members {
        if !seen.insert(member.key.as_str()) {
            return Err(RawJsonObjectError::DuplicateKey);
        }
    }
    Ok(())
}

fn object_from_unique_members(
    members: Vec<RawJsonObjectMember>,
) -> Result<Map<String, Value>, RawJsonObjectError> {
    ensure_unique_object_keys(&members)?;

    let mut object = Map::with_capacity(members.len());
    for member in members {
        object.insert(member.key, member.value);
    }

    Ok(object)
}

/// Deserialize a JSON object on the compat semantic-decode path after
/// rejecting duplicate keys.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(...)"
)]
pub fn deserialize_compat_json_object_without_duplicate_keys<T: DeserializeOwned>(
    payload: &[u8],
) -> Result<T, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(
        RawJsonSurface::GenericObject,
        payload,
    )
    .map(|report| report.value)
}

/// Deserialize a JSON object on the compat semantic-decode path after
/// rejecting duplicate keys with an explicit caller-selected backend for the
/// given surface.
///
/// This bypasses environment policy resolution so higher layers can keep the
/// promoted surface policy while still reusing the serde compatibility path in
/// builds where the structural parser is intentionally unavailable.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when the selected backend rejects the
/// payload, duplicate-key checking fails, or the final shape conversion fails.
pub fn deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface_and_backend<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    backend: RawJsonBackend,
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    let RawJsonParseReport {
        value: members,
        backend,
        surface,
    } = parse_json_object_members_with_backend_for_surface(surface, backend, payload)?;
    let object = object_from_unique_members(members)?;
    let value =
        serde_json::from_value(Value::Object(object)).map_err(RawJsonObjectError::InvalidShape)?;
    Ok(RawJsonParseReport {
        value,
        backend,
        surface,
    })
}

/// Deserialize a JSON object on the compat semantic-decode path after
/// rejecting duplicate keys and record backend metadata.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
pub fn deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    let report = parse_json_object_members_with_report_for_surface(surface, payload)?;
    let RawJsonParseReport {
        value: members,
        backend,
        surface,
    } = report;
    let object = object_from_unique_members(members)?;
    let value =
        serde_json::from_value(Value::Object(object)).map_err(RawJsonObjectError::InvalidShape)?;
    Ok(RawJsonParseReport {
        value,
        backend,
        surface,
    })
}

/// Deserialize a JSON object on the compat semantic-decode path after
/// rejecting duplicate keys and record backend metadata.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(...)"
)]
pub fn deserialize_compat_json_object_without_duplicate_keys_with_report<T: DeserializeOwned>(
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(
        RawJsonSurface::GenericObject,
        payload,
    )
}

/// Legacy convenience wrapper for the compat semantic-decode path.
///
/// Promoted surfaces should prefer surface-specific typed decoders over this
/// broad object deserialization API.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(...)"
)]
pub fn deserialize_json_object_without_duplicate_keys<T: DeserializeOwned>(
    payload: &[u8],
) -> Result<T, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(
        RawJsonSurface::GenericObject,
        payload,
    )
    .map(|report| report.value)
}

/// Legacy convenience wrapper for the compat semantic-decode path.
///
/// Promoted surfaces should prefer surface-specific typed decoders over this
/// broad object deserialization API.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
pub fn deserialize_json_object_without_duplicate_keys_with_report_for_surface_and_backend<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    backend: RawJsonBackend,
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface_and_backend(
        surface, backend, payload,
    )
}

/// Legacy convenience wrapper for the compat semantic-decode path.
///
/// Promoted surfaces should prefer surface-specific typed decoders over this
/// broad object deserialization API.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when backend policy resolution, parsing,
/// duplicate-key checking, or the final shape conversion fails.
pub fn deserialize_json_object_without_duplicate_keys_with_report_for_surface<
    T: DeserializeOwned,
>(
    surface: RawJsonSurface,
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(surface, payload)
}

/// Legacy convenience wrapper for the compat semantic-decode path.
///
/// # Errors
///
/// Returns [`RawJsonObjectError`] when parsing, duplicate-key checking, or the
/// final shape conversion fails.
#[cfg(test)]
#[deprecated(
    note = "legacy generic-object convenience wrapper; prefer deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(...)"
)]
pub fn deserialize_json_object_without_duplicate_keys_with_report<T: DeserializeOwned>(
    payload: &[u8],
) -> Result<RawJsonParseReport<T>, RawJsonObjectError> {
    deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface(
        RawJsonSurface::GenericObject,
        payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::Error as IoError;

    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Claims {
        iss: String,
        sub: String,
    }

    type TestResult = Result<(), Box<dyn Error>>;

    fn structural_parser_unavailable(err: &RawJsonObjectError) -> bool {
        matches!(
            err,
            RawJsonObjectError::InvalidJson(inner)
                if inner
                    .to_string()
                    .contains("raw JSON structural parser unavailable for this input or build")
        )
    }

    fn structural_report_when_available<T>(
        result: Result<RawJsonParseReport<T>, RawJsonObjectError>,
    ) -> Result<Option<RawJsonParseReport<T>>, RawJsonObjectError> {
        match result {
            Ok(report) => Ok(Some(report)),
            Err(err) if structural_parser_unavailable(&err) => Ok(None),
            Err(err) => Err(err),
        }
    }

    #[test]
    fn parse_json_object_members_preserves_order() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let members = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::GenericObject,
            br#"{"alg":"HS256","kid":"key-1","typ":"JWT"}"#,
        )?
        .value;

        assert_eq!(members.len(), 3);
        assert_eq!(members[0].key, "alg");
        assert_eq!(members[1].key, "kid");
        assert_eq!(members[2].key, "typ");
        Ok(())
    }

    #[test]
    fn ensure_unique_object_keys_rejects_duplicates() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let members = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::GenericObject,
            br#"{"alg":"HS256","alg":"RS256"}"#,
        )?
        .value;
        assert!(matches!(
            ensure_unique_object_keys(&members).err(),
            Some(RawJsonObjectError::DuplicateKey)
        ));
        Ok(())
    }

    #[test]
    fn deserialize_json_object_without_duplicate_keys_rejects_duplicates() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        assert!(matches!(
            deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface::<Claims>(
                RawJsonSurface::GenericObject,
                br#"{"iss":"issuer","iss":"evil","sub":"subject"}"#,
            )
            .err(),
            Some(RawJsonObjectError::DuplicateKey)
        ));
    }

    #[test]
    fn parse_json_object_members_rejects_trailing_bytes() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        assert!(matches!(
            parse_json_object_members_with_report_for_surface(
                RawJsonSurface::GenericObject,
                br#"{"alg":"HS256"}x"#,
            )
            .err(),
            Some(RawJsonObjectError::TrailingBytes(_))
        ));
    }

    #[test]
    fn parse_json_object_members_rejects_non_object_shape() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        assert!(matches!(
            parse_json_object_members_with_report_for_surface(
                RawJsonSurface::GenericObject,
                br#"["alg","HS256"]"#,
            )
            .err(),
            Some(RawJsonObjectError::InvalidShape(_))
        ));
    }

    #[test]
    fn parse_report_records_current_backend() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let report = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::GenericObject,
            br#"{"alg":"HS256","typ":"JWT"}"#,
        )?;
        assert_eq!(report.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(report.backend.as_str(), "serde-compat");
        assert_eq!(report.surface, RawJsonSurface::GenericObject);
        assert!(!report.backend.is_verified());
        Ok(())
    }

    #[test]
    fn deserialize_report_records_current_backend() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let report = deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface::<
            Claims,
        >(
            RawJsonSurface::GenericObject,
            br#"{"iss":"issuer","sub":"subject"}"#,
        )?;
        assert_eq!(report.value.iss, "issuer");
        assert_eq!(report.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(report.surface, RawJsonSurface::GenericObject);
        assert!(!report.backend.is_verified());
        Ok(())
    }

    #[test]
    fn parse_report_records_requested_surface_for_all_surfaces() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        for surface in ALL_RAW_JSON_SURFACES {
            let Some(report) = structural_report_when_available(
                parse_json_object_members_with_report_for_surface(
                    surface,
                    br#"{"alg":"HS256","typ":"JWT"}"#,
                ),
            )?
            else {
                continue;
            };
            let expected_backend = if surface.uses_verified_structural_v1() {
                RawJsonBackend::VerifiedStructuralV1
            } else {
                RawJsonBackend::SerdeCompat
            };
            assert_eq!(report.backend, expected_backend);
            assert_eq!(report.surface, surface);
        }
        Ok(())
    }

    #[test]
    fn deserialize_report_records_requested_surface_for_all_surfaces_on_compat_backend(
    ) -> TestResult {
        for surface in ALL_RAW_JSON_SURFACES {
            let report = deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface_and_backend::<
                Claims,
            >(
                surface,
                RawJsonBackend::SerdeCompat,
                br#"{"iss":"issuer","sub":"subject"}"#,
            )?;
            assert_eq!(report.value.sub, "subject");
            assert_eq!(report.backend, RawJsonBackend::SerdeCompat);
            assert_eq!(report.surface, surface);
        }
        Ok(())
    }

    #[test]
    fn all_current_surfaces_select_expected_default_backend() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        for surface in ALL_RAW_JSON_SURFACES {
            let backend = current_backend_for_surface(surface);
            let expected_backend = if surface.uses_verified_structural_v1() {
                RawJsonBackend::VerifiedStructuralV1
            } else {
                RawJsonBackend::SerdeCompat
            };
            assert_eq!(backend, expected_backend);
            assert_eq!(backend.as_str(), expected_backend.as_str());
            assert_eq!(backend.is_verified(), surface.uses_verified_structural_v1());
        }
    }

    #[test]
    fn all_current_surfaces_use_expected_claim_boundary() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        for surface in ALL_RAW_JSON_SURFACES {
            let boundary = current_claim_boundary_for_surface(surface);
            let expected_boundary = if surface.uses_verified_structural_v1() {
                RawJsonClaimBoundary::RawBytes
            } else {
                RawJsonClaimBoundary::TopLevelObjectMembers
            };
            assert_eq!(boundary, expected_boundary);
            assert_eq!(boundary.as_str(), expected_boundary.as_str());
        }
    }

    #[test]
    fn current_claim_posture_records_backend_and_boundary_for_all_surfaces() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        let default_posture = current_claim_posture_for_surface(RawJsonSurface::GenericObject);
        assert_eq!(default_posture.surface, RawJsonSurface::GenericObject);
        assert_eq!(default_posture.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(
            default_posture.boundary,
            RawJsonClaimBoundary::TopLevelObjectMembers
        );

        for surface in ALL_RAW_JSON_SURFACES {
            let posture = current_claim_posture_for_surface(surface);
            let expected_backend = if surface.uses_verified_structural_v1() {
                RawJsonBackend::VerifiedStructuralV1
            } else {
                RawJsonBackend::SerdeCompat
            };
            let expected_boundary = if surface.uses_verified_structural_v1() {
                RawJsonClaimBoundary::RawBytes
            } else {
                RawJsonClaimBoundary::TopLevelObjectMembers
            };
            assert_eq!(posture.surface, surface);
            assert_eq!(posture.backend, expected_backend);
            assert_eq!(posture.boundary, expected_boundary);
        }
    }

    #[test]
    fn promoted_and_compat_surface_inventories_cover_all_surfaces_without_overlap() {
        let mut seen = HashSet::new();

        for surface in PROMOTED_RAW_JSON_SURFACES {
            assert!(surface.is_promoted());
            assert!(!surface.is_compat_only());
            assert!(seen.insert(surface));
        }

        for surface in COMPAT_ONLY_RAW_JSON_SURFACES {
            assert!(surface.is_compat_only());
            assert!(!surface.is_promoted());
            assert!(seen.insert(surface));
        }

        assert_eq!(seen.len(), ALL_RAW_JSON_SURFACES.len());
        for surface in ALL_RAW_JSON_SURFACES {
            assert!(seen.contains(&surface));
        }
    }

    #[test]
    fn backend_policy_defaults_to_surface_default_backend() -> TestResult {
        let policy =
            backend_policy_for_surface_from_values(RawJsonSurface::JoseHeader, None, None)?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(policy.source, RawJsonBackendPolicySource::Default);

        let request_object_policy =
            backend_policy_for_surface_from_values(RawJsonSurface::RequestObject, None, None)?;
        assert_eq!(request_object_policy.surface, RawJsonSurface::RequestObject);
        assert_eq!(
            request_object_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            request_object_policy.source,
            RawJsonBackendPolicySource::Default
        );

        let client_registration_policy =
            backend_policy_for_surface_from_values(RawJsonSurface::ClientRegistration, None, None)?;
        assert_eq!(
            client_registration_policy.surface,
            RawJsonSurface::ClientRegistration
        );
        assert_eq!(
            client_registration_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            client_registration_policy.source,
            RawJsonBackendPolicySource::Default
        );

        let software_statement_policy =
            backend_policy_for_surface_from_values(RawJsonSurface::SoftwareStatement, None, None)?;
        assert_eq!(
            software_statement_policy.surface,
            RawJsonSurface::SoftwareStatement
        );
        assert_eq!(
            software_statement_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            software_statement_policy.source,
            RawJsonBackendPolicySource::Default
        );

        let private_key_jwt_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::PrivateKeyJwtPayload,
            None,
            None,
        )?;
        assert_eq!(
            private_key_jwt_policy.surface,
            RawJsonSurface::PrivateKeyJwtPayload
        );
        assert_eq!(
            private_key_jwt_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            private_key_jwt_policy.source,
            RawJsonBackendPolicySource::Default
        );

        let jwt_bearer_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JwtBearerAssertionPayload,
            None,
            None,
        )?;
        assert_eq!(
            jwt_bearer_policy.surface,
            RawJsonSurface::JwtBearerAssertionPayload
        );
        assert_eq!(
            jwt_bearer_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            jwt_bearer_policy.source,
            RawJsonBackendPolicySource::Default
        );

        let oidc_policy =
            backend_policy_for_surface_from_values(RawJsonSurface::OidcIdTokenPayload, None, None)?;
        assert_eq!(oidc_policy.surface, RawJsonSurface::OidcIdTokenPayload);
        assert_eq!(oidc_policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(oidc_policy.source, RawJsonBackendPolicySource::Default);
        Ok(())
    }

    #[test]
    fn backend_policy_uses_global_override() -> TestResult {
        let policy = backend_policy_for_surface_from_values(
            RawJsonSurface::RequestObject,
            None,
            Some("serde-compat"),
        )?;
        assert_eq!(policy.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(policy.source, RawJsonBackendPolicySource::GlobalOverride);
        Ok(())
    }

    #[test]
    fn backend_policy_prefers_surface_override() -> TestResult {
        let policy = backend_policy_for_surface_from_values(
            RawJsonSurface::FederationTrustMark,
            Some("serde_compat"),
            Some("serde-compat"),
        )?;
        assert_eq!(policy.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(policy.source, RawJsonBackendPolicySource::SurfaceOverride);
        Ok(())
    }

    #[test]
    fn every_current_surface_uses_expected_backend_env_var() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        let cases = [
            (
                RawJsonSurface::GenericObject,
                "AEGAEON_RAW_JSON_BACKEND_GENERIC_OBJECT",
            ),
            (
                RawJsonSurface::JoseHeader,
                "AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER",
            ),
            (
                RawJsonSurface::RequestObject,
                "AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT",
            ),
            (
                RawJsonSurface::ClientRegistration,
                "AEGAEON_RAW_JSON_BACKEND_CLIENT_REGISTRATION",
            ),
            (
                RawJsonSurface::SoftwareStatement,
                "AEGAEON_RAW_JSON_BACKEND_SOFTWARE_STATEMENT",
            ),
            (
                RawJsonSurface::PrivateKeyJwtPayload,
                "AEGAEON_RAW_JSON_BACKEND_PRIVATE_KEY_JWT_PAYLOAD",
            ),
            (
                RawJsonSurface::JwtBearerAssertionPayload,
                "AEGAEON_RAW_JSON_BACKEND_JWT_BEARER_ASSERTION_PAYLOAD",
            ),
            (
                RawJsonSurface::OidcIdTokenPayload,
                "AEGAEON_RAW_JSON_BACKEND_OIDC_ID_TOKEN_PAYLOAD",
            ),
            (
                RawJsonSurface::JwtAccessTokenHeader,
                "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_HEADER",
            ),
            (
                RawJsonSurface::JwtAccessTokenPayload,
                "AEGAEON_RAW_JSON_BACKEND_JWT_ACCESS_TOKEN_PAYLOAD",
            ),
            (
                RawJsonSurface::FederationEntityStatement,
                "AEGAEON_RAW_JSON_BACKEND_FEDERATION_ENTITY_STATEMENT",
            ),
            (
                RawJsonSurface::FederationTrustMark,
                "AEGAEON_RAW_JSON_BACKEND_FEDERATION_TRUST_MARK",
            ),
        ];

        for (surface, expected) in cases {
            assert_eq!(raw_json_backend_env_var_for_surface(surface), expected);
        }
        assert_eq!(raw_json_backend_env_var(), "AEGAEON_RAW_JSON_BACKEND");
    }

    #[test]
    fn every_current_surface_has_expected_name() {
        let cases = [
            (RawJsonSurface::GenericObject, "generic-object"),
            (RawJsonSurface::JoseHeader, "jose-header"),
            (RawJsonSurface::RequestObject, "request-object"),
            (RawJsonSurface::ClientRegistration, "client-registration"),
            (RawJsonSurface::SoftwareStatement, "software-statement"),
            (
                RawJsonSurface::PrivateKeyJwtPayload,
                "private-key-jwt-payload",
            ),
            (
                RawJsonSurface::JwtBearerAssertionPayload,
                "jwt-bearer-assertion-payload",
            ),
            (RawJsonSurface::OidcIdTokenPayload, "oidc-id-token-payload"),
            (
                RawJsonSurface::JwtAccessTokenHeader,
                "jwt-access-token-header",
            ),
            (
                RawJsonSurface::JwtAccessTokenPayload,
                "jwt-access-token-payload",
            ),
            (
                RawJsonSurface::FederationEntityStatement,
                "federation-entity-statement",
            ),
            (RawJsonSurface::FederationTrustMark, "federation-trust-mark"),
        ];

        for (surface, expected) in cases {
            assert_eq!(surface.as_str(), expected);
        }
        assert_eq!(RawJsonBackend::SerdeCompat.as_str(), "serde-compat");
        assert_eq!(
            RawJsonBackend::VerifiedStructuralV1.as_str(),
            "verified-structural-v1"
        );
        assert!(RawJsonBackend::VerifiedStructuralV1.is_verified());
        assert_eq!(
            RawJsonClaimBoundary::TopLevelObjectMembers.as_str(),
            "top-level-object-members"
        );
        assert_eq!(RawJsonClaimBoundary::RawBytes.as_str(), "raw-bytes");
    }

    #[test]
    fn all_current_surfaces_have_unique_names_and_backend_env_vars() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        let mut seen_names = HashSet::new();
        let mut seen_env_vars = HashSet::new();

        for surface in ALL_RAW_JSON_SURFACES {
            assert!(seen_names.insert(surface.as_str()));
            assert!(seen_env_vars.insert(raw_json_backend_env_var_for_surface(surface)));
        }
    }

    #[test]
    fn backend_policy_source_prefers_surface_then_global_then_default() -> TestResult {
        let default_policy =
            backend_policy_for_surface_from_values(RawJsonSurface::JoseHeader, None, None)?;
        assert_eq!(default_policy.source, RawJsonBackendPolicySource::Default);

        let global_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JoseHeader,
            None,
            Some("serde-compat"),
        )?;
        assert_eq!(
            global_policy.source,
            RawJsonBackendPolicySource::GlobalOverride
        );

        let surface_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JoseHeader,
            Some("serde_compat"),
            Some("future"),
        )?;
        assert_eq!(
            surface_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );
        assert_eq!(surface_policy.backend, RawJsonBackend::SerdeCompat);
        Ok(())
    }

    #[test]
    fn backend_policy_error_display_names_surface_and_source() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        let err = RawJsonBackendPolicyError {
            surface: RawJsonSurface::JoseHeader,
            source_var: raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader),
            requested: "future".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "unsupported raw JSON backend `future` for surface `jose-header` via AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER"
        );
    }

    #[test]
    fn raw_json_object_error_display_variants_are_stable() {
        let _guard = RAW_JSON_TEST_ENV_GUARD.lock().expect("raw json env guard");
        assert_eq!(
            RawJsonObjectError::DuplicateKey.to_string(),
            "duplicate key"
        );
        assert_eq!(
            RawJsonObjectError::InvalidBackendPolicy(RawJsonBackendPolicyError {
                surface: RawJsonSurface::RequestObject,
                source_var: raw_json_backend_env_var_for_surface(RawJsonSurface::RequestObject),
                requested: "future".to_string(),
            })
            .to_string(),
            "invalid backend policy: unsupported raw JSON backend `future` for surface `request-object` via AEGAEON_RAW_JSON_BACKEND_REQUEST_OBJECT"
        );
    }

    #[test]
    fn backend_policy_rejects_unknown_surface_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let err = backend_policy_for_surface_from_values(
            RawJsonSurface::JoseHeader,
            Some("future"),
            None,
        )
        .err()
        .ok_or_else(|| IoError::other("error must be present"))?;
        assert_eq!(err.surface, RawJsonSurface::JoseHeader);
        assert_eq!(
            err.source_var,
            raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader)
        );
        assert_eq!(err.requested, "future".to_string());
        Ok(())
    }

    #[test]
    fn backend_policy_rejects_unknown_global_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let err = backend_policy_for_surface_from_values(
            RawJsonSurface::GenericObject,
            None,
            Some("future"),
        )
        .err()
        .ok_or_else(|| IoError::other("error must be present"))?;
        assert_eq!(err.surface, RawJsonSurface::GenericObject);
        assert_eq!(err.source_var, raw_json_backend_env_var());
        assert_eq!(err.requested, "future".to_string());
        Ok(())
    }

    #[test]
    fn backend_policy_accepts_structural_backend_for_promoted_surfaces() -> TestResult {
        let policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JoseHeader,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(policy.source, RawJsonBackendPolicySource::SurfaceOverride);

        let request_object_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::RequestObject,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(request_object_policy.surface, RawJsonSurface::RequestObject);
        assert_eq!(
            request_object_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            request_object_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let client_registration_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::ClientRegistration,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            client_registration_policy.surface,
            RawJsonSurface::ClientRegistration
        );
        assert_eq!(
            client_registration_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            client_registration_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let software_statement_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::SoftwareStatement,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            software_statement_policy.surface,
            RawJsonSurface::SoftwareStatement
        );
        assert_eq!(
            software_statement_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            software_statement_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let private_key_jwt_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::PrivateKeyJwtPayload,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            private_key_jwt_policy.surface,
            RawJsonSurface::PrivateKeyJwtPayload
        );
        assert_eq!(
            private_key_jwt_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            private_key_jwt_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let jwt_bearer_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JwtBearerAssertionPayload,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            jwt_bearer_policy.surface,
            RawJsonSurface::JwtBearerAssertionPayload
        );
        assert_eq!(
            jwt_bearer_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            jwt_bearer_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let oidc_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::OidcIdTokenPayload,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(oidc_policy.surface, RawJsonSurface::OidcIdTokenPayload);
        assert_eq!(oidc_policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(
            oidc_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let jwt_access_token_header_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JwtAccessTokenHeader,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            jwt_access_token_header_policy.surface,
            RawJsonSurface::JwtAccessTokenHeader
        );
        assert_eq!(
            jwt_access_token_header_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            jwt_access_token_header_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let jwt_access_token_payload_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::JwtAccessTokenPayload,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            jwt_access_token_payload_policy.surface,
            RawJsonSurface::JwtAccessTokenPayload
        );
        assert_eq!(
            jwt_access_token_payload_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            jwt_access_token_payload_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let federation_entity_statement_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::FederationEntityStatement,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            federation_entity_statement_policy.surface,
            RawJsonSurface::FederationEntityStatement
        );
        assert_eq!(
            federation_entity_statement_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            federation_entity_statement_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );

        let federation_trust_mark_policy = backend_policy_for_surface_from_values(
            RawJsonSurface::FederationTrustMark,
            Some("verified-structural-v1"),
            None,
        )?;
        assert_eq!(
            federation_trust_mark_policy.surface,
            RawJsonSurface::FederationTrustMark
        );
        assert_eq!(
            federation_trust_mark_policy.backend,
            RawJsonBackend::VerifiedStructuralV1
        );
        assert_eq!(
            federation_trust_mark_policy.source,
            RawJsonBackendPolicySource::SurfaceOverride
        );
        Ok(())
    }

    #[test]
    fn backend_policy_rejects_structural_backend_for_generic_object() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let err = backend_policy_for_surface_from_values(
            RawJsonSurface::GenericObject,
            Some("verified-structural-v1"),
            None,
        )
        .err()
        .ok_or_else(|| IoError::other("unsupported structural backend must fail closed"))?;
        assert_eq!(err.surface, RawJsonSurface::GenericObject);
        assert_eq!(
            err.source_var,
            raw_json_backend_env_var_for_surface(RawJsonSurface::GenericObject)
        );
        assert_eq!(err.requested, "verified-structural-v1".to_string());
        Ok(())
    }

    #[test]
    fn surface_specific_backend_selection_exists_only_for_promoted_surfaces() {
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::JoseHeader,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::RequestObject,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::ClientRegistration,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::SoftwareStatement,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::PrivateKeyJwtPayload,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::JwtBearerAssertionPayload,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::OidcIdTokenPayload,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::JwtAccessTokenHeader,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::JwtAccessTokenPayload,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::FederationEntityStatement,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());
        assert!(surface_specific_backend_selection_for_surface(
            RawJsonSurface::FederationTrustMark,
            RawJsonBackend::VerifiedStructuralV1
        )
        .is_some());

        for surface in ALL_RAW_JSON_SURFACES {
            if surface.uses_verified_structural_v1() {
                continue;
            }

            assert!(surface_specific_backend_selection_for_surface(
                surface,
                RawJsonBackend::VerifiedStructuralV1
            )
            .is_none());
        }
    }

    #[test]
    fn direct_structural_backend_parse_accepts_supported_jose_header_subset() -> TestResult {
        let Some(report) =
            structural_report_when_available(parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::JoseHeader,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{"alg":"HS256"}"#,
            ))?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].key, "alg");
        assert_eq!(
            members[0].value,
            serde_json::Value::String("HS256".to_string())
        );
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_stays_fail_closed_for_unsupported_jose_header_input(
    ) -> TestResult {
        let err = parse_json_object_members_with_backend_for_surface(
            RawJsonSurface::JoseHeader,
            RawJsonBackend::VerifiedStructuralV1,
            br#"{"alg":{"nested":true}}"#,
        )
        .err()
        .ok_or_else(|| IoError::other("unsupported structural input must fail closed"))?;

        match err {
            RawJsonObjectError::InvalidJson(inner) => {
                assert!(inner
                    .to_string()
                    .contains("raw JSON structural parser unavailable for this input or build"));
            }
            RawJsonObjectError::InvalidShape(inner) => {
                assert!(inner
                    .to_string()
                    .contains("JOSE header value for key `alg` must be string or null"));
            }
            other => panic!("unexpected error for unsupported structural input: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_accepts_request_object_surface() -> TestResult {
        let Some(report) =
            structural_report_when_available(parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::RequestObject,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{"iss":"issuer","max_age":3600,"authorization_details":[{"type":"payment"}]}"#,
            ))?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].key, "iss");
        assert_eq!(members[0].value, Value::String("issuer".to_string()));
        assert_eq!(members[1].key, "max_age");
        assert_eq!(
            members[1].value,
            Value::Number(serde_json::Number::from(3600))
        );
        assert_eq!(members[2].key, "authorization_details");
        assert_eq!(
            members[2].value[0]["type"],
            Value::String("payment".to_string())
        );
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_accepts_client_registration_surface() -> TestResult {
        let Some(report) =
            structural_report_when_available(parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::ClientRegistration,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{
                "redirect_uris":["https://example.com/callback"],
                "pkce_required":true,
                "jwks":{"keys":[{"kty":"RSA"}]}
            }"#,
            ))?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 3);
        assert_eq!(members[0].key, "redirect_uris");
        assert_eq!(
            members[0].value[0],
            Value::String("https://example.com/callback".to_string())
        );
        assert_eq!(members[1].key, "pkce_required");
        assert_eq!(members[1].value, Value::Bool(true));
        assert_eq!(members[2].key, "jwks");
        assert_eq!(
            members[2].value["keys"][0]["kty"],
            Value::String("RSA".to_string())
        );
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_accepts_software_statement_surface() -> TestResult {
        let Some(report) = structural_report_when_available(
            parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::SoftwareStatement,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{"iss":"https://issuer.example","sub":"ssa-client","exp":42,"redirect_uris":["https://client.example/callback"]}"#,
            ),
        )?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 4);
        assert_eq!(members[0].key, "iss");
        assert_eq!(
            members[0].value,
            Value::String("https://issuer.example".to_string())
        );
        assert_eq!(members[2].key, "exp");
        assert_eq!(
            members[2].value,
            Value::Number(serde_json::Number::from(42))
        );
        assert_eq!(members[3].key, "redirect_uris");
        assert_eq!(
            members[3].value[0],
            Value::String("https://client.example/callback".to_string())
        );
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_accepts_private_key_jwt_payload_surface() -> TestResult {
        let Some(report) = structural_report_when_available(
            parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::PrivateKeyJwtPayload,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{"iss":"client","sub":"client","aud":"https://issuer/token","exp":42,"jti":"jti-1"}"#,
            ),
        )?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 5);
        assert_eq!(members[0].key, "iss");
        assert_eq!(members[0].value, Value::String("client".to_string()));
        assert_eq!(members[3].key, "exp");
        assert_eq!(
            members[3].value,
            Value::Number(serde_json::Number::from(42))
        );
        Ok(())
    }

    #[test]
    fn direct_structural_backend_parse_accepts_jwt_bearer_assertion_payload_surface() -> TestResult
    {
        let Some(report) = structural_report_when_available(
            parse_json_object_members_with_backend_for_surface(
                RawJsonSurface::JwtBearerAssertionPayload,
                RawJsonBackend::VerifiedStructuralV1,
                br#"{"iss":"client","sub":"resource-owner","aud":"https://issuer/token","exp":42,"jti":"jti-1"}"#,
            ),
        )?
        else {
            return Ok(());
        };

        let members = report.value;
        assert_eq!(members.len(), 5);
        assert_eq!(members[0].key, "iss");
        assert_eq!(members[0].value, Value::String("client".to_string()));
        assert_eq!(members[1].key, "sub");
        assert_eq!(
            members[1].value,
            Value::String("resource-owner".to_string())
        );
        assert_eq!(members[3].key, "exp");
        assert_eq!(
            members[3].value,
            Value::Number(serde_json::Number::from(42))
        );
        Ok(())
    }

    #[test]
    fn backend_policy_reads_surface_override_from_environment() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let surface_key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let global_key = raw_json_backend_env_var();
        let previous_surface = std::env::var(surface_key).ok();
        let previous_global = std::env::var(global_key).ok();
        std::env::set_var(surface_key, "serde-compat");
        std::env::set_var(global_key, "future");

        let result = backend_policy_for_surface(RawJsonSurface::JoseHeader);

        if let Some(prev) = previous_surface {
            std::env::set_var(surface_key, prev);
        } else {
            std::env::remove_var(surface_key);
        }
        if let Some(prev) = previous_global {
            std::env::set_var(global_key, prev);
        } else {
            std::env::remove_var(global_key);
        }

        let policy = result?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(policy.source, RawJsonBackendPolicySource::SurfaceOverride);
        Ok(())
    }

    #[test]
    fn backend_policy_reads_structural_surface_override_from_environment() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let surface_key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let global_key = raw_json_backend_env_var();
        let previous_surface = std::env::var(surface_key).ok();
        let previous_global = std::env::var(global_key).ok();
        std::env::set_var(surface_key, "verified-structural-v1");
        std::env::remove_var(global_key);

        let result = backend_policy_for_surface(RawJsonSurface::JoseHeader);

        if let Some(prev) = previous_surface {
            std::env::set_var(surface_key, prev);
        } else {
            std::env::remove_var(surface_key);
        }
        if let Some(prev) = previous_global {
            std::env::set_var(global_key, prev);
        } else {
            std::env::remove_var(global_key);
        }

        let policy = result?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(policy.source, RawJsonBackendPolicySource::SurfaceOverride);
        Ok(())
    }

    #[test]
    fn backend_policy_reads_global_override_from_environment() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let surface_key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let global_key = raw_json_backend_env_var();
        let previous_surface = std::env::var(surface_key).ok();
        let previous_global = std::env::var(global_key).ok();
        std::env::remove_var(surface_key);
        std::env::set_var(global_key, "serde-compat");

        let result = backend_policy_for_surface(RawJsonSurface::JoseHeader);

        if let Some(prev) = previous_surface {
            std::env::set_var(surface_key, prev);
        } else {
            std::env::remove_var(surface_key);
        }
        if let Some(prev) = previous_global {
            std::env::set_var(global_key, prev);
        } else {
            std::env::remove_var(global_key);
        }

        let policy = result?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::SerdeCompat);
        assert_eq!(policy.source, RawJsonBackendPolicySource::GlobalOverride);
        Ok(())
    }

    #[test]
    fn backend_policy_reads_structural_global_override_for_jose_header() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let surface_key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let global_key = raw_json_backend_env_var();
        let previous_surface = std::env::var(surface_key).ok();
        let previous_global = std::env::var(global_key).ok();
        std::env::remove_var(surface_key);
        std::env::set_var(global_key, "verified-structural-v1");

        let result = backend_policy_for_surface(RawJsonSurface::JoseHeader);

        if let Some(prev) = previous_surface {
            std::env::set_var(surface_key, prev);
        } else {
            std::env::remove_var(surface_key);
        }
        if let Some(prev) = previous_global {
            std::env::set_var(global_key, prev);
        } else {
            std::env::remove_var(global_key);
        }

        let policy = result?;
        assert_eq!(policy.surface, RawJsonSurface::JoseHeader);
        assert_eq!(policy.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(policy.source, RawJsonBackendPolicySource::GlobalOverride);
        Ok(())
    }

    #[test]
    fn backend_policy_surface_override_fails_closed_before_global_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let surface_key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let global_key = raw_json_backend_env_var();
        let previous_surface = std::env::var(surface_key).ok();
        let previous_global = std::env::var(global_key).ok();
        std::env::set_var(surface_key, "future");
        std::env::set_var(global_key, "serde-compat");

        let result = backend_policy_for_surface(RawJsonSurface::JoseHeader);

        if let Some(prev) = previous_surface {
            std::env::set_var(surface_key, prev);
        } else {
            std::env::remove_var(surface_key);
        }
        if let Some(prev) = previous_global {
            std::env::set_var(global_key, prev);
        } else {
            std::env::remove_var(global_key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("surface override must fail closed"))?;
        assert_eq!(err.surface, RawJsonSurface::JoseHeader);
        assert_eq!(err.source_var, surface_key);
        assert_eq!(err.requested, "future".to_string());
        Ok(())
    }

    #[test]
    fn surface_parse_report_rejects_unknown_surface_backend_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "future");

        let result = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::JoseHeader,
            br#"{"alg":"HS256","typ":"JWT"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown surface override must fail closed"))?;
        assert!(matches!(
            err,
            RawJsonObjectError::InvalidBackendPolicy(ref policy_err)
                if policy_err.surface == RawJsonSurface::JoseHeader
                    && policy_err.source_var == key
                    && policy_err.requested == "future"
        ));
        Ok(())
    }

    #[test]
    fn structural_backend_override_selects_jose_header_report() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var_for_surface(RawJsonSurface::JoseHeader);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "verified-structural-v1");

        let result = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::JoseHeader,
            br#"{"alg":"HS256","typ":"JWT"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let Some(report) = structural_report_when_available(result)? else {
            return Ok(());
        };
        assert_eq!(report.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(report.surface, RawJsonSurface::JoseHeader);
        assert_eq!(report.value.len(), 2);
        assert_eq!(report.value[0].key, "alg");
        assert_eq!(report.value[1].key, "typ");
        Ok(())
    }

    #[test]
    fn surface_deserialize_report_rejects_unknown_surface_backend_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var_for_surface(RawJsonSurface::RequestObject);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "future");

        let result = deserialize_json_object_without_duplicate_keys_with_report_for_surface::<Claims>(
            RawJsonSurface::RequestObject,
            br#"{"iss":"issuer","sub":"subject"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown surface override must fail closed"))?;
        assert!(matches!(
            err,
            RawJsonObjectError::InvalidBackendPolicy(ref policy_err)
                if policy_err.surface == RawJsonSurface::RequestObject
                    && policy_err.source_var == key
                    && policy_err.requested == "future"
        ));
        Ok(())
    }

    #[test]
    fn structural_backend_override_selects_request_object_surface() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var_for_surface(RawJsonSurface::RequestObject);
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "verified-structural-v1");

        let result = deserialize_json_object_without_duplicate_keys_with_report_for_surface::<Claims>(
            RawJsonSurface::RequestObject,
            br#"{"iss":"issuer","sub":"subject"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let Some(report) = structural_report_when_available(result)? else {
            return Ok(());
        };
        assert_eq!(report.backend, RawJsonBackend::VerifiedStructuralV1);
        assert_eq!(report.surface, RawJsonSurface::RequestObject);
        assert_eq!(report.value.iss, "issuer");
        assert_eq!(report.value.sub, "subject");
        Ok(())
    }

    #[test]
    fn generic_parse_report_rejects_unknown_global_backend_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var();
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "future");

        let result = parse_json_object_members_with_report_for_surface(
            RawJsonSurface::GenericObject,
            br#"{"alg":"HS256","typ":"JWT"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown backend override must fail closed"))?;
        assert!(matches!(
            err,
            RawJsonObjectError::InvalidBackendPolicy(ref policy_err)
                if policy_err.surface == RawJsonSurface::GenericObject
                    && policy_err.source_var == raw_json_backend_env_var()
                    && policy_err.requested == "future"
        ));
        Ok(())
    }

    #[test]
    fn generic_deserialize_report_rejects_unknown_global_backend_override() -> TestResult {
        let _guard = RAW_JSON_TEST_ENV_GUARD
            .lock()
            .map_err(|_| IoError::other("raw json env guard"))?;
        let key = raw_json_backend_env_var();
        let previous = std::env::var(key).ok();
        std::env::set_var(key, "future");

        let result = deserialize_compat_json_object_without_duplicate_keys_with_report_for_surface::<
            Claims,
        >(
            RawJsonSurface::GenericObject,
            br#"{"iss":"issuer","sub":"subject"}"#,
        );

        if let Some(prev) = previous {
            std::env::set_var(key, prev);
        } else {
            std::env::remove_var(key);
        }

        let err = result
            .err()
            .ok_or_else(|| IoError::other("unknown backend override must fail closed"))?;
        assert!(matches!(
            err,
            RawJsonObjectError::InvalidBackendPolicy(ref policy_err)
                if policy_err.surface == RawJsonSurface::GenericObject
                    && policy_err.source_var == raw_json_backend_env_var()
                    && policy_err.requested == "future"
        ));
        Ok(())
    }
}
