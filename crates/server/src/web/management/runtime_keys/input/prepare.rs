use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use uuid::Uuid;

use crate::key_encryption::KeyHandleEncryptionContext;
use crate::management::types::CreateRuntimeKeyRequest;

use super::super::super::encrypt_key_handle_required;
use super::super::super::key_stores::normalize_key_store_audit_note;
use super::material::{parse_runtime_key_pkcs8_der, runtime_key_public_jwk};
use super::types::RuntimeKeyCreateInput;
use super::validation::{
    normalize_aws_kms_provider_configuration, normalize_runtime_key_algorithm,
    normalize_runtime_key_kid, normalize_runtime_key_provider,
    normalize_runtime_key_provider_configuration, parse_runtime_key_usage, runtime_key_bad_request,
};

#[cfg(test)]
pub(in crate::web::management) fn prepare_runtime_key_create_input(
    req: &CreateRuntimeKeyRequest,
    environment_id: Uuid,
    request_id: &str,
) -> Result<RuntimeKeyCreateInput, Response> {
    let usage = parse_runtime_key_usage(&req.usage, request_id)?;
    let algorithm = normalize_runtime_key_algorithm(usage, req.algorithm.as_deref(), request_id)?;
    let provider = normalize_runtime_key_provider(&req.provider, request_id)?;
    let kid = normalize_runtime_key_kid(req.kid.as_deref(), request_id)?;
    if provider != "databaseEncrypted" {
        return Err(runtime_key_bad_request(
            request_id,
            "awsKms runtime keys require asynchronous KMS public key derivation",
            None,
        ));
    }

    prepare_database_encrypted_runtime_key_create_input(
        req,
        environment_id,
        usage,
        algorithm,
        provider,
        kid,
        request_id,
    )
}

pub(in crate::web::management) async fn prepare_runtime_key_create_input_async(
    req: &CreateRuntimeKeyRequest,
    environment_id: Uuid,
    request_id: &str,
) -> Result<RuntimeKeyCreateInput, Response> {
    let usage = parse_runtime_key_usage(&req.usage, request_id)?;
    let algorithm = normalize_runtime_key_algorithm(usage, req.algorithm.as_deref(), request_id)?;
    let provider = normalize_runtime_key_provider(&req.provider, request_id)?;
    let kid = normalize_runtime_key_kid(req.kid.as_deref(), request_id)?;

    match provider.as_str() {
        "databaseEncrypted" => prepare_database_encrypted_runtime_key_create_input(
            req,
            environment_id,
            usage,
            algorithm,
            provider,
            kid,
            request_id,
        ),
        "awsKms" => {
            prepare_aws_kms_runtime_key_create_input(
                req,
                environment_id,
                usage,
                algorithm,
                provider,
                kid,
                request_id,
            )
            .await
        }
        _ => Err(runtime_key_bad_request(
            request_id,
            "Unsupported runtime key provider",
            None,
        )),
    }
}

fn prepare_database_encrypted_runtime_key_create_input(
    req: &CreateRuntimeKeyRequest,
    environment_id: Uuid,
    usage: super::types::RuntimeKeyUsageInput,
    algorithm: String,
    provider: String,
    kid: String,
    request_id: &str,
) -> Result<RuntimeKeyCreateInput, Response> {
    let provider_configuration = normalize_runtime_key_provider_configuration(
        &provider,
        req.provider_configuration.as_ref(),
        request_id,
    )?;
    let pkcs8_der = parse_runtime_key_pkcs8_der(req.private_key_pem.as_deref(), request_id)?;
    let public_jwk = runtime_key_public_jwk(usage, &algorithm, &kid, &pkcs8_der, request_id)?;
    let plaintext_key_handle = URL_SAFE_NO_PAD.encode(pkcs8_der);
    let context = runtime_key_handle_context(environment_id, usage, &provider, &algorithm, &kid);
    let encrypted_key_handle =
        encrypt_key_handle_required(&plaintext_key_handle, context, request_id)?;

    Ok(RuntimeKeyCreateInput {
        usage,
        kid,
        algorithm,
        provider,
        initial_status: if req.activate { "ACTIVE" } else { "NEXT" },
        public_jwk,
        encrypted_key_handle,
        provider_configuration,
        comment: normalize_key_store_audit_note(req.comment.as_deref(), "comment", request_id)?,
    })
}

async fn prepare_aws_kms_runtime_key_create_input(
    req: &CreateRuntimeKeyRequest,
    environment_id: Uuid,
    usage: super::types::RuntimeKeyUsageInput,
    algorithm: String,
    provider: String,
    kid: String,
    request_id: &str,
) -> Result<RuntimeKeyCreateInput, Response> {
    if usage != super::types::RuntimeKeyUsageInput::OidcIdTokenSigning {
        return Err(runtime_key_bad_request(
            request_id,
            "awsKms runtime keys are supported only for OIDC ID Token signing",
            Some(serde_json::json!({
                "supportedUsage": "OIDC_ID_TOKEN_SIGNING",
            })),
        ));
    }
    if algorithm != "RS256" {
        return Err(runtime_key_bad_request(
            request_id,
            "awsKms OIDC runtime keys support RS256 only",
            Some(serde_json::json!({
                "supportedAlgorithms": ["RS256"],
            })),
        ));
    }
    if req
        .private_key_pem
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return Err(runtime_key_bad_request(
            request_id,
            "privateKeyPem must be omitted for awsKms runtime keys",
            None,
        ));
    }

    let kms =
        normalize_aws_kms_provider_configuration(req.provider_configuration.as_ref(), request_id)?;
    let public_jwk = aws_kms_oidc_public_jwk(&kms.region, &kms.key_id, &kid, request_id).await?;
    let context = runtime_key_handle_context(environment_id, usage, &provider, &algorithm, &kid);
    let encrypted_key_handle = encrypt_key_handle_required(&kms.key_id, context, request_id)?;

    Ok(RuntimeKeyCreateInput {
        usage,
        kid,
        algorithm,
        provider,
        initial_status: if req.activate { "ACTIVE" } else { "NEXT" },
        public_jwk,
        encrypted_key_handle,
        provider_configuration: serde_json::json!({ "region": kms.region }),
        comment: normalize_key_store_audit_note(req.comment.as_deref(), "comment", request_id)?,
    })
}

fn runtime_key_handle_context<'a>(
    environment_id: Uuid,
    usage: super::types::RuntimeKeyUsageInput,
    provider: &'a str,
    algorithm: &'a str,
    kid: &'a str,
) -> KeyHandleEncryptionContext<'a> {
    KeyHandleEncryptionContext::new(environment_id, usage.as_db_str(), provider, algorithm, kid)
}

#[cfg(feature = "kms-aws")]
async fn aws_kms_oidc_public_jwk(
    region: &str,
    key_id: &str,
    kid: &str,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let signing_key = crate::oidc::OidcSigningKey::from_aws_kms_async(
        region.to_string(),
        key_id.to_string(),
        kid.to_string(),
    )
    .await
    .map_err(|_| {
        runtime_key_bad_request(
            request_id,
            "providerConfiguration does not reference a usable AWS KMS RS256 signing key",
            None,
        )
    })?;
    let public_jwk = signing_key.jwks().keys.into_iter().next().ok_or_else(|| {
        super::super::super::management_internal_error(
            request_id,
            "Failed to derive AWS KMS public JWK",
        )
    })?;
    serde_json::to_value(public_jwk).map_err(|_| {
        super::super::super::management_internal_error(
            request_id,
            "Failed to serialize AWS KMS public JWK",
        )
    })
}

#[cfg(not(feature = "kms-aws"))]
async fn aws_kms_oidc_public_jwk(
    _region: &str,
    _key_id: &str,
    _kid: &str,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    Err(runtime_key_bad_request(
        request_id,
        "awsKms runtime keys require the kms-aws feature",
        None,
    ))
}
