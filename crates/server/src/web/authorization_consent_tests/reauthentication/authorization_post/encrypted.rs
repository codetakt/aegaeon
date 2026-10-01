use super::*;
#[cfg(test)]
use aws_lc_rs::rsa::{OaepPublicEncryptingKey, PrivateDecryptingKey, OAEP_SHA1_MGF1SHA1};

pub(super) async fn install(state: &mut AppState) -> TestResult {
    let pem = pem::parse(include_bytes!(
        "../../../../../tests/fixtures/rsa2048-private.pk8.pem"
    ))?;
    let kid = "authorization-post-encryption";
    let key = crate::oidc::config::OidcRequestObjectEncryptionKey::from_rsa_pkcs8_der(
        kid.into(),
        pem.contents(),
    )?;
    // Same synthetic KEK as the isolated test-support runtime loader.
    let handle = crate::key_encryption::encrypt_key_handle(
        &URL_SAFE_NO_PAD.encode(pem.contents()),
        &[0x57; 32],
        crate::key_encryption::KeyHandleEncryptionContext::new(
            state.environment_id,
            "OIDC_REQUEST_OBJECT_DECRYPTION",
            "databaseEncrypted",
            "RSA-OAEP+A256GCM",
            kid,
        ),
    )?;
    sqlx::query("INSERT INTO aegaeon.runtime_keys(environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle) SELECT environment_id,id,'OIDC_REQUEST_OBJECT_DECRYPTION',$2,'RSA-OAEP+A256GCM','databaseEncrypted','ACTIVE',$3,$4 FROM aegaeon.configuration_versions WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(state.environment_id).bind(kid).bind(serde_json::to_value(key.public_jwk())?).bind(handle)
        .execute(&state.db_pool).await?;
    reload_authorization_runtime(state).await
}

pub(super) async fn request_uri(state: &AppState, sid: &str, mode: &str) -> TestResult<String> {
    let signed = request_objects::signed_request(state, mode)?;
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(signed.split('.').nth(1).ok_or("claims")?)?,
    )?;
    claims["response_mode"] = serde_json::json!("form_post");
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("oauth-authz-req+jwt".into());
    let signed = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../../../tests/fixtures/rsa2048-private.pk8.pem"
        ))?,
    )?;
    let private = PrivateDecryptingKey::from_pkcs8(
        state
            .oidc
            .config
            .as_ref()
            .and_then(|c| c.request_object_encryption_key.as_ref())
            .ok_or("encryption key")?
            .pkcs8_der(),
    )
    .map_err(|_| "RSA key")?;
    let public = OaepPublicEncryptingKey::new(private.public_key()).map_err(|_| "OAEP key")?;
    let mut cek = [0_u8; 32];
    let mut nonce = [0_u8; 12];
    aegaeon_crypto::rand::fill_random(&mut cek)?;
    aegaeon_crypto::rand::fill_random(&mut nonce)?;
    let protected = URL_SAFE_NO_PAD.encode(br#"{"alg":"RSA-OAEP","enc":"A256GCM","cty":"JWT"}"#);
    let mut encrypted = vec![0; public.ciphertext_size()];
    let encrypted = public
        .encrypt(&OAEP_SHA1_MGF1SHA1, &cek, &mut encrypted, None)
        .map_err(|_| "OAEP encryption")?;
    let ciphertext = aegaeon_crypto::jwe::encrypt_a256gcm(
        &cek,
        &nonce,
        signed.as_bytes(),
        protected.as_bytes(),
    )?;
    let (ciphertext, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let jwe = format!(
        "{protected}.{}.{}.{}.{}",
        URL_SAFE_NO_PAD.encode(encrypted),
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(ciphertext),
        URL_SAFE_NO_PAD.encode(tag)
    );
    request_objects::authorization_uri(state, sid, &jwe, mode).await
}
