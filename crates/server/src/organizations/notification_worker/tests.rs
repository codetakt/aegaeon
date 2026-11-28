use super::*;
// Provider access below creates test-only key material.
#[cfg(test)]
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeySize, PrivateDecryptingKey},
};
use std::io::Write;
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};

struct Files(std::path::PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("notification-keys-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn write(&self, bytes: &[u8]) -> std::path::PathBuf {
        let path = self.0.join("keys.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes).unwrap();
        path
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn document() -> serde_json::Value {
    let key = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let public = key.public_key().as_der().unwrap();
    serde_json::json!({
        "version":1,"credential":URL_SAFE_NO_PAD.encode([7u8;32]),
        "keys":[{"version":"delivery_1","deployment_id":Uuid::new_v4(),
            "scope":{"kind":"environment","environment_id":Uuid::new_v4()},
            "not_before":0,"seal_until":100,"open_until":200,
            "spki_sha256":URL_SAFE_NO_PAD.encode(aegaeon_crypto::hash::sha256_digest(public.as_ref())),
            "pkcs8":URL_SAFE_NO_PAD.encode(key.as_der().unwrap().as_ref())}]
    })
}

#[test]
fn notification_private_file_refuses_links_fifo_public_permissions_and_bounds() {
    let files = Files::new();
    let bytes = Zeroizing::new(serde_json::to_vec(&document()).unwrap());
    let path = files.write(&bytes);
    assert!(Configuration::load(&path).is_ok());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(Configuration::load(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = files.0.join("link");
    symlink(&path, &link).unwrap();
    assert!(Configuration::load(&link).is_err());
    let hard = files.0.join("hard");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(Configuration::load(&path).is_err());
    std::fs::remove_file(&hard).unwrap();
    let fifo = files.0.join("fifo");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(Configuration::load(&fifo).is_err());
    assert!(Configuration::load(&files.0).is_err());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_FILE as u64 + 1)
        .unwrap();
    assert!(Configuration::load(&path).is_err());
}

#[test]
fn notification_private_configuration_rejects_wrong_pin_duplicate_versions_and_unknown_fields() {
    let original = document();
    assert!(Configuration::parse(&serde_json::to_vec(&original).unwrap()).is_ok());
    let expected = [
        ConfigurationError::Fingerprint,
        ConfigurationError::Metadata,
        ConfigurationError::Document,
        ConfigurationError::Metadata,
        ConfigurationError::Document,
        ConfigurationError::Encoding,
        ConfigurationError::Credential,
        ConfigurationError::Scope,
    ];
    for (variant, reason) in expected.into_iter().enumerate() {
        let mut value = original.clone();
        match variant {
            0 => value["keys"][0]["spki_sha256"] = URL_SAFE_NO_PAD.encode([0; 32]).into(),
            1 => {
                let duplicate = value["keys"][0].clone();
                value["keys"].as_array_mut().unwrap().push(duplicate);
            }
            2 => value["keys"][0]["scope"]["kind"] = "installation".into(),
            3 => value["keys"][0]["open_until"] = 99.into(),
            4 => value["unexpected"] = true.into(),
            5 => value["keys"][0]["pkcs8"] = "padded==".into(),
            6 => value["credential"] = "invalid-private-input".into(),
            _ => value["keys"][0]["scope"]["environment_id"] = Uuid::nil().to_string().into(),
        }
        assert_eq!(
            Configuration::parse(&serde_json::to_vec(&value).unwrap()).err(),
            Some(reason),
            "{variant}"
        );
    }
}

#[test]
fn notification_private_configuration_requires_pkcs8_wrapper_for_rsa_key() {
    use simple_asn1::{from_der, ASN1Block};

    let mut value = document();
    let files = Files::new();
    let encoded = value["keys"][0]["pkcs8"].as_str().unwrap();
    let pkcs8 = URL_SAFE_NO_PAD.decode(encoded).unwrap();
    let parsed = from_der(&pkcs8).unwrap();
    let [ASN1Block::Sequence(_, fields)] = parsed.as_slice() else {
        panic!("expected PKCS#8 sequence");
    };
    let ASN1Block::OctetString(_, pkcs1) = &fields[2] else {
        panic!("expected PKCS#8 private key octets");
    };
    let path = files.write(&serde_json::to_vec(&value).unwrap());
    assert!(Configuration::load_classified(&path).is_ok());
    value["keys"][0]["pkcs8"] = URL_SAFE_NO_PAD.encode(pkcs1).into();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        Configuration::load_classified(&path).err(),
        Some(ConfigurationError::Pkcs8)
    );
}
