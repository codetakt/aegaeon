use super::*;
use serde_json::json;

fn input(origin: &str, path: &std::path::Path) -> Input {
    serde_json::from_value(json!({"origin":origin,"root_cert":path})).unwrap()
}

#[test]
fn organization_delivery_trust_requires_bounded_unique_canonical_dns_origins() {
    let path = std::path::Path::new("/private/trust.pem");
    assert!(Trust::validate(&[]).is_ok());
    assert!(Trust::validate(&[input("https://delivery.example.test", path)]).is_ok());
    for origin in [
        "http://delivery.example.test",
        "https://delivery.example.test/",
        "https://Delivery.example.test",
        "https://delivery.example.test:443",
        "https://delivery.example.test:444",
        "https://delivery.example.test./",
        "https://user@delivery.example.test",
        "https://delivery.example.test?query",
        "https://delivery.example.test#fragment",
        "https://127.0.0.1",
        "https://[::1]",
        "https://localhost",
        "https://delivery.example.test/path",
    ] {
        assert!(Trust::validate(&[input(origin, path)]).is_err(), "{origin}");
    }
    let repeated = || input("https://delivery.example.test", path);
    assert!(Trust::validate(&[repeated(), repeated()]).is_err());
    assert!(Trust::validate(
        &(0..9)
            .map(|i| input(&format!("https://d{i}.example.test"), path))
            .collect::<Vec<_>>()
    )
    .is_err());
    assert!(Trust::validate(&[input(
        "https://delivery.example.test",
        std::path::Path::new("relative.pem")
    )])
    .is_err());
    assert!(serde_json::from_value::<Input>(
        json!({"origin":"https://delivery.example.test","root_cert":path,"insecure":true})
    )
    .is_err());
}

#[test]
fn organization_delivery_trust_freezes_validated_bundle_and_refuses_missing_invalid_or_fifo() {
    let directory =
        std::env::temp_dir().join(format!("aegaeon-delivery-trust-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("ca.pem");
    let inputs = [input("https://delivery.example.test", &path)];
    assert!(Trust::load(&inputs).is_err());
    let ca = rcgen::generate_simple_self_signed(vec!["fixture.example.test".into()]).unwrap();
    let pem = ca.serialize_pem().unwrap();
    std::fs::write(&path, format!("{pem}{pem}")).unwrap();
    let trust = Trust::load(&inputs).unwrap();
    assert_eq!(trust.0["https://delivery.example.test"].len(), 2);
    for bytes in [
        vec![],
        b"invalid".to_vec(),
        b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n".to_vec(),
        ca.serialize_private_key_pem().into_bytes(),
        vec![b' '; 65_537],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(Trust::load(&inputs).is_err());
        assert_eq!(trust.0["https://delivery.example.test"].len(), 2);
    }
    std::fs::remove_file(&path).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(Trust::load(&inputs).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(directory).unwrap();
}
