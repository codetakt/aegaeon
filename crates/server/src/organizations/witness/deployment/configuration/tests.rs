use super::*;
use serde_json::{json, Value};

fn document() -> Value {
    let selection = json!({"epoch":Uuid::new_v4(), "primary":Uuid::new_v4(),
        "token_store":Uuid::new_v4(), "source_sha256":"a".repeat(64),
        "history_sha256":"b".repeat(64), "acceptance_sha256":"c".repeat(64)});
    json!({"version":1,"deployment_id":Uuid::new_v4(),"selection":selection,
        "control":{"url":"postgresql://runtime:secret@control.example/control?sslmode=verify-full","root_cert":"/certs/control.pem"},
        "primary":{"url":"postgresql://runtime:secret@primary.example/primary?sslmode=verify-full","root_cert":"/certs/primary.pem"},
        "token":{"url":"rediss://runtime:secret@token.example/0","root_cert":"/certs/token.pem"},
        "environments":[{"id":Uuid::new_v4(),"issuer":"https://issuer.example","selection":selection}]})
}
fn parse(value: &Value) -> Result<Configuration> {
    Configuration::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn organization_deployment_configuration_binds_independent_runtime_inputs() {
    let value = document();
    let config = parse(&value).unwrap();
    let environment = serde_json::from_value(value["environments"][0]["id"].clone()).unwrap();
    let primary = value["primary"]["url"].as_str().unwrap();
    let token = value["token"]["url"].as_str().unwrap();
    assert!(config
        .check_runtime(environment, "https://issuer.example", primary, token)
        .is_ok());
    assert!(config
        .check_runtime(Uuid::new_v4(), "https://issuer.example", primary, token)
        .is_err());
    assert!(config
        .check_runtime(environment, "https://other.example", primary, token)
        .is_err());
    assert!(config
        .check_runtime(environment, "https://issuer.example", token, primary)
        .is_err());
}

#[test]
fn organization_deployment_configuration_refuses_ambiguous_or_unbounded_registry() {
    let original = document();
    for field in ["epoch", "primary", "token_store"] {
        let mut v = original.clone();
        v["selection"][field] = json!(Uuid::nil());
        assert!(parse(&v).is_err());
    }
    for issuer in [
        "http://issuer.example",
        "https://u:p@issuer.example",
        "https://issuer.example/?query",
        "https://issuer.example/#fragment",
    ] {
        let mut v = original.clone();
        v["environments"][0]["issuer"] = json!(issuer);
        assert!(parse(&v).is_err());
    }
    let mut v = original.clone();
    v["environments"][0]["selection"]["primary"] = json!(Uuid::new_v4());
    assert!(parse(&v).is_err());
    let mut v = original.clone();
    v["environments"]
        .as_array_mut()
        .unwrap()
        .push(original["environments"][0].clone());
    assert!(parse(&v).is_err());
    v["environments"][1]["id"] = json!(Uuid::new_v4());
    v["environments"][1]["issuer"] = json!("https://ISSUER.example/");
    assert!(parse(&v).is_err());
    v["environments"] = json!(vec![original["environments"][0].clone(); 1025]);
    assert!(parse(&v).is_err());
}

#[test]
fn organization_deployment_configuration_has_no_unknown_field_or_error_fallback() {
    for (key, value) in [
        ("version", json!(2)),
        ("enabled", json!(false)),
        ("deployment_id", json!(Uuid::nil())),
    ] {
        let mut v = document();
        v[key] = value;
        assert!(parse(&v).is_err());
    }
    let mut v = document();
    v["primary"]["root_cert"] = json!("relative.pem");
    assert!(parse(&v).is_err());
    assert!(Configuration::parse(&vec![b' '; MAX_CONFIGURATION_BYTES + 1]).is_err());
    assert!(Configuration::parse(b"{}").is_err());
    assert!(Configuration::parse(b"{invalid: secret}").is_err());
    let mut v = document();
    v["selection"]["source_sha256"] = json!("A".repeat(64));
    assert!(parse(&v).is_err());
}

#[test]
fn organization_startup_selection_refuses_missing_and_ambiguous_issuer_host() {
    let mut value = document();
    let config = parse(&value).unwrap();
    let (id, issuer) = config.startup_environment("issuer.example").unwrap();
    assert_eq!(
        serde_json::to_value(id).unwrap(),
        value["environments"][0]["id"]
    );
    assert_eq!(issuer, "https://issuer.example");
    assert!(config.startup_environment("other.example").is_err());
    let mut other = value["environments"][0].clone();
    other["id"] = json!(Uuid::new_v4());
    other["issuer"] = json!("https://issuer.example/other");
    value["environments"].as_array_mut().unwrap().push(other);
    assert!(parse(&value)
        .unwrap()
        .startup_environment("issuer.example")
        .is_err());
}

#[test]
fn organization_configuration_file_reads_once_and_refuses_nonregular_or_oversized_input() {
    let directory = std::env::temp_dir().join(format!("aegaeon-configuration-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("runtime.json");
    let value = document();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let config = Configuration::load(&path).unwrap();
    std::fs::write(&path, b"invalid secret").unwrap();
    assert!(config.startup_environment("issuer.example").is_ok());
    assert!(Configuration::load(&path).is_err());
    std::fs::write(&path, vec![b' '; MAX_CONFIGURATION_BYTES + 1]).unwrap();
    assert!(Configuration::load(&path).is_err());
    assert!(Configuration::load(&directory).is_err());
    std::fs::remove_file(&path).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert!(Configuration::load(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(Configuration::load(&path).is_err());
    std::fs::remove_dir(directory).unwrap();
}
