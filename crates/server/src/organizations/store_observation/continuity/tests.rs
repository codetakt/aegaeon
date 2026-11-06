use super::*;

#[test]
fn continuity_seals_require_canonical_scoped_non_nil_values() {
    let deployment = Uuid::new_v4();
    let seal = Uuid::new_v4();
    assert_eq!(parse(None, deployment).unwrap(), None);
    assert_eq!(
        parse(Some(format!("{deployment}:{seal}")), deployment).unwrap(),
        Some(seal)
    );
    for value in [
        format!("{}:{seal}", Uuid::new_v4()),
        format!("{deployment}:{}", Uuid::nil()),
        format!("{deployment}:{}", seal.simple()),
        format!("{deployment}:{seal}:extra"),
        "invalid".into(),
    ] {
        assert!(parse(Some(value), deployment).is_err());
    }
    assert!(request(Uuid::nil(), None).is_err());
    assert!(request(deployment, Some((None, Uuid::nil()))).is_err());
    assert!(request(deployment, Some((Some(Uuid::nil()), seal))).is_err());
    assert!(request(deployment, Some((Some(seal), seal))).is_err());
    assert!(request(deployment, Some((None, seal))).is_ok());
}
