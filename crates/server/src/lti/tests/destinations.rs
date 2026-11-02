use super::{configuration, validate_configuration};

#[test]
fn registration_rejects_issuer_relative_https_destinations() {
    for uri in [
        "https:tool.example/launch",
        "https:/tool.example/launch",
        "HTTPS:tool.example/launch",
        "HTTPS:/tool.example/launch",
    ] {
        let mut login = configuration();
        login.initiate_login_uri = uri.into();
        assert!(validate_configuration(&login).is_err(), "login: {uri}");

        let mut redirect = configuration();
        redirect.redirect_uris = [uri.into()].into();
        assert!(
            validate_configuration(&redirect).is_err(),
            "redirect: {uri}"
        );

        let mut target = configuration();
        target.deployments[0].resource_links[0].target_link_uri = uri.into();
        assert!(validate_configuration(&target).is_err(), "target: {uri}");
    }
}

#[test]
fn registration_preserves_explicit_https_destinations() {
    for uri in [
        "https://tool.example:8443/launch?opaque=%2B",
        "HTTPS://tool.example:8443/launch?opaque=%2B",
    ] {
        let mut config = configuration();
        config.initiate_login_uri = uri.into();
        config.redirect_uris = [uri.into()].into();
        config.deployments[0].resource_links[0].target_link_uri = uri.into();
        assert!(validate_configuration(&config).is_ok(), "{uri}");
        assert_eq!(config.initiate_login_uri, uri);
        assert!(config.redirect_uris.contains(uri));
        assert_eq!(config.deployments[0].resource_links[0].target_link_uri, uri);
    }
}
