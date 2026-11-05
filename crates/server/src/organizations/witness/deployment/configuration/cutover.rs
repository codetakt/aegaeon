//! Exact prepared selection check before publishing protected startup inputs.
use super::*;
use crate::organizations::witness::cutover::Plan;

impl Configuration {
    /// Pure metadata check: it neither observes stores nor authorizes activation.
    /// Credential delivery, actual roles, certificate bytes and unit custody are
    /// separately bound by the root publication/activation coordinator.
    pub(crate) fn check_cutover(&self, plan: &Plan) -> Result<Vec<(Uuid, String)>> {
        plan.validate().map_err(|_| Error::Refused)?;
        let document = &self.document;
        if document.deployment_id != plan.deployment_id
            || document.selection != plan.parent.selection
            || document.environments.len() != plan.children.len()
        {
            return Err(Error::Refused);
        }
        for transport in [&document.control, &document.primary] {
            crate::organizations::witness::connection::options(
                &transport.url,
                &transport.root_cert,
            )?;
        }
        crate::organizations::store_observation::transport::redis_url(&document.token.url)
            .map_err(|_| Error::Refused)?;
        let mut selectors = Vec::with_capacity(document.environments.len());
        for (actual, expected) in document.environments.iter().zip(&plan.children) {
            if (actual.id, &actual.issuer, &actual.selection)
                != (
                    expected.environment_id,
                    &expected.issuer,
                    &expected.transition.selection,
                )
            {
                return Err(Error::Refused);
            }
            let issuer = url::Url::parse(&actual.issuer).map_err(|_| Error::Refused)?;
            let host = &issuer[url::Position::BeforeHost..url::Position::AfterPort];
            if self.startup_environment(host)? != (actual.id, actual.issuer.clone()) {
                return Err(Error::Refused);
            }
            selectors.push((actual.id, host.to_owned()));
        }
        Ok(selectors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn fixture() -> (Value, Plan) {
        let parent = Selection {
            epoch: Uuid::new_v4(),
            primary: Uuid::new_v4(),
            token_store: Uuid::new_v4(),
            source_sha256: "a".repeat(64),
            history_sha256: "b".repeat(64),
            acceptance_sha256: "c".repeat(64),
        };
        let mut child = parent.clone();
        child.epoch = Uuid::new_v4();
        let id = Uuid::new_v4();
        let deployment = Uuid::new_v4();
        let plan = serde_json::from_value(json!({
            "version":1,"deployment_id":deployment,"cutover_operation_id":Uuid::new_v4(),
            "parent":{"operation_id":Uuid::new_v4(),"revision":1,"selection":parent},
            "children":[{"environment_id":id,"issuer":"https://issuer.example/",
                "transition":{"operation_id":Uuid::new_v4(),"revision":1,"selection":child}}],
            "stores":{"primary":{},"control":{},"token":{}}
        }))
        .unwrap();
        let document = json!({
            "version":1,"deployment_id":deployment,"selection":parent,
            "control":{"url":"postgresql://runtime:fixture@control.example/control","root_cert":"/run/credentials/worker.service/root-cert"},
            "primary":{"url":"postgresql://runtime:fixture@primary.example/primary","root_cert":"/run/credentials/worker.service/root-cert"},
            "token":{"url":"rediss://runtime:fixture@token.example/0","root_cert":"/run/credentials/worker.service/root-cert"},
            "environments":[{"id":id,"issuer":"https://issuer.example/","selection":child}]
        });
        (document, plan)
    }

    fn check(value: &Value, plan: &Plan) -> bool {
        Configuration::parse(&serde_json::to_vec(value).unwrap())
            .and_then(|config| config.check_cutover(plan))
            .is_ok()
    }

    #[test]
    fn organization_cutover_startup_matches_complete_prepared_selection() {
        let (document, plan) = fixture();
        assert!(check(&document, &plan));
        for pointer in [
            "/deployment_id",
            "/environments/0/id",
            "/selection/epoch",
            "/environments/0/selection/epoch",
        ] {
            let mut changed = document.clone();
            *changed.pointer_mut(pointer).unwrap() = json!(Uuid::new_v4());
            assert!(!check(&changed, &plan), "{pointer}");
        }
        for field in ["source_sha256", "history_sha256", "acceptance_sha256"] {
            for parent in [true, false] {
                let mut changed = document.clone();
                let selection = if parent {
                    &mut changed["selection"]
                } else {
                    &mut changed["environments"][0]["selection"]
                };
                selection[field] = json!("d".repeat(64));
                assert!(!check(&changed, &plan), "{field}");
            }
        }
        let mut missing = document.clone();
        missing["environments"] = json!([]);
        assert!(!check(&missing, &plan));
        let mut foreign = document.clone();
        foreign["environments"][0]["issuer"] = json!("https://foreign.example/");
        assert!(!check(&foreign, &plan));
    }

    #[test]
    fn organization_cutover_startup_refuses_same_host_distinct_paths() {
        let (mut document, mut plan) = fixture();
        let mut child = plan.children[0].clone();
        child.environment_id = Uuid::new_v4();
        child.issuer = "https://issuer.example/other".into();
        child.transition.selection.epoch = Uuid::new_v4();
        document["environments"].as_array_mut().unwrap().push(json!({
            "id":child.environment_id,"issuer":child.issuer,"selection":child.transition.selection
        }));
        plan.children.push(child);
        // General parsing accepts multiple paths; each actual server must have
        // an unambiguous issuer-host selector before publication.
        assert!(Configuration::parse(&serde_json::to_vec(&document).unwrap()).is_ok());
        assert!(!check(&document, &plan));
    }

    #[test]
    fn organization_cutover_startup_returns_actual_native_host_selectors() {
        let (mut document, mut plan) = fixture();
        for (issuer, host) in [
            ("https://ISSUER.example:443/path", "issuer.example"),
            ("https://bücher.example/", "xn--bcher-kva.example"),
            ("https://[2001:DB8::1]:443/path", "[2001:db8::1]"),
            ("https://issuer.example:8443/path", "issuer.example:8443"),
        ] {
            document["environments"][0]["issuer"] = json!(issuer);
            plan.children[0].issuer = issuer.into();
            let config = Configuration::parse(&serde_json::to_vec(&document).unwrap()).unwrap();
            assert_eq!(
                config.check_cutover(&plan).unwrap(),
                vec![(plan.children[0].environment_id, host.into())]
            );
            assert_eq!(config.startup_environment(host).unwrap().1, issuer);
            // The predecessor root launcher copied Python's raw netloc. It
            // fails the actual server selector for the normalized forms above.
            let legacy = issuer
                .strip_prefix("https://")
                .unwrap()
                .split('/')
                .next()
                .unwrap();
            if legacy != host {
                assert!(config.startup_environment(legacy).is_err());
            }
        }
    }

    #[test]
    fn organization_cutover_reserves_revision_capacity_for_activation() {
        let (document, mut plan) = fixture();
        plan.parent.revision = i64::MAX - 3;
        plan.children[0].transition.revision = i64::MAX - 3;
        assert!(check(&document, &plan));
        plan.parent.revision += 1;
        assert!(!check(&document, &plan));
        plan.parent.revision -= 1;
        plan.children[0].transition.revision += 1;
        assert!(!check(&document, &plan));
    }

    #[test]
    fn organization_cutover_startup_refuses_transport_destination_overrides() {
        let (document, plan) = fixture();
        for store in ["control", "primary"] {
            for suffix in [
                "?host=foreign.example",
                "?options=-crole=owner",
                "#fragment",
            ] {
                let mut changed = document.clone();
                changed[store]["url"] = json!(format!(
                    "{}{}",
                    document[store]["url"].as_str().unwrap(),
                    suffix
                ));
                assert!(!check(&changed, &plan));
            }
        }
        let mut changed = document.clone();
        changed["token"]["url"] = json!("redis://runtime:fixture@token.example/0");
        assert!(!check(&changed, &plan));
    }
}
