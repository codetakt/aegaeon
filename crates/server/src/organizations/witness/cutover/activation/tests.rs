use super::super::{Child, Stores, Transition};
use super::*;
use crate::organizations::witness::Selection;

fn fixture() -> (Plan, Value) {
    let selection = Selection {
        epoch: Uuid::new_v4(),
        primary: Uuid::new_v4(),
        token_store: Uuid::new_v4(),
        source_sha256: "a".repeat(64),
        history_sha256: "b".repeat(64),
        acceptance_sha256: "c".repeat(64),
    };
    let parent = Transition {
        operation_id: Uuid::new_v4(),
        revision: 1,
        selection,
    };
    let child = Child {
        environment_id: Uuid::new_v4(),
        issuer: "https://issuer.example/".into(),
        transition: Transition {
            selection: Selection {
                epoch: Uuid::new_v4(),
                ..parent.selection.clone()
            },
            ..parent.clone()
        },
    };
    let plan = Plan {
        version: 1,
        deployment_id: Uuid::new_v4(),
        cutover_operation_id: Uuid::new_v4(),
        parent,
        children: vec![child],
        stores: Stores {
            primary: json!({}),
            control: json!({}),
            token: json!({}),
        },
    };
    let value = json!({"parentCheckpoint":{"principal":"selected_maintenance"},"bindings":[{
        "environment_id":plan.children[0].environment_id, "child_epoch":plan.children[0].transition.selection.epoch,
        "deployment_id":plan.deployment_id,"deployment_epoch":plan.parent.selection.epoch,
        "principal":"selected_maintenance","bound_at":"2026-11-04T08:00:00.123456+09:00"
    }]});
    (plan, value)
}

#[test]
fn organization_cutover_activation_preserves_complete_binding_provenance() {
    let (plan, value) = fixture();
    assert!(bindings(&value, &plan, true).is_ok());
    assert!(bindings(&value, &plan, false).is_err());
    let mut empty = value.clone();
    empty["bindings"] = json!([]);
    assert!(bindings(&empty, &plan, false).is_ok());
    assert!(bindings(&empty, &plan, true).is_err());
    for (field, wrong) in [
        ("principal", json!("another_maintenance")),
        ("bound_at", json!("invalid")),
        ("environment_id", json!(Uuid::new_v4())),
        ("deployment_epoch", json!(Uuid::new_v4())),
        ("extra", json!(true)),
    ] {
        let mut altered = value.clone();
        altered["bindings"][0][field] = wrong;
        assert!(bindings(&altered, &plan, true).is_err(), "{field}");
    }
    let mut missing = value.clone();
    missing["bindings"][0]
        .as_object_mut()
        .unwrap()
        .remove("bound_at");
    assert!(bindings(&missing, &plan, true).is_err());
    let mut duplicate = value.clone();
    duplicate["bindings"]
        .as_array_mut()
        .unwrap()
        .push(value["bindings"][0].clone());
    assert!(bindings(&duplicate, &plan, true).is_err());
}
