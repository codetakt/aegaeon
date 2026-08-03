use super::super::error_response;
use super::super::host_validation::normalize_dns_label;
use super::{CreateEnvironmentInput, CreateTenantInput};
use crate::management::types::{CreateEnvironmentRequest, CreateTenantRequest};
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn parse_create_tenant_input(
    req: &CreateTenantRequest,
    request_id: &str,
) -> Result<CreateTenantInput, Response> {
    let name = req.name.trim().to_owned();
    if name.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "name is required",
            None,
            Some(request_id),
        ));
    }
    let slug = parse_dns_label(&req.slug, "slug", request_id)?;
    let region = parse_dns_label(&req.region, "region", request_id)?;

    Ok(CreateTenantInput { slug, name, region })
}

pub(in crate::web::management) fn parse_update_name(
    name: Option<&str>,
    request_id: &str,
) -> Result<String, Response> {
    let Some(name) = name.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No updatable fields provided",
            None,
            Some(request_id),
        ));
    };

    Ok(name.to_owned())
}

pub(in crate::web::management) fn parse_create_environment_input(
    req: &CreateEnvironmentRequest,
    request_id: &str,
) -> Result<CreateEnvironmentInput, Response> {
    let name = req.name.trim().to_owned();
    if name.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "name is required",
            None,
            Some(request_id),
        ));
    }
    let slug = parse_dns_label(&req.slug, "slug", request_id)?;

    Ok(CreateEnvironmentInput { slug, name })
}

fn parse_dns_label(value: &str, label: &'static str, request_id: &str) -> Result<String, Response> {
    normalize_dns_label(value, label).map_err(|message| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &message,
            None,
            Some(request_id),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_create_tenant_input_normalizes_dns_labels() {
        let input = parse_create_tenant_input(
            &CreateTenantRequest {
                slug: " Primary ".to_string(),
                name: " Tenant ".to_string(),
                region: " AWS ".to_string(),
            },
            "req-1",
        )
        .expect("valid tenant input");

        assert_eq!(input.slug, "primary");
        assert_eq!(input.name, "Tenant");
        assert_eq!(input.region, "aws");
    }

    #[test]
    fn parse_create_tenant_input_rejects_non_dns_label_parts() {
        for (slug, region) in [
            ("bad.slug", "aws"),
            ("bad/slug", "aws"),
            ("-bad", "aws"),
            ("bad-", "aws"),
            ("primary", "aws/prod"),
            ("primary", "aws.prod"),
        ] {
            assert!(
                parse_create_tenant_input(
                    &CreateTenantRequest {
                        slug: slug.to_string(),
                        name: "Tenant".to_string(),
                        region: region.to_string(),
                    },
                    "req-1",
                )
                .is_err(),
                "{slug}/{region} should be rejected"
            );
        }
    }

    #[test]
    fn parse_create_environment_input_rejects_non_dns_label_slug() {
        for slug in ["bad.slug", "bad/slug", "-bad", "bad-"] {
            assert!(
                parse_create_environment_input(
                    &CreateEnvironmentRequest {
                        slug: slug.to_string(),
                        name: "Environment".to_string(),
                    },
                    "req-1",
                )
                .is_err(),
                "{slug} should be rejected"
            );
        }
    }
}
