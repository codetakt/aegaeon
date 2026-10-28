use std::collections::BTreeSet;
use url::Url;

use super::{model::*, LtiError};

pub(super) fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

pub(super) fn identifier(value: &str) -> bool {
    text(value, 255) && value.is_ascii() && !value.contains(' ')
}

pub(super) fn https(value: &str) -> bool {
    text(value, 4096)
        && !value.contains(['\\', ' '])
        && Url::parse(value).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
}

pub(super) fn role(value: &str) -> bool {
    text(value, 512)
        && !value.contains(' ')
        && Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https" | "urn"))
}

/// Exact principal roles and context sub-roles from LTI Core Appendix A.2.
/// Unknown extension roles may accompany a vocabulary role.
pub(super) fn standard_role(value: &str) -> bool {
    [
        ("http://purl.imsglobal.org/vocab/lis/v2/membership#", "Administrator ContentDeveloper Instructor Learner Mentor Manager Member Officer"),
        ("http://purl.imsglobal.org/vocab/lis/v2/system/person#", "Administrator None AccountAdmin Creator SysAdmin SysSupport User"),
        ("http://purl.imsglobal.org/vocab/lis/v2/institution/person#", "Administrator Faculty Guest Learner Mentor None Other Staff Student Alumni Instructor Member Observer ProspectiveStudent"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Administrator#", "Administrator Developer ExternalDeveloper ExternalSupport ExternalSystemAdministrator Support SystemAdministrator"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/ContentDeveloper#", "ContentDeveloper ContentExpert ExternalContentExpert Librarian"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Instructor#", "ExternalInstructor Grader GuestInstructor Lecturer PrimaryInstructor SecondaryInstructor TeachingAssistant TeachingAssistantGroup TeachingAssistantOffering TeachingAssistantSection TeachingAssistantSectionAssociation TeachingAssistantTemplate"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Learner#", "ExternalLearner GuestLearner Instructor Learner NonCreditLearner"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Manager#", "AreaManager CourseCoordinator ExternalObserver Manager Observer"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Member#", "Member"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Mentor#", "Advisor Auditor ExternalAdvisor ExternalAuditor ExternalLearningFacilitator ExternalMentor ExternalReviewer ExternalTutor LearningFacilitator Mentor Reviewer Tutor"),
        ("http://purl.imsglobal.org/vocab/lis/v2/membership/Officer#", "Chair Communications Secretary Treasurer Vice-Chair"),
    ]
    .iter()
    .any(|(prefix, names)| {
        value.strip_prefix(prefix).is_some_and(|name| names.split(' ').any(|entry| entry == name))
    })
}

pub(super) fn roles(values: &BTreeSet<String>) -> bool {
    values.len() <= 64
        && values.iter().all(|value| role(value))
        && (values.is_empty() || values.iter().any(|value| standard_role(value)))
}

/// Validate a whole registration revision before it can be stored or activated.
///
/// # Errors
/// Rejects invalid destinations, duplicate identities, unsupported semantics or
/// mapping rules that can override protocol-owned claims.
pub fn validate_configuration(config: &ToolConfiguration) -> Result<(), LtiError> {
    aegaeon_attribute_mapping::validate_encoded_size(config, MAX_CONFIGURATION_BYTES)?;
    if config.schema_version != 1
        || !text(&config.name, 255)
        || !https(&config.initiate_login_uri)
        || config.redirect_uris.is_empty()
        || config.redirect_uris.len() > 32
        || !config.redirect_uris.iter().all(|uri| https(uri))
        || config.deployments.len() > 128
    {
        return Err(LtiError::Invalid);
    }
    let login = Url::parse(&config.initiate_login_uri).map_err(|_| LtiError::Invalid)?;
    if login.query_pairs().any(|(name, _)| {
        [
            "iss",
            "login_hint",
            "target_link_uri",
            "client_id",
            "lti_message_hint",
            "lti_deployment_id",
        ]
        .contains(&name.as_ref())
    }) {
        return Err(LtiError::Invalid);
    }
    let mut deployments = BTreeSet::new();
    let mut links = BTreeSet::new();
    for deployment in &config.deployments {
        if !identifier(&deployment.id)
            || !deployments.insert(&deployment.id)
            || deployment.producers.is_empty()
            || deployment.producers.len() > 64
            || !deployment.producers.iter().all(|value| text(value, 255))
            || deployment.allowed_roles.len() > 64
            || !deployment.allowed_roles.iter().all(|value| role(value))
            || deployment.resource_links.len() > 256
        {
            return Err(LtiError::Invalid);
        }
        for link in &deployment.resource_links {
            if !identifier(&link.id)
                || !links.insert(&link.id)
                || !https(&link.target_link_uri)
                || !identifier(&link.context.id)
                || !link.context.types.iter().all(|value| {
                    [
                        "http://purl.imsglobal.org/vocab/lis/v2/course#CourseTemplate",
                        "http://purl.imsglobal.org/vocab/lis/v2/course#CourseOffering",
                        "http://purl.imsglobal.org/vocab/lis/v2/course#CourseSection",
                        "http://purl.imsglobal.org/vocab/lis/v2/course#Group",
                    ]
                    .contains(&value.as_str())
                })
                || [
                    &link.title,
                    &link.description,
                    &link.context.label,
                    &link.context.title,
                ]
                .iter()
                .any(|value| value.as_ref().is_some_and(|value| !text(value, 4096)))
            {
                return Err(LtiError::Invalid);
            }
        }
    }
    super::claims::validate_mapping(&config.mapping)
}

fn lifecycle(previous: Lifecycle, next: Lifecycle) -> bool {
    previous != Lifecycle::Retired || next == Lifecycle::Retired
}

/// Preserve identifiers and terminal retirement across revisions, including drafts.
///
/// # Errors
/// Rejects removing or moving an existing identity and reviving a retired object.
pub fn validate_transition(
    old: &ToolConfiguration,
    new: &ToolConfiguration,
) -> Result<(), LtiError> {
    validate_configuration(new)?;
    if !lifecycle(old.status, new.status) {
        return Err(LtiError::Conflict);
    }
    for before in &old.deployments {
        let after = new
            .deployments
            .iter()
            .find(|value| value.id == before.id)
            .ok_or(LtiError::Conflict)?;
        if !lifecycle(before.status, after.status) {
            return Err(LtiError::Conflict);
        }
        for link in &before.resource_links {
            let next = after
                .resource_links
                .iter()
                .find(|value| value.id == link.id)
                .ok_or(LtiError::Conflict)?;
            if link.context.id != next.context.id || !lifecycle(link.status, next.status) {
                return Err(LtiError::Conflict);
            }
        }
    }
    Ok(())
}
