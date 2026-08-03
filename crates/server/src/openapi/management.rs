#![allow(clippy::needless_for_each, clippy::wildcard_imports)] // OpenAPI schema assembly is generated-style DTO wiring.

use super::types::*;
use utoipa::openapi::security::{
    ApiKey as OpenApiApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme,
};
use utoipa::openapi::Components;
use utoipa::{Modify, OpenApi};

mod account_links;
mod api_keys;
mod audit_system;
mod auth_bootstrap;
mod clients;
mod configuration;
mod federation;
mod keys;
mod tenancy;
mod users;

const MANAGEMENT_BEARER_API_KEY_SCHEME: &str = "managementBearerApiKey";
const MANAGEMENT_SESSION_COOKIE_SCHEME: &str = "managementSessionCookie";
const MANAGEMENT_CSRF_HEADER_SCHEME: &str = "managementCsrfHeader";

struct ManagementSecuritySchemes;

impl Modify for ManagementSecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Components::new);
        components.add_security_scheme(
            MANAGEMENT_BEARER_API_KEY_SCHEME,
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("Aegaeon management API key")
                    .description(Some(
                        "Team-scoped management API key. Requests using this scheme must not send management cookies.",
                    ))
                    .build(),
            ),
        );
        components.add_security_scheme(
            MANAGEMENT_SESSION_COOKIE_SCHEME,
            SecurityScheme::ApiKey(OpenApiApiKey::Cookie(ApiKeyValue::with_description(
                "aeg_mgmt_session",
                "Interactive management session cookie.",
            ))),
        );
        components.add_security_scheme(
            MANAGEMENT_CSRF_HEADER_SCHEME,
            SecurityScheme::ApiKey(OpenApiApiKey::Header(ApiKeyValue::with_description(
                "X-CSRF-Token",
                "Double-submit CSRF token required for cookie-authenticated state-changing management requests.",
            ))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    modifiers(&ManagementSecuritySchemes),
    info(
        title = "Aegaeon Management API",
        version = "v1",
        description = "Control-plane management API contract (Phase 1 draft)."
    ),
    paths(
        auth_bootstrap::create_authentication_session,
        auth_bootstrap::delete_current_authentication_session,
        auth_bootstrap::bootstrap_owner,
        tenancy::list_teams,
        tenancy::create_team,
        tenancy::get_team,
        tenancy::update_team,
        tenancy::delete_team,
        tenancy::list_tenants,
        tenancy::create_tenant,
        tenancy::get_tenant,
        tenancy::update_tenant,
        tenancy::delete_tenant,
        tenancy::list_environments,
        tenancy::create_environment,
        tenancy::get_environment,
        tenancy::update_environment,
        tenancy::delete_environment,
        configuration::dcr_bearer_tokens::get_dcr_bearer_token_status,
        configuration::dcr_bearer_tokens::put_dcr_bearer_token,
        configuration::dcr_bearer_tokens::delete_dcr_bearer_token,
        api_keys::list_api_keys,
        api_keys::create_api_key,
        api_keys::revoke_api_key,
        configuration::versions::list_configuration_versions,
        configuration::versions::create_configuration_version,
        configuration::versions::get_configuration_version,
        configuration::versions::activate_configuration_version,
        configuration::versions::archive_configuration_version,
        configuration::policies::get_policies,
        configuration::policies::patch_policies,
        configuration::oauth_profiles::list_oauth_profiles,
        configuration::oauth_profiles::create_oauth_profile,
        configuration::oauth_profiles::get_oauth_profile,
        configuration::oauth_profiles::update_oauth_profile,
        configuration::oauth_profiles::delete_oauth_profile,
        configuration::connections::list_connections,
        configuration::connections::create_connection,
        configuration::connections::get_connection,
        configuration::connections::update_connection,
        configuration::connections::delete_connection,
        federation::list_federation_logout_recovery_incidents,
        federation::get_federation_logout_recovery_incident,
        federation::clear_federation_logout_recovery_incident,
        federation::list_federation_trust_anchors,
        federation::create_federation_trust_anchor,
        federation::get_federation_trust_anchor,
        federation::delete_federation_trust_anchor,
        federation::list_federation_entity_cache,
        federation::refresh_federation_entity_cache_entry,
        federation::delete_federation_entity_cache_entry,
        federation::list_federation_trust_chains,
        federation::refresh_federation_trust_chain,
        federation::delete_federation_trust_chain,
        account_links::create_account_link,
        account_links::preview_account_link_conflict,
        account_links::resolve_account_link_conflict,
        account_links::list_account_links,
        account_links::delete_account_link,
        account_links::bulk_relink_account_links,
        account_links::relink_account_link,
        clients::list_clients,
        clients::create_client,
        clients::get_client,
        clients::update_client,
        clients::delete_client,
        clients::list_client_secrets,
        clients::issue_client_secret,
        clients::revoke_client_secret,
        clients::revoke_all_client_secrets,
        keys::list_runtime_keys,
        keys::create_runtime_key,
        keys::activate_next_runtime_key,
        keys::revoke_runtime_key,
        keys::get_current_key_store,
        keys::put_current_key_store,
        users::lifecycle::list_users,
            users::lifecycle::create_user,
            users::lifecycle::get_user,
        users::lifecycle::update_user,
        users::lifecycle::delete_user,
        users::lifecycle::restore_user,
        users::lifecycle::suspend_user,
        users::lifecycle::unsuspend_user,
        users::lifecycle::invalidate_user_sessions,
        users::lifecycle::revoke_user_refresh_tokens,
        users::credentials::get_user_credentials,
        users::credentials::issue_activation_token,
        users::credentials::issue_password_reset_token,
        users::credentials::revoke_user_password_credential,
        users::credentials::revoke_user_recovery_token,
        users::profile::get_user_profile,
        users::profile::update_user_profile,
        users::sessions::list_user_sessions,
        users::sessions::revoke_user_session,
        users::grants::list_user_grants,
        users::grants::revoke_user_grant,
        users::grants::list_user_refresh_tokens,
        users::grants::revoke_user_refresh_token_inventory,
        users::bulk::invite_user,
        users::bulk::import_users_csv,
        audit_system::list_team_audit_events,
        audit_system::list_environment_audit_events,
        audit_system::get_audit_event,
        audit_system::system_health,
        audit_system::system_version
    ),
    components(
        schemas(
            ErrorResponse,
            PageInfo,
            Team,
            Tenant,
            Environment,
            DcrBearerTokenStatus,
            SetDcrBearerTokenRequest,
            ApiKey,
            ApiKeyCapability,
            CreateApiKeyRequest,
            CreateApiKeyResponse,
            ListApiKeysResponse,
            Client,
            ClientSecret,
            RuntimeKey,
            PolicyDocument,
            PolicyPatchRequest,
            PolicyPatchResponse,
            RuntimeActivationStatus,
            ActivateConfigurationVersionRequest,
            ConfigurationVersion,
            ConfigurationTransactionRequest,
            ClientMutationResponse,
            OAuthProfile,
            CreateOAuthProfileRequest,
            UpdateOAuthProfileRequest,
            OAuthProfileMutationResponse,
            Connection,
            FederationTrustAnchor,
            AccountLinkSummary,
            AccountLinkRefreshTokenHandling,
            AccountLinkConflictCandidate,
            AccountLinkConflictPreview,
            CreateAccountLinkRequest,
            PreviewAccountLinkConflictRequest,
            ResolveAccountLinkConflictRequest,
            BulkRelinkAccountLinksRequest,
            BulkRelinkAccountLinksResponse,
            RelinkAccountLinkRequest,
            CreateFederationTrustAnchorRequest,
            ListFederationTrustAnchorsResponse,
            FederationEntityCacheEntry,
            ListFederationEntityCacheResponse,
            FederationTrustChainEntry,
            ListFederationTrustChainsResponse,
            CreateConnectionRequest,
            UpdateConnectionRequest,
            ConnectionMutationResponse,
            ClientSecretMutationResponse,
            RuntimeKeyMutationResponse,
            EnvironmentMutationResponse,
            KeyStorePublicView,
            KeyStoreUpdateResponse,
            User,
            UserProfile,
            UpdateUserProfileRequest,
            PasswordCredential,
            RecoveryToken,
            UserCredentialsResponse,
            UserSessionInventoryEntry,
            ListUserSessionsResponse,
            UserGrantInventoryEntry,
            ListUserGrantsResponse,
            UserRefreshTokenInventoryEntry,
            ListUserRefreshTokensResponse,
            IssueRecoveryTokenRequest,
            IssueRecoveryTokenResponse,
            InviteUserRequest,
            InviteUserResponse,
            ImportUsersCsvRequest,
            ImportedUserRow,
            ImportUsersCsvResponse,
            AuditActor,
            AuditTarget,
            AuditRequestContext,
            AuditChange,
            AuditEvent,
            CreateTeamRequest,
            UpdateTeamRequest,
            CreateTenantRequest,
            UpdateTenantRequest,
            CreateEnvironmentRequest,
            UpdateEnvironmentRequest,
            CreateClientRequest,
            UpdateClientRequest,
            IssueClientSecretRequest,
            IssueClientSecretResponse,
            CreateRuntimeKeyRequest,
            ActivateRuntimeKeyRequest,
            CreateConfigurationVersionRequest,
            UpdateKeyStoreRequest,
            CreateSessionRequest,
            BootstrapOwnerRequest,
            SystemVersionResponse,
            ListTeamsResponse,
            ListTenantsResponse,
            ListEnvironmentsResponse,
            ListOAuthProfilesResponse,
            ListConnectionsResponse,
            FederationLogoutRecoveryIncident,
            ListFederationLogoutRecoveryIncidentsResponse,
            ClearFederationLogoutRecoveryIncidentRequest,
            ListAccountLinksResponse,
            ListClientsResponse,
            ListClientSecretsResponse,
            ListRuntimeKeysResponse,
            ListConfigurationVersionsResponse,
            ListAuditEventsResponse,
            ListUsersResponse
        )
    ),
    tags(
        (name = "authentication", description = "Management plane authentication"),
        (name = "bootstrapping", description = "One-time management plane bootstrap"),
        (name = "teams", description = "Team resources"),
        (name = "tenants", description = "Tenant resources"),
        (name = "environments", description = "Environment resources (issuer boundary)"),
        (name = "configurationVersions", description = "Configuration versioning and activation"),
        (name = "policies", description = "Policy shortcut endpoints"),
        (name = "apiKeys", description = "Team-scoped management API keys"),
        (name = "oauthProfiles", description = "OAuth profile configuration"),
        (name = "connections", description = "Upstream IdP connections"),
        (name = "federation", description = "Federation trust and cache diagnostics"),
        (name = "accountLinks", description = "Upstream account link operations"),
        (name = "clients", description = "Client registry resources"),
        (name = "clientSecrets", description = "Client secret lifecycle"),
        (name = "runtimeKeys", description = "Runtime key inventory for shared OIDC and token cryptography"),
        (name = "keyStores", description = "Environment keystore configuration"),
        (name = "users", description = "User operations (Phase 1 minimal)"),
        (name = "audit", description = "Audit events"),
        (name = "system", description = "System endpoints")
    ),
    security(
        ("managementBearerApiKey" = []),
        ("managementSessionCookie" = [], "managementCsrfHeader" = [])
    )
)]
pub struct ManagementApiV1;
