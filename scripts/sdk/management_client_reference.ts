import type {
  AccountLink,
  AccountLinkConflictCandidate,
  AccountLinkConflictPreview,
  AccountLinkInactiveTargetHandling,
  AccountLinkLowConfidenceHandling,
  AccountLinkRefreshTokenHandling,
  AuditEvent,
  BulkRelinkAccountLinksResponse,
  Client,
  ClientMutationResponse,
  ClientSecret,
  ClientSecretMutationResponse,
  ConfigurationVersion,
  Connection,
  ConnectionMutationResponse,
  CreateSessionRequest,
  DcrBearerTokenStatus,
  FederationLogoutRecoveryIncident,
  Environment,
  EnvironmentMutationResponse,
  ErrorResponse,
  ExportAuditEventsResponse,
  FederationEntityCacheEntry,
  FederationTrustAnchor,
  FederationTrustChainEntry,
  KeyStorePublicView,
  KeyStoreUpdateResponse,
  ListFederationLogoutRecoveryIncidentsResponse,
  ListAccountLinksResponse,
  ListAuditEventsResponse,
  ListClientSecretsResponse,
  ListClientsResponse,
  ListConfigurationVersionsResponse,
  ListConnectionsResponse,
  ListEnvironmentsResponse,
  ListFederationEntityCacheResponse,
  ListFederationTrustAnchorsResponse,
  ListFederationTrustChainsResponse,
  ListOAuthProfilesResponse,
  ListTeamsResponse,
  ListTenantsResponse,
  ListUsersResponse,
  ManagementClient,
  ManagementCookieJar,
  ManagementOperationDescriptor,
  ManagementSessionState,
  ManagementSessionStore,
  OAuthProfile,
  OAuthProfileMutationResponse,
  PageInfo,
  PolicyDocument,
  PolicyPatchResponse,
  SystemVersionResponse,
  Team,
  Tenant,
  User,
} from "../index.js";

const DEFAULT_BASE_PATH = "/api/v1";
const DEFAULT_CSRF_COOKIE_NAME = "csrf_token";
const DEFAULT_SESSION_COOKIE_NAME = "aegaeon_admin_session";
const DEFAULT_CREDENTIALS_MODE = "include";

type PlainObject = Record<string, unknown>;
type OptionalString = string | null | undefined;
type QueryScalar = string | number | boolean;
type QueryValue = QueryScalar | QueryScalar[] | null | undefined;
type QueryRecord = Record<string, QueryValue>;
type CookieReader = (() => string) | null;
type ResponseLike = {
  ok: boolean;
  status: number;
  headers?: Headers | {
    get?(name: string): string | null;
    getSetCookie?(): string[];
  };
  json(): Promise<unknown>;
  text(): Promise<string>;
};
type ManagementOperation = ManagementOperationDescriptor & {
  validate?: (value: unknown) => unknown;
};
type ManagementApiErrorDetails = {
  status: number;
  operationId: string;
  errorCode?: string | null;
  requestId?: string | null;
  details?: unknown;
  responseBody?: unknown;
};
type CreateDocumentCookieReaderOptions = { documentLike?: { cookie?: string } | null };
type CreateInMemoryCookieJarOptions = { initialCookies?: string | Record<string, string> | null };
type SessionStoreOverrides = Partial<{
  origin: string | null;
  teamId: string | null;
  csrfToken: string | null;
  csrfCookieName: string;
  credentials: string;
  cookieJar: ManagementCookieJar;
  cookieReader: CookieReader;
}>;
type CreateInMemoryManagementSessionStoreOptions = SessionStoreOverrides;
type BuildManagementOperationUrlOptions = {
  baseUrl: string;
  operationName: string;
  pathParams?: Record<string, string | null | undefined>;
  query?: QueryRecord;
  defaultTeamId?: string | null;
  basePath?: string;
};
type RequestOperationOptions = {
  pathParams?: Record<string, string | null | undefined>;
  query?: QueryRecord;
  body?: unknown;
  headers?: HeadersInit;
};
type CreateManagementClientOptions = {
  baseUrl: string;
  fetchImpl?: typeof fetch | null;
  sessionStore?: ManagementSessionStore | null;
  defaultTeamId?: string | null;
  origin?: string | null;
  basePath?: string;
};
type MethodInput<K extends keyof ManagementClient> =
  ManagementClient[K] extends (input: infer A, ...args: never[]) => unknown ? A : never;
type OptionalMethodInput<K extends keyof ManagementClient> = Exclude<MethodInput<K>, undefined>;

const WRITE_METHODS: ReadonlySet<ManagementOperation["method"]> = new Set([
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
]);

const POLICY_BOOLEAN_FIELDS = Object.freeze([
  "pkceRequired",
  "dcrEnabled",
  "requireStateParameter",
  "strictAuthorizeRedirect",
  "requireClientAuthToken",
  "requireClientAuthPar",
  "requireClientAuthIntrospection",
  "requireClientAuthRevocation",
  "dpopStrict",
  "dpopRequireNonce",
  "privateKeyJwtEnabled",
  "clientJwtRequireKid",
  "jwtBearerAllowClientSubject",
  "jwtAccessTokensEnabled",
  "jwtIntrospectionEnabled",
  "dcrRequirePkceForPublic",
  "dcrRequirePkceForConfidential",
  "dcrRequireSenderConstrained",
  "oidcEnabled",
  "oidcEnableDiscovery",
  "oidcEnableUserinfo",
  "oidcEnableLogout",
  "oidcEnableBackchannelLogout",
  "oidcRequireNonce",
  "mtlsEnabled",
  "mtlsAliasParEnabled",
]);

const POLICY_INTEGER_FIELDS = Object.freeze([
  "dpopIatWindowSeconds",
  "dpopNonceTtlSeconds",
  "parExpiresInSeconds",
  "jwtLeewaySeconds",
  "pkjwtJtiWindowSeconds",
  "jwtBearerJtiWindowSeconds",
  "requestObjectJtiTtlSeconds",
  "jwtIntrospectionExpSeconds",
  "ssaLeewaySeconds",
  "oidcLogoutSessionTtlSeconds",
  "oidcBackchannelLogoutTimeoutSeconds",
  "accessTokenTimeToLiveSeconds",
  "idTokenTimeToLiveSeconds",
  "refreshTokenTimeToLiveSeconds",
  "authorizationCodeTimeToLiveSeconds",
  "authSessionTtlSeconds",
  "authMaxSessions",
  "stepupChallengeTtlSeconds",
  "upstreamAuthTtlSeconds",
  "upstreamLogoutRelayTtlSeconds",
]);

const POLICY_STRING_ARRAY_FIELDS = Object.freeze([
  "clientJwtAllowedAlgs",
  "authorizationDetailsTypesSupported",
  "acrValuesSupported",
  "dcrAllowedSenderMethods",
  "allowedSigningAlgorithms",
  "allowedGrantTypes",
  "allowedResponseTypes",
]);

const POLICY_OPTIONAL_STRING_FIELDS = Object.freeze([
  "ssaJwtPem",
  "ssaExpectedIss",
  "ssaExpectedAud",
  "mtlsBaseUrl",
  "defaultAcr",
  "localPasswordAcr",
]);

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
  return value;
}

function requirePlainObject(value: unknown, fieldName: string): PlainObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${fieldName} must be a plain object`);
  }
  return value as PlainObject;
}

function normalizeOptionalString(value: unknown, fieldName: string): string | null {
  if (value == null) {
    return null;
  }
  return requireString(value, fieldName);
}

function requireBoolean(value: unknown, fieldName: string): boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(`${fieldName} must be a boolean`);
  }
  return value;
}

function requireInteger(value: unknown, fieldName: string): number {
  if (!Number.isInteger(value)) {
    throw new TypeError(`${fieldName} must be an integer`);
  }
  return value as number;
}

function requireArrayOfStrings(value: unknown, fieldName: string): string[] {
  if (!Array.isArray(value)) {
    throw new TypeError(`${fieldName} must be an array`);
  }
  for (let index = 0; index < value.length; index += 1) {
    requireString(value[index], `${fieldName}[${index}]`);
  }
  return Object.freeze([...value]) as unknown as string[];
}

function requirePresent(value: PlainObject, fieldName: string): unknown {
  if (!(fieldName in value)) {
    throw new TypeError(`${fieldName} is required`);
  }
  return value[fieldName];
}

function validatePageInfo(value: unknown, fieldName: string): Readonly<PageInfo> | null {
  if (value == null) {
    return null;
  }
  const pageInfo = requirePlainObject(value, fieldName);
  const nextPageToken = normalizeOptionalString(
    pageInfo.nextPageToken ?? null,
    `${fieldName}.nextPageToken`,
  );
  return Object.freeze({
    nextPageToken,
  });
}

function validateErrorResponse(value: unknown): Readonly<ErrorResponse> {
  const response = requirePlainObject(value, "errorResponse");
  return Object.freeze({
    errorCode: requireString(response.errorCode, "errorResponse.errorCode"),
    message: requireString(response.message, "errorResponse.message"),
    requestId: normalizeOptionalString(response.requestId ?? null, "errorResponse.requestId"),
    details: response.details ?? null,
  });
}

function validateTeam(value: unknown): Readonly<Team> {
  const team = requirePlainObject(value, "team");
  return Object.freeze({
    id: requireString(team.id, "team.id"),
    name: requireString(team.name, "team.name"),
    slug: normalizeOptionalString(team.slug ?? null, "team.slug"),
    createdAt: requireString(team.createdAt, "team.createdAt"),
    updatedAt: requireString(team.updatedAt, "team.updatedAt"),
  });
}

function validateTenant(value: unknown): Readonly<Tenant> {
  const tenant = requirePlainObject(value, "tenant");
  return Object.freeze({
    id: requireString(tenant.id, "tenant.id"),
    teamId: requireString(tenant.teamId, "tenant.teamId"),
    slug: requireString(tenant.slug, "tenant.slug"),
    name: requireString(tenant.name, "tenant.name"),
    region: requireString(tenant.region, "tenant.region"),
    createdAt: requireString(tenant.createdAt, "tenant.createdAt"),
    updatedAt: requireString(tenant.updatedAt, "tenant.updatedAt"),
  });
}

function validateEnvironment(value: unknown): Readonly<Environment> {
  const environment = requirePlainObject(value, "environment");
  return Object.freeze({
    id: requireString(environment.id, "environment.id"),
    teamId: requireString(environment.teamId, "environment.teamId"),
    tenantId: requireString(environment.tenantId, "environment.tenantId"),
    name: requireString(environment.name, "environment.name"),
    slug: requireString(environment.slug, "environment.slug"),
    issuerHost: requireString(environment.issuerHost, "environment.issuerHost"),
    issuerUrl: requireString(environment.issuerUrl, "environment.issuerUrl"),
    activeConfigurationVersionId: requireString(
      environment.activeConfigurationVersionId,
      "environment.activeConfigurationVersionId",
    ),
    createdAt: requireString(environment.createdAt, "environment.createdAt"),
    updatedAt: requireString(environment.updatedAt, "environment.updatedAt"),
  });
}

function validateDcrBearerTokenStatus(value: unknown): Readonly<DcrBearerTokenStatus> {
  const status = requirePlainObject(value, "dcrBearerTokenStatus");
  return Object.freeze({
    environmentId: requireString(status.environmentId, "dcrBearerTokenStatus.environmentId"),
    configured: requireBoolean(status.configured, "dcrBearerTokenStatus.configured"),
    hashAlgorithm: normalizeOptionalString(
      status.hashAlgorithm ?? null,
      "dcrBearerTokenStatus.hashAlgorithm",
    ),
    updatedAt: normalizeOptionalString(status.updatedAt ?? null, "dcrBearerTokenStatus.updatedAt"),
  });
}

function validateOAuthProfile(value: unknown): Readonly<OAuthProfile> {
  const oauthProfile = requirePlainObject(value, "oauthProfile");
  return Object.freeze({
    id: requireString(oauthProfile.id, "oauthProfile.id"),
    environmentId: requireString(oauthProfile.environmentId, "oauthProfile.environmentId"),
    configurationVersionId: requireString(
      oauthProfile.configurationVersionId,
      "oauthProfile.configurationVersionId",
    ),
    name: requireString(oauthProfile.name, "oauthProfile.name"),
    description: normalizeOptionalString(
      oauthProfile.description ?? null,
      "oauthProfile.description",
    ),
    profileType: requireString(oauthProfile.profileType, "oauthProfile.profileType"),
    oauthVersion: requireString(oauthProfile.oauthVersion, "oauthProfile.oauthVersion"),
    isDefault: requireBoolean(oauthProfile.isDefault, "oauthProfile.isDefault"),
    requirePkce: requireBoolean(oauthProfile.requirePkce, "oauthProfile.requirePkce"),
    requireStateParameter: requireBoolean(
      oauthProfile.requireStateParameter,
      "oauthProfile.requireStateParameter",
    ),
    requireIssParameter: requireBoolean(
      oauthProfile.requireIssParameter,
      "oauthProfile.requireIssParameter",
    ),
    allowImplicit: requireBoolean(oauthProfile.allowImplicit, "oauthProfile.allowImplicit"),
    allowRopc: requireBoolean(oauthProfile.allowRopc, "oauthProfile.allowRopc"),
    senderConstrained: requireString(
      oauthProfile.senderConstrained,
      "oauthProfile.senderConstrained",
    ),
    enforceRefreshSenderBinding: requireBoolean(
      oauthProfile.enforceRefreshSenderBinding,
      "oauthProfile.enforceRefreshSenderBinding",
    ),
    allowedGrantTypes: requireArrayOfStrings(
      oauthProfile.allowedGrantTypes,
      "oauthProfile.allowedGrantTypes",
    ),
    allowedResponseTypes: requireArrayOfStrings(
      oauthProfile.allowedResponseTypes,
      "oauthProfile.allowedResponseTypes",
    ),
    tokenEndpointAuthMethodsAllowed: requireArrayOfStrings(
      oauthProfile.tokenEndpointAuthMethodsAllowed,
      "oauthProfile.tokenEndpointAuthMethodsAllowed",
    ),
    expiresAt: normalizeOptionalString(oauthProfile.expiresAt ?? null, "oauthProfile.expiresAt"),
    status: requireString(oauthProfile.status, "oauthProfile.status"),
    createdAt: requireString(oauthProfile.createdAt, "oauthProfile.createdAt"),
    updatedAt: requireString(oauthProfile.updatedAt, "oauthProfile.updatedAt"),
  });
}

function validateConnection(value: unknown): Readonly<Connection> {
  const connection = requirePlainObject(value, "connection");
  return Object.freeze({
    id: requireString(connection.id, "connection.id"),
    environmentId: requireString(connection.environmentId, "connection.environmentId"),
    configurationVersionId: requireString(
      connection.configurationVersionId,
      "connection.configurationVersionId",
    ),
    oauthProfileId: normalizeOptionalString(
      connection.oauthProfileId ?? null,
      "connection.oauthProfileId",
    ),
    connectionIdentifier: requireString(
      connection.connectionIdentifier,
      "connection.connectionIdentifier",
    ),
    name: requireString(connection.name, "connection.name"),
    connectionType: requireString(connection.connectionType, "connection.connectionType"),
    issuerUrl: requireString(connection.issuerUrl, "connection.issuerUrl"),
    clientId: requireString(connection.clientId, "connection.clientId"),
    clientAuthMethod: requireString(connection.clientAuthMethod, "connection.clientAuthMethod"),
    status: requireString(connection.status, "connection.status"),
    createdAt: requireString(connection.createdAt, "connection.createdAt"),
    updatedAt: requireString(connection.updatedAt, "connection.updatedAt"),
  });
}

function validateAccountLink(value: unknown): Readonly<AccountLink> {
  const accountLink = requirePlainObject(value, "accountLink");
  return Object.freeze({
    id: requireString(accountLink.id, "accountLink.id"),
    environmentId: requireString(accountLink.environmentId, "accountLink.environmentId"),
    connectionId: requireString(accountLink.connectionId, "accountLink.connectionId"),
    connectionIdentifier: requireString(
      accountLink.connectionIdentifier,
      "accountLink.connectionIdentifier",
    ),
    connectionName: requireString(accountLink.connectionName, "accountLink.connectionName"),
    upstreamIssuer: requireString(accountLink.upstreamIssuer, "accountLink.upstreamIssuer"),
    endUserId: requireString(accountLink.endUserId, "accountLink.endUserId"),
    endUserSubject: requireString(accountLink.endUserSubject, "accountLink.endUserSubject"),
    endUserEmail: normalizeOptionalString(
      accountLink.endUserEmail ?? null,
      "accountLink.endUserEmail",
    ),
    endUserStatus: requireString(accountLink.endUserStatus, "accountLink.endUserStatus"),
    hasRefreshToken: requireBoolean(accountLink.hasRefreshToken, "accountLink.hasRefreshToken"),
    createdAt: requireString(accountLink.createdAt, "accountLink.createdAt"),
    lastUsedAt: normalizeOptionalString(accountLink.lastUsedAt ?? null, "accountLink.lastUsedAt"),
  });
}

function validateAccountLinkConflictPreview(
  value: unknown,
): Readonly<AccountLinkConflictPreview> {
  const preview = requirePlainObject(value, "accountLinkConflictPreview");
  return Object.freeze({
    requestedConnectionId: requireString(
      preview.requestedConnectionId,
      "accountLinkConflictPreview.requestedConnectionId",
    ),
    requestedConnectionIdentifier: requireString(
      preview.requestedConnectionIdentifier,
      "accountLinkConflictPreview.requestedConnectionIdentifier",
    ),
    requestedConnectionName: requireString(
      preview.requestedConnectionName,
      "accountLinkConflictPreview.requestedConnectionName",
    ),
    upstreamIssuer: requireString(
      preview.upstreamIssuer,
      "accountLinkConflictPreview.upstreamIssuer",
    ),
    upstreamSubject: requireString(
      preview.upstreamSubject,
      "accountLinkConflictPreview.upstreamSubject",
    ),
    existingAccountLink:
      preview.existingAccountLink == null
        ? null
        : validateAccountLink(preview.existingAccountLink),
    candidateEndUsers: (Array.isArray(preview.candidateEndUsers)
      ? preview.candidateEndUsers
      : []).map((candidate, index) =>
      validateAccountLinkConflictCandidate(
        candidate,
        `accountLinkConflictPreview.candidateEndUsers[${index}]`,
      ),
    ),
  });
}

function validateAccountLinkConflictCandidate(
  value: unknown,
  path: string,
): Readonly<AccountLinkConflictCandidate> {
  const candidate = requirePlainObject(value, path);
  return Object.freeze({
    endUser: validateUser(requirePresent(candidate, "endUser")),
    matchReasons: requireArrayOfStrings(candidate.matchReasons ?? [], `${path}.matchReasons`),
    recommended: requireBoolean(candidate.recommended, `${path}.recommended`),
  });
}

function validateFederationTrustAnchor(value: unknown): Readonly<FederationTrustAnchor> {
  const trustAnchor = requirePlainObject(value, "federationTrustAnchor");
  return Object.freeze({
    id: requireString(trustAnchor.id, "federationTrustAnchor.id"),
    environmentId: requireString(
      trustAnchor.environmentId,
      "federationTrustAnchor.environmentId",
    ),
    entityId: requireString(trustAnchor.entityId, "federationTrustAnchor.entityId"),
    jwks: requirePresent(trustAnchor, "jwks"),
    metadataPolicy: trustAnchor.metadataPolicy,
    createdAt: requireString(trustAnchor.createdAt, "federationTrustAnchor.createdAt"),
    updatedAt: requireString(trustAnchor.updatedAt, "federationTrustAnchor.updatedAt"),
  });
}

function validateFederationEntityCacheEntry(
  value: unknown,
): Readonly<FederationEntityCacheEntry> {
  const entry = requirePlainObject(value, "federationEntityCacheEntry");
  return Object.freeze({
    id: requireString(entry.id, "federationEntityCacheEntry.id"),
    environmentId: requireString(
      entry.environmentId,
      "federationEntityCacheEntry.environmentId",
    ),
    entityId: requireString(entry.entityId, "federationEntityCacheEntry.entityId"),
    entityConfigurationJws: requireString(
      entry.entityConfigurationJws,
      "federationEntityCacheEntry.entityConfigurationJws",
    ),
    parsedStatement: requirePresent(entry, "parsedStatement"),
    fetchedAt: requireString(entry.fetchedAt, "federationEntityCacheEntry.fetchedAt"),
    expiresAt: requireString(entry.expiresAt, "federationEntityCacheEntry.expiresAt"),
  });
}

function validateFederationTrustChainEntry(
  value: unknown,
): Readonly<FederationTrustChainEntry> {
  const entry = requirePlainObject(value, "federationTrustChainEntry");
  return Object.freeze({
    id: requireString(entry.id, "federationTrustChainEntry.id"),
    environmentId: requireString(
      entry.environmentId,
      "federationTrustChainEntry.environmentId",
    ),
    leafEntityId: requireString(
      entry.leafEntityId,
      "federationTrustChainEntry.leafEntityId",
    ),
    anchorEntityId: requireString(
      entry.anchorEntityId,
      "federationTrustChainEntry.anchorEntityId",
    ),
    chainJwts: requirePresent(entry, "chainJwts"),
    resolvedAt: requireString(entry.resolvedAt, "federationTrustChainEntry.resolvedAt"),
    expiresAt: requireString(entry.expiresAt, "federationTrustChainEntry.expiresAt"),
  });
}

function validateFederationLogoutRecoveryIncident(
  value: unknown,
): Readonly<FederationLogoutRecoveryIncident> {
  const incident = requirePlainObject(value, "federationLogoutRecoveryIncident");
  return Object.freeze({
    id: requireString(incident.id, "federationLogoutRecoveryIncident.id"),
    teamId: requireString(incident.teamId, "federationLogoutRecoveryIncident.teamId"),
    tenantId: requireString(incident.tenantId, "federationLogoutRecoveryIncident.tenantId"),
    environmentId: requireString(
      incident.environmentId,
      "federationLogoutRecoveryIncident.environmentId",
    ),
    connectionId: normalizeOptionalString(
      incident.connectionId ?? null,
      "federationLogoutRecoveryIncident.connectionId",
    ),
    connectionIdentifier: normalizeOptionalString(
      incident.connectionIdentifier ?? null,
      "federationLogoutRecoveryIncident.connectionIdentifier",
    ),
    connectionName: normalizeOptionalString(
      incident.connectionName ?? null,
      "federationLogoutRecoveryIncident.connectionName",
    ),
    downstreamClientId: normalizeOptionalString(
      incident.downstreamClientId ?? null,
      "federationLogoutRecoveryIncident.downstreamClientId",
    ),
    upstreamIssuer: requireString(
      incident.upstreamIssuer,
      "federationLogoutRecoveryIncident.upstreamIssuer",
    ),
    recoveryPolicy: requireString(
      incident.recoveryPolicy,
      "federationLogoutRecoveryIncident.recoveryPolicy",
    ),
    status: requireString(incident.status, "federationLogoutRecoveryIncident.status"),
    sessionHintClaim: normalizeOptionalString(
      incident.sessionHintClaim ?? null,
      "federationLogoutRecoveryIncident.sessionHintClaim",
    ),
    sessionHintPresent: requireBoolean(
      incident.sessionHintPresent,
      "federationLogoutRecoveryIncident.sessionHintPresent",
    ),
    downstreamRedirectUri: requireString(
      incident.downstreamRedirectUri,
      "federationLogoutRecoveryIncident.downstreamRedirectUri",
    ),
    downstreamStatePresent: requireBoolean(
      incident.downstreamStatePresent,
      "federationLogoutRecoveryIncident.downstreamStatePresent",
    ),
    failureReason: normalizeOptionalString(
      incident.failureReason ?? null,
      "federationLogoutRecoveryIncident.failureReason",
    ),
    requestId: requireString(incident.requestId, "federationLogoutRecoveryIncident.requestId"),
    createdAt: requireString(incident.createdAt, "federationLogoutRecoveryIncident.createdAt"),
    expiresAt: requireString(incident.expiresAt, "federationLogoutRecoveryIncident.expiresAt"),
    resolvedAt: normalizeOptionalString(
      incident.resolvedAt ?? null,
      "federationLogoutRecoveryIncident.resolvedAt",
    ),
  });
}

function validateClient(value: unknown): Readonly<Client> {
  const client = requirePlainObject(value, "client");
  return Object.freeze({
    id: requireString(client.id, "client.id"),
    environmentId: requireString(client.environmentId, "client.environmentId"),
    oauthProfileId: normalizeOptionalString(client.oauthProfileId ?? null, "client.oauthProfileId"),
    clientIdentifier: requireString(client.clientIdentifier, "client.clientIdentifier"),
    name: requireString(client.name, "client.name"),
    clientType: requireString(client.clientType, "client.clientType"),
    redirectUris: requireArrayOfStrings(client.redirectUris, "client.redirectUris"),
    allowedGrantTypes: requireArrayOfStrings(client.allowedGrantTypes, "client.allowedGrantTypes"),
    allowedResponseTypes: requireArrayOfStrings(
      client.allowedResponseTypes,
      "client.allowedResponseTypes",
    ),
    allowedScopes: requireArrayOfStrings(client.allowedScopes, "client.allowedScopes"),
    tokenEndpointAuthenticationMethod: requireString(
      client.tokenEndpointAuthenticationMethod,
      "client.tokenEndpointAuthenticationMethod",
    ),
    requirePkce: requireBoolean(client.requirePkce, "client.requirePkce"),
    createdAt: requireString(client.createdAt, "client.createdAt"),
    updatedAt: requireString(client.updatedAt, "client.updatedAt"),
  });
}

function validateUser(value: unknown): Readonly<User> {
  const user = requirePlainObject(value, "user");
  return Object.freeze({
    id: requireString(user.id, "user.id"),
    environmentId: requireString(user.environmentId, "user.environmentId"),
    subject: requireString(user.subject, "user.subject"),
    status: requireString(user.status, "user.status"),
    createdAt: requireString(user.createdAt, "user.createdAt"),
    updatedAt: requireString(user.updatedAt, "user.updatedAt"),
    email: normalizeOptionalString(user.email ?? null, "user.email"),
  });
}

function validatePasswordCredential(
  value: unknown,
): Readonly<import("../index.js").PasswordCredential> {
  const credential = requirePlainObject(value, "passwordCredential");
  return Object.freeze({
    id: requireString(credential.id, "passwordCredential.id"),
    status: requireString(credential.status, "passwordCredential.status"),
    createdAt: requireString(credential.createdAt, "passwordCredential.createdAt"),
    updatedAt: requireString(credential.updatedAt, "passwordCredential.updatedAt"),
    lastUsedAt: normalizeOptionalString(
      credential.lastUsedAt ?? null,
      "passwordCredential.lastUsedAt",
    ),
  });
}

function validateRecoveryToken(value: unknown): Readonly<import("../index.js").RecoveryToken> {
  const token = requirePlainObject(value, "recoveryToken");
  return Object.freeze({
    id: requireString(token.id, "recoveryToken.id"),
    purpose: requireString(token.purpose, "recoveryToken.purpose"),
    status: requireString(token.status, "recoveryToken.status"),
    expiresAt: requireString(token.expiresAt, "recoveryToken.expiresAt"),
    redeemedAt: normalizeOptionalString(token.redeemedAt ?? null, "recoveryToken.redeemedAt"),
    revokedAt: normalizeOptionalString(token.revokedAt ?? null, "recoveryToken.revokedAt"),
    createdAt: requireString(token.createdAt, "recoveryToken.createdAt"),
  });
}

function validateUserCredentialsResponse(
  value: unknown,
): Readonly<import("../index.js").UserCredentialsResponse> {
  const response = requirePlainObject(value, "userCredentialsResponse");
  return Object.freeze({
    password:
      response.password == null ? null : validatePasswordCredential(response.password),
    recoveryTokens: (Array.isArray(response.recoveryTokens) ? response.recoveryTokens : []).map(
      (entry) => validateRecoveryToken(entry),
    ),
  });
}

function validateIssueRecoveryTokenResponse(
  value: unknown,
): Readonly<import("../index.js").IssueRecoveryTokenResponse> {
  const response = requirePlainObject(value, "issueRecoveryTokenResponse");
  return Object.freeze({
    token: requireString(response.token, "issueRecoveryTokenResponse.token"),
    redeemUrl: requireString(response.redeemUrl, "issueRecoveryTokenResponse.redeemUrl"),
    recoveryToken: validateRecoveryToken(
      requirePresent(response, "recoveryToken"),
    ),
  });
}

function validateUserProfile(value: unknown): Readonly<import("../index.js").UserProfile> {
  const profile = requirePlainObject(value, "userProfile");
  return Object.freeze({
    userId: requireString(profile.userId, "userProfile.userId"),
    subject: requireString(profile.subject, "userProfile.subject"),
    subjectPolicy: requireString(profile.subjectPolicy, "userProfile.subjectPolicy"),
    email: normalizeOptionalString(profile.email ?? null, "userProfile.email"),
    emailVerified: requireBoolean(profile.emailVerified, "userProfile.emailVerified"),
    displayName: normalizeOptionalString(profile.displayName ?? null, "userProfile.displayName"),
    customClaims: Object.freeze({
      ...requirePlainObject(profile.customClaims ?? {}, "userProfile.customClaims"),
    }),
    version: requireInteger(profile.version, "userProfile.version"),
    updatedAt: requireString(profile.updatedAt, "userProfile.updatedAt"),
  });
}

function validateUserSessionInventoryEntry(
  value: unknown,
): Readonly<import("../index.js").UserSessionInventoryEntry> {
  const session = requirePlainObject(value, "userSessionInventoryEntry");
  return Object.freeze({
    id: requireString(session.id, "userSessionInventoryEntry.id"),
    authTimeEpochSeconds: requireInteger(
      session.authTimeEpochSeconds,
      "userSessionInventoryEntry.authTimeEpochSeconds",
    ),
    acr: normalizeOptionalString(session.acr ?? null, "userSessionInventoryEntry.acr"),
  });
}

function validateListUserSessionsResponse(
  value: unknown,
): Readonly<import("../index.js").ListUserSessionsResponse> {
  const response = requirePlainObject(value, "listUserSessionsResponse");
  if (!Array.isArray(response.sessions)) {
    throw new TypeError("listUserSessionsResponse.sessions must be an array");
  }
  return Object.freeze({
    sessions: response.sessions.map((entry) => validateUserSessionInventoryEntry(entry)),
  });
}

function validateUserGrantInventoryEntry(
  value: unknown,
): Readonly<import("../index.js").UserGrantInventoryEntry> {
  const grant = requirePlainObject(value, "userGrantInventoryEntry");
  return Object.freeze({
    id: requireString(grant.id, "userGrantInventoryEntry.id"),
    source: requireString(grant.source, "userGrantInventoryEntry.source"),
    clientId: requireString(grant.clientId, "userGrantInventoryEntry.clientId"),
    scopes: requireArrayOfStrings(grant.scopes ?? [], "userGrantInventoryEntry.scopes"),
    audience: requireString(grant.audience, "userGrantInventoryEntry.audience"),
    authorizationDetails: grant.authorizationDetails ?? null,
    authTimeEpochSeconds:
      grant.authTimeEpochSeconds == null
        ? null
        : requireInteger(
            grant.authTimeEpochSeconds,
            "userGrantInventoryEntry.authTimeEpochSeconds",
          ),
    acr: normalizeOptionalString(grant.acr ?? null, "userGrantInventoryEntry.acr"),
    expiresAtEpochSeconds: requireInteger(
      grant.expiresAtEpochSeconds,
      "userGrantInventoryEntry.expiresAtEpochSeconds",
    ),
  });
}

function validateListUserGrantsResponse(
  value: unknown,
): Readonly<import("../index.js").ListUserGrantsResponse> {
  const response = requirePlainObject(value, "listUserGrantsResponse");
  if (!Array.isArray(response.grants)) {
    throw new TypeError("listUserGrantsResponse.grants must be an array");
  }
  return Object.freeze({
    grants: response.grants.map((entry) => validateUserGrantInventoryEntry(entry)),
  });
}

function validateUserRefreshTokenInventoryEntry(
  value: unknown,
): Readonly<import("../index.js").UserRefreshTokenInventoryEntry> {
  const token = requirePlainObject(value, "userRefreshTokenInventoryEntry");
  return Object.freeze({
    id: requireString(token.id, "userRefreshTokenInventoryEntry.id"),
    clientId: requireString(token.clientId, "userRefreshTokenInventoryEntry.clientId"),
    scopes: requireArrayOfStrings(token.scopes ?? [], "userRefreshTokenInventoryEntry.scopes"),
    resource: normalizeOptionalString(
      token.resource ?? null,
      "userRefreshTokenInventoryEntry.resource",
    ),
    senderBinding: normalizeOptionalString(
      token.senderBinding ?? null,
      "userRefreshTokenInventoryEntry.senderBinding",
    ),
    authorizationDetails: token.authorizationDetails ?? null,
    authTimeEpochSeconds: requireInteger(
      token.authTimeEpochSeconds,
      "userRefreshTokenInventoryEntry.authTimeEpochSeconds",
    ),
    acr: normalizeOptionalString(token.acr ?? null, "userRefreshTokenInventoryEntry.acr"),
    expiresAtEpochSeconds: requireInteger(
      token.expiresAtEpochSeconds,
      "userRefreshTokenInventoryEntry.expiresAtEpochSeconds",
    ),
    rotationCount: requireInteger(
      token.rotationCount,
      "userRefreshTokenInventoryEntry.rotationCount",
    ),
  });
}

function validateListUserRefreshTokensResponse(
  value: unknown,
): Readonly<import("../index.js").ListUserRefreshTokensResponse> {
  const response = requirePlainObject(value, "listUserRefreshTokensResponse");
  if (!Array.isArray(response.refreshTokens)) {
    throw new TypeError("listUserRefreshTokensResponse.refreshTokens must be an array");
  }
  return Object.freeze({
    refreshTokens: response.refreshTokens.map((entry) =>
      validateUserRefreshTokenInventoryEntry(entry),
    ),
  });
}

function validateInviteUserResponse(
  value: unknown,
): Readonly<import("../index.js").InviteUserResponse> {
  const response = requirePlainObject(value, "inviteUserResponse");
  return Object.freeze({
    user: validateUser(requirePresent(response, "user")),
    activation: validateIssueRecoveryTokenResponse(
      requirePresent(response, "activation"),
    ),
  });
}

function validateImportedUserRow(
  value: unknown,
): Readonly<import("../index.js").ImportedUserRow> {
  const row = requirePlainObject(value, "importedUserRow");
  return Object.freeze({
    rowNumber: requireInteger(row.rowNumber, "importedUserRow.rowNumber"),
    user: validateUser(requirePresent(row, "user")),
    activation:
      row.activation == null ? null : validateIssueRecoveryTokenResponse(row.activation),
  });
}

function validateImportUsersCsvResponse(
  value: unknown,
): Readonly<import("../index.js").ImportUsersCsvResponse> {
  const response = requirePlainObject(value, "importUsersCsvResponse");
  if (!Array.isArray(response.importedUsers)) {
    throw new TypeError("importUsersCsvResponse.importedUsers must be an array");
  }
  return Object.freeze({
    importedUsers: response.importedUsers.map((entry) => validateImportedUserRow(entry)),
  });
}

function validateListResponse<T>(
  value: unknown,
  fieldName: string,
  itemValidator: (value: unknown) => T,
): Readonly<Record<string, readonly T[] | Readonly<PageInfo> | null>> {
  const response = requirePlainObject(value, `${fieldName}Response`);
  if (!Array.isArray(response[fieldName])) {
    throw new TypeError(`${fieldName}Response.${fieldName} must be an array`);
  }
  return Object.freeze({
    [fieldName]: Object.freeze(response[fieldName].map((entry) => itemValidator(entry))),
    pageInfo: validatePageInfo(response.pageInfo ?? null, `${fieldName}Response.pageInfo`),
  });
}

function validateEnvironmentMutationResponse(
  value: unknown,
): Readonly<EnvironmentMutationResponse> {
  const response = requirePlainObject(value, "environmentMutationResponse");
  return Object.freeze({
    environment: validateEnvironment(response.environment),
  });
}

function validateOAuthProfileMutationResponse(
  value: unknown,
): Readonly<OAuthProfileMutationResponse> {
  const response = requirePlainObject(value, "oauthProfileMutationResponse");
  return Object.freeze({
    oauthProfile: validateOAuthProfile(response.oauthProfile),
    environment: validateEnvironment(response.environment),
  });
}

function validateConnectionMutationResponse(value: unknown): Readonly<ConnectionMutationResponse> {
  const response = requirePlainObject(value, "connectionMutationResponse");
  return Object.freeze({
    connection: validateConnection(response.connection),
    environment: validateEnvironment(response.environment),
  });
}

function validateSystemVersionResponse(value: unknown): Readonly<SystemVersionResponse> {
  const response = requirePlainObject(value, "systemVersionResponse");
  return Object.freeze({
    version: requireString(response.version, "systemVersionResponse.version"),
    commit: normalizeOptionalString(response.commit ?? null, "systemVersionResponse.commit"),
  });
}

function validatePolicyDocument(value: unknown): Readonly<PolicyDocument> {
  const policy = requirePlainObject(value, "policy");
  for (const fieldName of POLICY_BOOLEAN_FIELDS) {
    if (fieldName in policy && policy[fieldName] != null) {
      requireBoolean(policy[fieldName], `policy.${fieldName}`);
    }
  }
  for (const fieldName of POLICY_INTEGER_FIELDS) {
    if (fieldName in policy && policy[fieldName] != null) {
      requireInteger(policy[fieldName], `policy.${fieldName}`);
    }
  }
  for (const fieldName of POLICY_STRING_ARRAY_FIELDS) {
    if (fieldName in policy && policy[fieldName] != null) {
      requireArrayOfStrings(policy[fieldName], `policy.${fieldName}`);
    }
  }
  for (const fieldName of POLICY_OPTIONAL_STRING_FIELDS) {
    if (fieldName in policy) {
      normalizeOptionalString(policy[fieldName], `policy.${fieldName}`);
    }
  }
  return Object.freeze({ ...policy }) as Readonly<PolicyDocument>;
}

function validatePolicyPatchResponse(value: unknown): Readonly<PolicyPatchResponse> {
  const response = requirePlainObject(value, "policyPatchResponse");
  return Object.freeze({
    environment: validateEnvironment(response.environment),
    policy: validatePolicyDocument(response.policy),
  });
}

export const MANAGEMENT_OPENAPI_METADATA = Object.freeze({
  title: "Aegaeon Management API",
  version: "v1",
  pathCount: 75,
  sourceArtifact: "generated/openapi/aegaeon-management-api.v1.json",
});

export const MANAGEMENT_CLIENT_DEFAULTS = Object.freeze({
  basePath: DEFAULT_BASE_PATH,
  csrfCookieName: DEFAULT_CSRF_COOKIE_NAME,
  sessionCookieName: DEFAULT_SESSION_COOKIE_NAME,
  credentials: DEFAULT_CREDENTIALS_MODE,
});

export const MANAGEMENT_OPERATIONS: Readonly<Record<string, ManagementOperation>> = Object.freeze({
  systemHealth: Object.freeze({
    operationId: "system_health",
    method: "GET",
    path: "/system/health",
    responseType: "text",
  }),
  systemVersion: Object.freeze({
    operationId: "system_version",
    method: "GET",
    path: "/system/version",
    responseType: "json",
    validate: validateSystemVersionResponse,
  }),
  bootstrapOwner: Object.freeze({
    operationId: "bootstrap_owner",
    method: "POST",
    path: "/bootstrapping/owners",
    responseType: "empty",
  }),
  createAuthenticationSession: Object.freeze({
    operationId: "create_authentication_session",
    method: "POST",
    path: "/authentication/sessions",
    responseType: "empty",
  }),
  deleteCurrentAuthenticationSession: Object.freeze({
    operationId: "delete_current_authentication_session",
    method: "DELETE",
    path: "/authentication/sessions/current",
    responseType: "empty",
  }),
  listTeams: Object.freeze({
    operationId: "list_teams",
    method: "GET",
    path: "/teams",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "teams", validateTeam) as ListTeamsResponse,
  }),
  createTeam: Object.freeze({
    operationId: "create_team",
    method: "POST",
    path: "/teams",
    responseType: "json",
    validate: validateTeam,
  }),
  getTeam: Object.freeze({
    operationId: "get_team",
    method: "GET",
    path: "/teams/{teamId}",
    responseType: "json",
    validate: validateTeam,
  }),
  updateTeam: Object.freeze({
    operationId: "update_team",
    method: "PATCH",
    path: "/teams/{teamId}",
    responseType: "json",
    validate: validateTeam,
  }),
  deleteTeam: Object.freeze({
    operationId: "delete_team",
    method: "DELETE",
    path: "/teams/{teamId}",
    responseType: "empty",
  }),
  listApiKeys: Object.freeze({
    operationId: "list_api_keys",
    method: "GET",
    path: "/teams/{teamId}/apiKeys",
    responseType: "json",
  }),
  createApiKey: Object.freeze({
    operationId: "create_api_key",
    method: "POST",
    path: "/teams/{teamId}/apiKeys",
    responseType: "json",
  }),
  revokeApiKey: Object.freeze({
    operationId: "revoke_api_key",
    method: "POST",
    path: "/teams/{teamId}/apiKeys/{apiKeyId}/revoke",
    responseType: "empty",
  }),
  listTenants: Object.freeze({
    operationId: "list_tenants",
    method: "GET",
    path: "/teams/{teamId}/tenants",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "tenants", validateTenant) as ListTenantsResponse,
  }),
  createTenant: Object.freeze({
    operationId: "create_tenant",
    method: "POST",
    path: "/teams/{teamId}/tenants",
    responseType: "json",
    validate: validateTenant,
  }),
  getTenant: Object.freeze({
    operationId: "get_tenant",
    method: "GET",
    path: "/teams/{teamId}/tenants/{tenantId}",
    responseType: "json",
    validate: validateTenant,
  }),
  updateTenant: Object.freeze({
    operationId: "update_tenant",
    method: "PATCH",
    path: "/teams/{teamId}/tenants/{tenantId}",
    responseType: "json",
    validate: validateTenant,
  }),
  deleteTenant: Object.freeze({
    operationId: "delete_tenant",
    method: "DELETE",
    path: "/teams/{teamId}/tenants/{tenantId}",
    responseType: "empty",
  }),
  listEnvironments: Object.freeze({
    operationId: "list_environments",
    method: "GET",
    path: "/teams/{teamId}/tenants/{tenantId}/environments",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "environments", validateEnvironment) as ListEnvironmentsResponse,
  }),
  createEnvironment: Object.freeze({
    operationId: "create_environment",
    method: "POST",
    path: "/teams/{teamId}/tenants/{tenantId}/environments",
    responseType: "json",
    validate: validateEnvironment,
  }),
  getEnvironment: Object.freeze({
    operationId: "get_environment",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}",
    responseType: "json",
    validate: validateEnvironment,
  }),
  updateEnvironment: Object.freeze({
    operationId: "update_environment",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}",
    responseType: "json",
    validate: validateEnvironment,
  }),
  deleteEnvironment: Object.freeze({
    operationId: "delete_environment",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}",
    responseType: "empty",
  }),
  getDcrBearerTokenStatus: Object.freeze({
    operationId: "get_dcr_bearer_token_status",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/dcrBearerToken",
    responseType: "json",
    validate: validateDcrBearerTokenStatus,
  }),
  putDcrBearerToken: Object.freeze({
    operationId: "put_dcr_bearer_token",
    method: "PUT",
    path: "/teams/{teamId}/environments/{environmentId}/dcrBearerToken",
    responseType: "json",
    validate: validateDcrBearerTokenStatus,
  }),
  deleteDcrBearerToken: Object.freeze({
    operationId: "delete_dcr_bearer_token",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/dcrBearerToken",
    responseType: "empty",
  }),
  listOAuthProfiles: Object.freeze({
    operationId: "list_oauth_profiles",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/oauthProfiles",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "oauthProfiles",
        validateOAuthProfile,
      ) as ListOAuthProfilesResponse,
  }),
  createOAuthProfile: Object.freeze({
    operationId: "create_oauth_profile",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/oauthProfiles",
    responseType: "json",
    validate: validateOAuthProfileMutationResponse,
  }),
  getOAuthProfile: Object.freeze({
    operationId: "get_oauth_profile",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    responseType: "json",
    validate: validateOAuthProfile,
  }),
  updateOAuthProfile: Object.freeze({
    operationId: "update_oauth_profile",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    responseType: "json",
    validate: validateOAuthProfileMutationResponse,
  }),
  deleteOAuthProfile: Object.freeze({
    operationId: "delete_oauth_profile",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/oauthProfiles/{oauthProfileId}",
    responseType: "empty",
  }),
  listConnections: Object.freeze({
    operationId: "list_connections",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/connections",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "connections", validateConnection) as ListConnectionsResponse,
  }),
  createConnection: Object.freeze({
    operationId: "create_connection",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/connections",
    responseType: "json",
    validate: validateConnectionMutationResponse,
  }),
  getConnection: Object.freeze({
    operationId: "get_connection",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    responseType: "json",
    validate: validateConnection,
  }),
  updateConnection: Object.freeze({
    operationId: "update_connection",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    responseType: "json",
    validate: validateConnectionMutationResponse,
  }),
  deleteConnection: Object.freeze({
    operationId: "delete_connection",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/connections/{connectionId}",
    responseType: "empty",
  }),
  listAccountLinks: Object.freeze({
    operationId: "list_account_links",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "accountLinks", validateAccountLink) as ListAccountLinksResponse,
  }),
  createAccountLink: Object.freeze({
    operationId: "create_account_link",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks",
    responseType: "json",
    validate: validateAccountLink,
  }),
  previewAccountLinkConflict: Object.freeze({
    operationId: "preview_account_link_conflict",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks/conflictPreview",
    responseType: "json",
    validate: validateAccountLinkConflictPreview,
  }),
  resolveAccountLinkConflict: Object.freeze({
    operationId: "resolve_account_link_conflict",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks/resolveConflict",
    responseType: "json",
    validate: validateAccountLink,
  }),
  bulkRelinkAccountLinks: Object.freeze({
    operationId: "bulk_relink_account_links",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks/bulkRelink",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "accountLinks",
        validateAccountLink,
      ) as BulkRelinkAccountLinksResponse,
  }),
  relinkAccountLink: Object.freeze({
    operationId: "relink_account_link",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks/{accountLinkId}/relink",
    responseType: "json",
    validate: validateAccountLink,
  }),
  deleteAccountLink: Object.freeze({
    operationId: "delete_account_link",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/accountLinks/{accountLinkId}",
    responseType: "empty",
  }),
  listFederationLogoutRecoveryIncidents: Object.freeze({
    operationId: "list_federation_logout_recovery_incidents",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/federationLogoutRecoveryIncidents",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "incidents",
        validateFederationLogoutRecoveryIncident,
      ) as ListFederationLogoutRecoveryIncidentsResponse,
  }),
  getFederationLogoutRecoveryIncident: Object.freeze({
    operationId: "get_federation_logout_recovery_incident",
    method: "GET",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "federationLogoutRecoveryIncidents/{incidentId}",
    responseType: "json",
    validate: validateFederationLogoutRecoveryIncident,
  }),
  clearFederationLogoutRecoveryIncident: Object.freeze({
    operationId: "clear_federation_logout_recovery_incident",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "federationLogoutRecoveryIncidents/{incidentId}/clear",
    responseType: "empty",
  }),
  listFederationTrustAnchors: Object.freeze({
    operationId: "list_federation_trust_anchors",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustAnchors",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "trustAnchors",
        validateFederationTrustAnchor,
      ) as ListFederationTrustAnchorsResponse,
  }),
  createFederationTrustAnchor: Object.freeze({
    operationId: "create_federation_trust_anchor",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustAnchors",
    responseType: "json",
    validate: validateFederationTrustAnchor,
  }),
  getFederationTrustAnchor: Object.freeze({
    operationId: "get_federation_trust_anchor",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustAnchors/{trustAnchorId}",
    responseType: "json",
    validate: validateFederationTrustAnchor,
  }),
  deleteFederationTrustAnchor: Object.freeze({
    operationId: "delete_federation_trust_anchor",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustAnchors/{trustAnchorId}",
    responseType: "empty",
  }),
  listFederationEntityCache: Object.freeze({
    operationId: "list_federation_entity_cache",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/federationEntityCache",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "entityCacheEntries",
        validateFederationEntityCacheEntry,
      ) as ListFederationEntityCacheResponse,
  }),
  refreshFederationEntityCacheEntry: Object.freeze({
    operationId: "refresh_federation_entity_cache_entry",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "federationEntityCache/{entityCacheId}/refresh",
    responseType: "json",
    validate: validateFederationEntityCacheEntry,
  }),
  deleteFederationEntityCacheEntry: Object.freeze({
    operationId: "delete_federation_entity_cache_entry",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/federationEntityCache/{entityCacheId}",
    responseType: "empty",
  }),
  listFederationTrustChains: Object.freeze({
    operationId: "list_federation_trust_chains",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustChains",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(
        value,
        "trustChains",
        validateFederationTrustChainEntry,
      ) as ListFederationTrustChainsResponse,
  }),
  refreshFederationTrustChain: Object.freeze({
    operationId: "refresh_federation_trust_chain",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "federationTrustChains/{trustChainId}/refresh",
    responseType: "json",
    validate: validateFederationTrustChainEntry,
  }),
  deleteFederationTrustChain: Object.freeze({
    operationId: "delete_federation_trust_chain",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/federationTrustChains/{trustChainId}",
    responseType: "empty",
  }),
  listClients: Object.freeze({
    operationId: "list_clients",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/clients",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "clients", validateClient) as ListClientsResponse,
  }),
  createClient: Object.freeze({
    operationId: "create_client",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/clients",
    responseType: "json",
  }),
  getClient: Object.freeze({
    operationId: "get_client",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    responseType: "json",
    validate: validateClient,
  }),
  updateClient: Object.freeze({
    operationId: "update_client",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    responseType: "json",
  }),
  deleteClient: Object.freeze({
    operationId: "delete_client",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}",
    responseType: "empty",
  }),
  listClientSecrets: Object.freeze({
    operationId: "list_client_secrets",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets",
    responseType: "json",
  }),
  issueClientSecret: Object.freeze({
    operationId: "issue_client_secret",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets",
    responseType: "json",
  }),
  revokeClientSecret: Object.freeze({
    operationId: "revoke_client_secret",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/clients/{clientId}/" +
      "clientSecrets/{clientSecretId}/revoke",
    responseType: "json",
  }),
  revokeAllClientSecrets: Object.freeze({
    operationId: "revoke_all_client_secrets",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/clients/{clientId}/clientSecrets/revokeAll",
    responseType: "json",
  }),
  listConfigurationVersions: Object.freeze({
    operationId: "list_configuration_versions",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/configurationVersions",
    responseType: "json",
  }),
  createConfigurationVersion: Object.freeze({
    operationId: "create_configuration_version",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/configurationVersions",
    responseType: "json",
  }),
  getConfigurationVersion: Object.freeze({
    operationId: "get_configuration_version",
    method: "GET",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "configurationVersions/{configurationVersionId}",
    responseType: "json",
  }),
  activateConfigurationVersion: Object.freeze({
    operationId: "activate_configuration_version",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "configurationVersions/{configurationVersionId}/activate",
    responseType: "json",
  }),
  archiveConfigurationVersion: Object.freeze({
    operationId: "archive_configuration_version",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "configurationVersions/{configurationVersionId}/archive",
    responseType: "empty",
  }),
  getPolicies: Object.freeze({
    operationId: "get_policies",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/policies",
    responseType: "json",
    validate: validatePolicyDocument,
  }),
  patchPolicies: Object.freeze({
    operationId: "patch_policies",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/policies",
    responseType: "json",
    validate: validatePolicyPatchResponse,
  }),
  getCurrentKeyStore: Object.freeze({
    operationId: "get_current_key_store",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/keyStores/current",
    responseType: "json",
  }),
  putCurrentKeyStore: Object.freeze({
    operationId: "put_current_key_store",
    method: "PUT",
    path: "/teams/{teamId}/environments/{environmentId}/keyStores/current",
    responseType: "json",
  }),
  listRuntimeKeys: Object.freeze({
    operationId: "list_runtime_keys",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/runtimeKeys",
    responseType: "json",
  }),
  createRuntimeKey: Object.freeze({
    operationId: "create_runtime_key",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/runtimeKeys",
    responseType: "json",
  }),
  activateNextRuntimeKey: Object.freeze({
    operationId: "activate_next_runtime_key",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/runtimeKeys/activateNext",
    responseType: "json",
  }),
  revokeRuntimeKey: Object.freeze({
    operationId: "revoke_runtime_key",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/" +
      "runtimeKeys/{runtimeKeyId}/revoke",
    responseType: "json",
  }),
  listUsers: Object.freeze({
    operationId: "list_users",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users",
    responseType: "json",
    validate: (value: unknown) =>
      validateListResponse(value, "users", validateUser) as ListUsersResponse,
  }),
  createUser: Object.freeze({
    operationId: "create_user",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users",
    responseType: "json",
    validate: validateUser,
  }),
  getUser: Object.freeze({
    operationId: "get_user",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}",
    responseType: "json",
    validate: validateUser,
  }),
  updateUser: Object.freeze({
    operationId: "update_user",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}",
    responseType: "json",
    validate: validateUser,
  }),
  deleteUser: Object.freeze({
    operationId: "delete_user",
    method: "DELETE",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}",
    responseType: "empty",
  }),
  restoreUser: Object.freeze({
    operationId: "restore_user",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/restore",
    responseType: "json",
    validate: validateUser,
  }),
  suspendUser: Object.freeze({
    operationId: "suspend_user",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/suspend",
    responseType: "json",
    validate: validateUser,
  }),
  unsuspendUser: Object.freeze({
    operationId: "unsuspend_user",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/unsuspend",
    responseType: "json",
    validate: validateUser,
  }),
  invalidateUserSessions: Object.freeze({
    operationId: "invalidate_user_sessions",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/invalidateSessions",
    responseType: "empty",
  }),
  revokeUserRefreshTokens: Object.freeze({
    operationId: "revoke_user_refresh_tokens",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/revokeRefreshTokens",
    responseType: "empty",
  }),
  getUserCredentials: Object.freeze({
    operationId: "get_user_credentials",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/credentials",
    responseType: "json",
    validate: validateUserCredentialsResponse,
  }),
  issueActivationToken: Object.freeze({
    operationId: "issue_activation_token",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/activationTokens",
    responseType: "json",
    validate: validateIssueRecoveryTokenResponse,
  }),
  issuePasswordResetToken: Object.freeze({
    operationId: "issue_password_reset_token",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/passwordResetTokens",
    responseType: "json",
    validate: validateIssueRecoveryTokenResponse,
  }),
  revokeUserPasswordCredential: Object.freeze({
    operationId: "revoke_user_password_credential",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/credentials/password/revoke",
    responseType: "json",
    validate: validateUserCredentialsResponse,
  }),
  revokeUserRecoveryToken: Object.freeze({
    operationId: "revoke_user_recovery_token",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/users/{userId}/" +
      "recoveryTokens/{tokenId}/revoke",
    responseType: "json",
    validate: validateUserCredentialsResponse,
  }),
  getUserProfile: Object.freeze({
    operationId: "get_user_profile",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/profile",
    responseType: "json",
    validate: validateUserProfile,
  }),
  updateUserProfile: Object.freeze({
    operationId: "update_user_profile",
    method: "PATCH",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/profile",
    responseType: "json",
    validate: validateUserProfile,
  }),
  listUserSessions: Object.freeze({
    operationId: "list_user_sessions",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/sessions",
    responseType: "json",
    validate: validateListUserSessionsResponse,
  }),
  revokeUserSession: Object.freeze({
    operationId: "revoke_user_session",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/sessions/{sessionId}/revoke",
    responseType: "empty",
  }),
  listUserGrants: Object.freeze({
    operationId: "list_user_grants",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/grants",
    responseType: "json",
    validate: validateListUserGrantsResponse,
  }),
  revokeUserGrant: Object.freeze({
    operationId: "revoke_user_grant",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/grants/{grantId}/revoke",
    responseType: "empty",
  }),
  listUserRefreshTokens: Object.freeze({
    operationId: "list_user_refresh_tokens",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/users/{userId}/refreshTokens",
    responseType: "json",
    validate: validateListUserRefreshTokensResponse,
  }),
  revokeUserRefreshToken: Object.freeze({
    operationId: "revoke_user_refresh_token_inventory",
    method: "POST",
    path:
      "/teams/{teamId}/environments/{environmentId}/users/{userId}/" +
      "refreshTokens/{refreshTokenId}/revoke",
    responseType: "empty",
  }),
  inviteUser: Object.freeze({
    operationId: "invite_user",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/invitations",
    responseType: "json",
    validate: validateInviteUserResponse,
  }),
  importUsersCsv: Object.freeze({
    operationId: "import_users_csv",
    method: "POST",
    path: "/teams/{teamId}/environments/{environmentId}/users/importCsv",
    responseType: "json",
    validate: validateImportUsersCsvResponse,
  }),
  listTeamAuditEvents: Object.freeze({
    operationId: "list_team_audit_events",
    method: "GET",
    path: "/teams/{teamId}/auditEvents",
    responseType: "json",
  }),
  exportTeamAuditEvents: Object.freeze({
    operationId: "export_team_audit_events",
    method: "GET",
    path: "/teams/{teamId}/auditEvents/export",
    responseType: "json",
  }),
  exportTeamAuditEventsCsv: Object.freeze({
    operationId: "export_team_audit_events_csv",
    method: "GET",
    path: "/teams/{teamId}/auditEvents/export",
    responseType: "text",
  }),
  getAuditEvent: Object.freeze({
    operationId: "get_audit_event",
    method: "GET",
    path: "/teams/{teamId}/auditEvents/{auditEventId}",
    responseType: "json",
  }),
  listEnvironmentAuditEvents: Object.freeze({
    operationId: "list_environment_audit_events",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/auditEvents",
    responseType: "json",
  }),
  exportEnvironmentAuditEvents: Object.freeze({
    operationId: "export_environment_audit_events",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/auditEvents/export",
    responseType: "json",
  }),
  exportEnvironmentAuditEventsCsv: Object.freeze({
    operationId: "export_environment_audit_events_csv",
    method: "GET",
    path: "/teams/{teamId}/environments/{environmentId}/auditEvents/export",
    responseType: "text",
  }),
});

function parseCookieHeader(cookieHeader: unknown): Map<string, string> {
  const cookies = new Map<string, string>();
  if (typeof cookieHeader !== "string" || cookieHeader.trim().length === 0) {
    return cookies;
  }
  for (const pair of cookieHeader.split(";")) {
    const trimmed = pair.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const separator = trimmed.indexOf("=");
    if (separator <= 0) {
      continue;
    }
    const name = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim();
    if (name.length > 0) {
      cookies.set(name, value);
    }
  }
  return cookies;
}

function parseSetCookieHeader(setCookieValue: unknown): {
  name: string;
  value: string;
  attributes: Map<string, string | boolean>;
} {
  const [cookiePair = "", ...attributeParts] = requireString(
    setCookieValue,
    "setCookieValue",
  ).split(";");
  const separator = cookiePair.indexOf("=");
  if (separator <= 0) {
    throw new Error(`invalid Set-Cookie header: ${setCookieValue}`);
  }
  const name = cookiePair.slice(0, separator).trim();
  const value = cookiePair.slice(separator + 1).trim();
  const attributes = new Map<string, string | boolean>();
  for (const attributePart of attributeParts) {
    const trimmed = attributePart.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const attributeSeparator = trimmed.indexOf("=");
    if (attributeSeparator === -1) {
      attributes.set(trimmed.toLowerCase(), true);
      continue;
    }
    attributes.set(
      trimmed.slice(0, attributeSeparator).trim().toLowerCase(),
      trimmed.slice(attributeSeparator + 1).trim(),
    );
  }
  return { name, value, attributes };
}

function extractSetCookieHeaders(headersOrResponse: unknown): string[] {
  const responseLike = headersOrResponse as { headers?: unknown } | null | undefined;
  const headers = (responseLike?.headers ?? headersOrResponse) as {
    getSetCookie?: () => string[];
    get?: (name: string) => string | null;
  } | null | undefined;
  if (!headers) {
    return [];
  }
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }
  if (typeof headers.get === "function") {
    const headerValue = headers.get("set-cookie");
    return headerValue ? [headerValue] : [];
  }
  return [];
}

export function readCookieValue(
  cookieSource: string,
  name: string = DEFAULT_CSRF_COOKIE_NAME,
): string | null {
  const cookies = parseCookieHeader(cookieSource);
  return cookies.get(name) ?? null;
}

export function createDocumentCookieReader(
  { documentLike = globalThis.document }: CreateDocumentCookieReaderOptions = {},
): () => string {
  return () => documentLike?.cookie ?? "";
}

export function createInMemoryCookieJar(
  { initialCookies = null }: CreateInMemoryCookieJarOptions = {},
): ManagementCookieJar {
  const cookies = new Map<string, string>();
  if (typeof initialCookies === "string") {
    for (const [name, value] of parseCookieHeader(initialCookies)) {
      cookies.set(name, value);
    }
  } else if (
    initialCookies &&
    typeof initialCookies === "object" &&
    !Array.isArray(initialCookies)
  ) {
    for (const [name, value] of Object.entries(initialCookies)) {
      cookies.set(requireString(name, "cookie name"), requireString(value, `cookie ${name}`));
    }
  } else if (initialCookies != null) {
    throw new TypeError("initialCookies must be a cookie string or plain object");
  }

  const cookieJar: ManagementCookieJar = {
    get(name: string) {
      return cookies.get(requireString(name, "cookie name")) ?? null;
    },
    set(name: string, value: string) {
      cookies.set(requireString(name, "cookie name"), requireString(value, `cookie ${name}`));
    },
    delete(name: string) {
      cookies.delete(requireString(name, "cookie name"));
    },
    clear() {
      cookies.clear();
    },
    applySetCookieHeaders(headersOrResponse: unknown) {
      for (const setCookieValue of extractSetCookieHeaders(headersOrResponse)) {
        const parsed = parseSetCookieHeader(setCookieValue);
        if (parsed.value.length === 0 || parsed.attributes.get("max-age") === "0") {
          cookies.delete(parsed.name);
          continue;
        }
        cookies.set(parsed.name, parsed.value);
      }
    },
    toHeader() {
      if (cookies.size === 0) {
        return null;
      }
      return Array.from(cookies.entries())
        .map(([name, value]) => `${name}=${value}`)
        .join("; ");
    },
    toJSON() {
      return Object.fromEntries(cookies.entries());
    },
    clone() {
      return createInMemoryCookieJar({ initialCookies: Object.fromEntries(cookies.entries()) });
    },
  };
  return cookieJar;
}

function requireCookieJar(cookieJar: unknown): ManagementCookieJar {
  if (!cookieJar || typeof cookieJar !== "object") {
    throw new TypeError("cookieJar must be an object");
  }
  const candidate = cookieJar as Record<string, unknown>;
  for (const methodName of [
    "get",
    "set",
    "delete",
    "clear",
    "applySetCookieHeaders",
    "toHeader",
    "clone",
  ]) {
    if (typeof candidate[methodName] !== "function") {
      throw new TypeError(`cookieJar.${methodName}() is required`);
    }
  }
  return cookieJar as ManagementCookieJar;
}

export function createInMemoryManagementSessionStore({
  origin = null,
  teamId = null,
  csrfToken = null,
  csrfCookieName = DEFAULT_CSRF_COOKIE_NAME,
  credentials = DEFAULT_CREDENTIALS_MODE,
  cookieJar = createInMemoryCookieJar(),
  cookieReader = null,
}: CreateInMemoryManagementSessionStoreOptions = {}): ManagementSessionStore {
  let state: {
    origin: string | null;
    teamId: string | null;
    csrfToken: string | null;
    csrfCookieName: string;
    credentials: string;
    cookieJar: ManagementCookieJar;
    cookieReader: CookieReader;
  } = {
    origin: normalizeOptionalString(origin, "origin"),
    teamId: normalizeOptionalString(teamId, "teamId"),
    csrfToken: normalizeOptionalString(csrfToken, "csrfToken"),
    csrfCookieName: requireString(csrfCookieName, "csrfCookieName"),
    credentials: requireString(credentials, "credentials"),
    cookieJar: requireCookieJar(cookieJar),
    cookieReader:
      cookieReader == null
        ? null
        : typeof cookieReader === "function"
          ? cookieReader
          : null,
  };
  if (cookieReader != null && typeof cookieReader !== "function") {
    throw new TypeError("cookieReader must be a function when provided");
  }

  function syncCsrfToken(): string | null {
    const fromCookieJar = state.cookieJar.get(state.csrfCookieName);
    if (fromCookieJar) {
      state.csrfToken = fromCookieJar;
      return fromCookieJar;
    }
    if (state.cookieReader) {
      const cookieValue = readCookieValue(state.cookieReader(), state.csrfCookieName);
      if (cookieValue) {
        state.cookieJar.set(state.csrfCookieName, cookieValue);
        state.csrfToken = cookieValue;
        return cookieValue;
      }
    }
    return state.csrfToken;
  }

  function getState(): ManagementSessionState {
    return Object.freeze({
      origin: state.origin,
      teamId: state.teamId,
      csrfToken: state.csrfToken,
      csrfCookieName: state.csrfCookieName,
      credentials: state.credentials,
      cookieJar: state.cookieJar,
    });
  }

  const sessionStoreImpl: ManagementSessionStore = {
    getState,
    setOrigin(nextOrigin: string | null) {
      state.origin = normalizeOptionalString(nextOrigin, "origin");
      return getState();
    },
    setTeamId(nextTeamId: string | null) {
      state.teamId = normalizeOptionalString(nextTeamId, "teamId");
      return getState();
    },
    setCsrfToken(nextCsrfToken: string | null) {
      state.csrfToken = normalizeOptionalString(nextCsrfToken, "csrfToken");
      if (state.csrfToken) {
        state.cookieJar.set(state.csrfCookieName, state.csrfToken);
      } else {
        state.cookieJar.delete(state.csrfCookieName);
      }
      return getState();
    },
    syncCsrfToken,
    captureResponse(response: unknown) {
      state.cookieJar.applySetCookieHeaders(response);
      syncCsrfToken();
      return getState();
    },
    clearSession() {
      state.cookieJar.delete(DEFAULT_SESSION_COOKIE_NAME);
      return getState();
    },
    clone(overrides: SessionStoreOverrides = {}) {
      const nextState = {
        origin: overrides.origin ?? state.origin,
        teamId: overrides.teamId ?? state.teamId,
        csrfToken: overrides.csrfToken ?? state.csrfToken,
        csrfCookieName: overrides.csrfCookieName ?? state.csrfCookieName,
        credentials: overrides.credentials ?? state.credentials,
        cookieJar: overrides.cookieJar ?? state.cookieJar.clone(),
        cookieReader: overrides.cookieReader ?? state.cookieReader,
      };
      return createInMemoryManagementSessionStore(nextState);
    },
  };
  return sessionStoreImpl;
}

export class ManagementApiError extends Error {
  status: number;
  operationId: string;
  errorCode: string | null;
  requestId: string | null;
  details: unknown;
  responseBody: unknown;
  error: ErrorResponse | undefined;
  raw: unknown;

  constructor(message: string, details: ManagementApiErrorDetails) {
    super(message);
    this.name = "ManagementApiError";
    this.status = details.status;
    this.operationId = details.operationId;
    this.errorCode = details.errorCode ?? null;
    this.requestId = details.requestId ?? null;
    this.details = details.details ?? null;
    this.responseBody = details.responseBody ?? null;
    this.error = details.errorCode || details.requestId || details.details
      ? Object.freeze({
          errorCode: details.errorCode ?? "management_request_failed",
          message,
          requestId: details.requestId ?? null,
          details: details.details ?? null,
        })
      : undefined;
    this.raw = details.responseBody ?? null;
  }
}

function normalizeFetchImpl(fetchImpl: typeof fetch | null | undefined): typeof fetch {
  const resolved = fetchImpl ?? (globalThis.fetch?.bind(globalThis) as typeof fetch | undefined);
  if (typeof resolved !== "function") {
    throw new TypeError("fetchImpl is required");
  }
  return resolved;
}

function buildOperationPath(
  pathTemplate: string,
  pathParams: PlainObject,
  defaultTeamId: string | null,
): string {
  return pathTemplate.replace(/\{([^}]+)\}/g, (_: string, parameterName: string) => {
    if (parameterName === "teamId" && pathParams.teamId == null && defaultTeamId != null) {
      return encodeURIComponent(requireString(defaultTeamId, "defaultTeamId"));
    }
    return encodeURIComponent(requireString(pathParams[parameterName], parameterName));
  });
}

function applyQuery(url: URL, query: QueryRecord = {}): void {
  const queryObject = requirePlainObject(query, "query") as QueryRecord;
  for (const [key, rawValue] of Object.entries(queryObject)) {
    if (rawValue == null) {
      continue;
    }
    const values = Array.isArray(rawValue) ? rawValue : [rawValue];
    for (const value of values) {
      if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
        url.searchParams.append(key, String(value));
      } else {
        throw new TypeError(`query.${key} must contain only string, number, or boolean values`);
      }
    }
  }
}

export function buildManagementOperationUrl({
  baseUrl,
  operationName,
  pathParams = {},
  query = {},
  defaultTeamId = null,
  basePath = DEFAULT_BASE_PATH,
}: BuildManagementOperationUrlOptions): string {
  const operation = MANAGEMENT_OPERATIONS[requireString(operationName, "operationName")];
  if (!operation) {
    throw new Error(`unknown management operation: ${operationName}`);
  }
  const normalizedBaseUrl = new URL(requireString(baseUrl, "baseUrl"));
  const normalizedBasePath = requireString(basePath, "basePath").replace(/\/$/, "");
  const operationPath = buildOperationPath(
    operation.path,
    requirePlainObject(pathParams, "pathParams"),
    defaultTeamId,
  );
  normalizedBaseUrl.pathname =
    `${normalizedBaseUrl.pathname.replace(/\/$/, "")}${normalizedBasePath}${operationPath}`;
  applyQuery(normalizedBaseUrl, query);
  return normalizedBaseUrl.toString();
}

async function parseManagementSuccessResponse(
  response: ResponseLike,
  operation: ManagementOperation,
): Promise<unknown> {
  if (operation.responseType === "empty") {
    return null;
  }
  if (operation.responseType === "text") {
    return response.text();
  }
  const parsed = await response.json();
  return operation.validate ? operation.validate(parsed) : parsed;
}

async function buildManagementError(
  response: ResponseLike,
  operationId: string,
): Promise<ManagementApiError> {
  let responseBody = null;
  try {
    const contentType = response.headers?.get?.("content-type") ?? "";
    responseBody = contentType.includes("application/json")
      ? validateErrorResponse(await response.json())
      : await response.text();
  } catch (_error) {
    responseBody = null;
  }
  const errorMessage =
    typeof responseBody === "object" && responseBody && "message" in responseBody
      ? responseBody.message
      : `management request failed with status ${response.status}`;
  return new ManagementApiError(errorMessage, {
    status: response.status,
    operationId,
    errorCode: typeof responseBody === "object" && responseBody ? responseBody.errorCode : null,
    requestId:
      (typeof responseBody === "object" && responseBody ? responseBody.requestId : null)
      ?? response.headers?.get?.("x-request-id")
      ?? null,
    details: typeof responseBody === "object" && responseBody ? responseBody.details : null,
    responseBody,
  });
}

export function createManagementClient({
  baseUrl,
  fetchImpl = null,
  sessionStore = createInMemoryManagementSessionStore(),
  defaultTeamId = null,
  origin = null,
  basePath = DEFAULT_BASE_PATH,
}: CreateManagementClientOptions): ManagementClient {
  const resolvedBaseUrl = requireString(baseUrl, "baseUrl");
  const resolvedFetch = normalizeFetchImpl(fetchImpl);
  const store = sessionStore == null ? null : sessionStore;
  if (store != null && typeof store.getState !== "function") {
    throw new TypeError("sessionStore must expose getState()");
  }
  const fallbackOrigin = normalizeOptionalString(origin, "origin");

  const requestOperation: ManagementClient["requestOperation"] = async <T = unknown>(
    operationName: string,
    {
      pathParams = {},
      query = {},
      body = undefined,
      headers = undefined,
    }: RequestOperationOptions = {},
  ): Promise<T> => {
    const operation = MANAGEMENT_OPERATIONS[requireString(operationName, "operationName")];
    if (!operation) {
      throw new Error(`unknown management operation: ${operationName}`);
    }
    const defaultTeam = defaultTeamId ?? store?.getState().teamId ?? null;
    const requestUrl = buildManagementOperationUrl({
      baseUrl: resolvedBaseUrl,
      operationName,
      pathParams,
      query,
      defaultTeamId: defaultTeam,
      basePath,
    });

    const requestHeaders = new Headers(headers ?? {});
    if (body !== undefined && !requestHeaders.has("content-type")) {
      requestHeaders.set("content-type", "application/json");
    }

    if (store) {
      const state = store.getState();
      const cookieHeader = state.cookieJar.toHeader();
      if (
        typeof globalThis.document === "undefined" &&
        cookieHeader &&
        !requestHeaders.has("cookie")
      ) {
        requestHeaders.set("cookie", cookieHeader);
      }
      if (WRITE_METHODS.has(operation.method)) {
        const effectiveOrigin = fallbackOrigin ?? state.origin;
        if (!effectiveOrigin) {
          throw new Error(`origin is required for management write operation ${operationName}`);
        }
        if (!requestHeaders.has("origin")) {
          requestHeaders.set("origin", effectiveOrigin);
        }
        let csrfToken = state.csrfToken ?? store.syncCsrfToken?.();
        if (!csrfToken) {
          await primeCsrf();
          csrfToken = store.getState().csrfToken ?? store.syncCsrfToken?.();
        }
        if (!csrfToken) {
          throw new Error(`csrf token is required for management write operation ${operationName}`);
        }
        if (!requestHeaders.has("x-csrf-token")) {
          requestHeaders.set("x-csrf-token", csrfToken);
        }
      }
    }

    const response = await resolvedFetch(requestUrl, {
      method: operation.method,
      headers: requestHeaders,
      credentials: (store?.getState().credentials ??
        DEFAULT_CREDENTIALS_MODE) as RequestCredentials,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    store?.captureResponse?.(response);
    if (!response.ok) {
      throw await buildManagementError(response, operation.operationId);
    }
    return (await parseManagementSuccessResponse(response as ResponseLike, operation)) as T;
  };

  const primeCsrf: ManagementClient["primeCsrf"] = async () => {
    if (!store) {
      throw new Error("sessionStore is required to prime management CSRF state");
    }
    await requestOperation("systemHealth");
    const csrfToken = store.getState().csrfToken ?? store.syncCsrfToken?.();
    if (!csrfToken) {
      throw new Error("management CSRF token was not available after priming request");
    }
    return csrfToken;
  };

  const createAuthenticationSession: ManagementClient["createAuthenticationSession"] = async ({
    email,
    password,
  }) => {
    requireString(email, "email");
    requireString(password, "password");
    if (store) {
      const csrfToken = store.getState().csrfToken ?? store.syncCsrfToken?.();
      if (!csrfToken) {
        await primeCsrf();
      }
    }
    await requestOperation("createAuthenticationSession", {
      body: { email, password },
    });
    return store?.getState() ?? null;
  };

  const deleteCurrentAuthenticationSession: ManagementClient[
    "deleteCurrentAuthenticationSession"
  ] = async () => {
    await requestOperation("deleteCurrentAuthenticationSession");
    store?.clearSession?.();
    return null;
  };

  const client: ManagementClient = {
    metadata: MANAGEMENT_OPENAPI_METADATA,
    operations: MANAGEMENT_OPERATIONS,
    sessionStore: store,
    requestOperation,
    primeCsrf,
    withTeamId(teamId: MethodInput<"withTeamId">) {
      return createManagementClient({
        baseUrl: resolvedBaseUrl,
        fetchImpl: resolvedFetch,
        sessionStore: store,
        defaultTeamId: requireString(teamId, "teamId"),
        origin: fallbackOrigin,
        basePath,
      });
    },
    systemHealth() {
      return requestOperation("systemHealth");
    },
    systemVersion() {
      return requestOperation("systemVersion");
    },
    bootstrapOwner(input: MethodInput<"bootstrapOwner">) {
      return requestOperation("bootstrapOwner", {
        body: requirePlainObject(input, "bootstrapOwner"),
      });
    },
    createAuthenticationSession,
    deleteCurrentAuthenticationSession,
    listTeams(query: OptionalMethodInput<"listTeams"> = {}) {
      return requestOperation("listTeams", { query });
    },
    createTeam(input: MethodInput<"createTeam">) {
      return requestOperation("createTeam", {
        body: requirePlainObject(input, "createTeam"),
      });
    },
    getTeam({ teamId }: MethodInput<"getTeam">) {
      return requestOperation("getTeam", {
        pathParams: { teamId },
      });
    },
    updateTeam({ teamId, ...input }: MethodInput<"updateTeam">) {
      return requestOperation("updateTeam", {
        pathParams: { teamId },
        body: requirePlainObject(input, "updateTeam"),
      });
    },
    deleteTeam({ teamId }: MethodInput<"deleteTeam">) {
      return requestOperation("deleteTeam", {
        pathParams: { teamId },
      });
    },
    listTenants({
      teamId = null,
      pageSize = null,
      pageToken = null,
    }: OptionalMethodInput<"listTenants"> = {}) {
      return requestOperation("listTenants", {
        pathParams: { teamId },
        query: { pageSize, pageToken },
      });
    },
    createTenant({ teamId = null, ...input }: MethodInput<"createTenant">) {
      return requestOperation("createTenant", {
        pathParams: { teamId },
        body: requirePlainObject(input, "createTenant"),
      });
    },
    getTenant({ teamId = null, tenantId }: MethodInput<"getTenant">) {
      return requestOperation("getTenant", {
        pathParams: { teamId, tenantId },
      });
    },
    updateTenant({ teamId = null, tenantId, ...input }: MethodInput<"updateTenant">) {
      return requestOperation("updateTenant", {
        pathParams: { teamId, tenantId },
        body: requirePlainObject(input, "updateTenant"),
      });
    },
    deleteTenant({ teamId = null, tenantId }: MethodInput<"deleteTenant">) {
      return requestOperation("deleteTenant", {
        pathParams: { teamId, tenantId },
      });
    },
    listEnvironments({
      teamId = null,
      tenantId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listEnvironments">) {
      return requestOperation("listEnvironments", {
        pathParams: { teamId, tenantId },
        query: { pageSize, pageToken },
      });
    },
    createEnvironment({ teamId = null, tenantId, ...input }: MethodInput<"createEnvironment">) {
      return requestOperation("createEnvironment", {
        pathParams: { teamId, tenantId },
        body: requirePlainObject(input, "createEnvironment"),
      });
    },
    listOAuthProfiles({
      teamId = null,
      environmentId,
      configurationVersionId = null,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listOAuthProfiles">) {
      return requestOperation("listOAuthProfiles", {
        pathParams: { teamId, environmentId },
        query: { configurationVersionId, pageSize, pageToken },
      });
    },
    createOAuthProfile({
      teamId = null,
      environmentId,
      configurationVersionId = null,
      ...input
    }: MethodInput<"createOAuthProfile">) {
      return requestOperation("createOAuthProfile", {
        pathParams: { teamId, environmentId },
        query: { configurationVersionId },
        body: requirePlainObject(input, "createOAuthProfile"),
      });
    },
    getOAuthProfile({
      teamId = null,
      environmentId,
      oauthProfileId,
    }: MethodInput<"getOAuthProfile">) {
      return requestOperation("getOAuthProfile", {
        pathParams: { teamId, environmentId, oauthProfileId },
      });
    },
    updateOAuthProfile({
      teamId = null,
      environmentId,
      oauthProfileId,
      ...input
    }: MethodInput<"updateOAuthProfile">) {
      return requestOperation("updateOAuthProfile", {
        pathParams: { teamId, environmentId, oauthProfileId },
        body: requirePlainObject(input, "updateOAuthProfile"),
      });
    },
    deleteOAuthProfile({
      teamId = null,
      environmentId,
      oauthProfileId,
    }: MethodInput<"deleteOAuthProfile">) {
      return requestOperation("deleteOAuthProfile", {
        pathParams: { teamId, environmentId, oauthProfileId },
      });
    },
    listConnections({
      teamId = null,
      environmentId,
      configurationVersionId = null,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listConnections">) {
      return requestOperation("listConnections", {
        pathParams: { teamId, environmentId },
        query: { configurationVersionId, pageSize, pageToken },
      });
    },
    createConnection({
      teamId = null,
      environmentId,
      configurationVersionId = null,
      ...input
    }: MethodInput<"createConnection">) {
      return requestOperation("createConnection", {
        pathParams: { teamId, environmentId },
        query: { configurationVersionId },
        body: requirePlainObject(input, "createConnection"),
      });
    },
    getConnection({ teamId = null, environmentId, connectionId }: MethodInput<"getConnection">) {
      return requestOperation("getConnection", {
        pathParams: { teamId, environmentId, connectionId },
      });
    },
    updateConnection({
      teamId = null,
      environmentId,
      connectionId,
      ...input
    }: MethodInput<"updateConnection">) {
      return requestOperation("updateConnection", {
        pathParams: { teamId, environmentId, connectionId },
        body: requirePlainObject(input, "updateConnection"),
      });
    },
    deleteConnection({
      teamId = null,
      environmentId,
      connectionId,
    }: MethodInput<"deleteConnection">) {
      return requestOperation("deleteConnection", {
        pathParams: { teamId, environmentId, connectionId },
      });
    },
    listAccountLinks({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
      upstreamIssuer = null,
      upstreamSubject = null,
      endUserSubject = null,
      endUserEmail = null,
      connectionIdentifier = null,
    }: MethodInput<"listAccountLinks">) {
      return requestOperation("listAccountLinks", {
        pathParams: { teamId, environmentId },
        query: {
          pageSize,
          pageToken,
          upstreamIssuer,
          upstreamSubject,
          endUserSubject,
          endUserEmail,
          connectionIdentifier,
        },
      });
    },
    createAccountLink({
      teamId = null,
      environmentId,
      connectionId,
      upstreamSubject,
      endUserId,
    }: MethodInput<"createAccountLink">) {
      return requestOperation("createAccountLink", {
        pathParams: { teamId, environmentId },
        body: { connectionId, upstreamSubject, endUserId },
      });
    },
    previewAccountLinkConflict({
      teamId = null,
      environmentId,
      connectionId,
      upstreamSubject,
    }: MethodInput<"previewAccountLinkConflict">) {
      return requestOperation("previewAccountLinkConflict", {
        pathParams: { teamId, environmentId },
        body: { connectionId, upstreamSubject },
      });
    },
    resolveAccountLinkConflict({
      teamId = null,
      environmentId,
      connectionId,
      upstreamSubject,
      endUserId,
      upstreamRefreshTokenHandling = null,
      lowConfidenceHandling = null,
      inactiveTargetHandling = null,
    }: MethodInput<"resolveAccountLinkConflict">) {
      return requestOperation("resolveAccountLinkConflict", {
        pathParams: { teamId, environmentId },
        body: {
          connectionId,
          upstreamSubject,
          endUserId,
          upstreamRefreshTokenHandling,
          lowConfidenceHandling,
          inactiveTargetHandling,
        },
      });
    },
    deleteAccountLink({
      teamId = null,
      environmentId,
      accountLinkId,
    }: MethodInput<"deleteAccountLink">) {
      return requestOperation("deleteAccountLink", {
        pathParams: { teamId, environmentId, accountLinkId },
      });
    },
    bulkRelinkAccountLinks({
      teamId = null,
      environmentId,
      accountLinkIds,
      endUserId,
      upstreamRefreshTokenHandling = null,
      inactiveTargetHandling = null,
    }: MethodInput<"bulkRelinkAccountLinks">) {
      return requestOperation("bulkRelinkAccountLinks", {
        pathParams: { teamId, environmentId },
        body: {
          accountLinkIds,
          endUserId,
          upstreamRefreshTokenHandling,
          inactiveTargetHandling,
        },
      });
    },
    relinkAccountLink({
      teamId = null,
      environmentId,
      accountLinkId,
      endUserId,
      upstreamRefreshTokenHandling = null,
      inactiveTargetHandling = null,
    }: MethodInput<"relinkAccountLink">) {
      return requestOperation("relinkAccountLink", {
        pathParams: { teamId, environmentId, accountLinkId },
        body: { endUserId, upstreamRefreshTokenHandling, inactiveTargetHandling },
      });
    },
    listFederationLogoutRecoveryIncidents({
      teamId = null,
      environmentId,
      connectionId = null,
      status = null,
      recoveryPolicy = null,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listFederationLogoutRecoveryIncidents">) {
      return requestOperation("listFederationLogoutRecoveryIncidents", {
        pathParams: { teamId, environmentId },
        query: { connectionId, status, recoveryPolicy, pageSize, pageToken },
      });
    },
    getFederationLogoutRecoveryIncident({
      teamId = null,
      environmentId,
      incidentId,
    }: MethodInput<"getFederationLogoutRecoveryIncident">) {
      return requestOperation("getFederationLogoutRecoveryIncident", {
        pathParams: { teamId, environmentId, incidentId },
      });
    },
    clearFederationLogoutRecoveryIncident({
      teamId = null,
      environmentId,
      incidentId,
      reason,
    }: MethodInput<"clearFederationLogoutRecoveryIncident">) {
      return requestOperation("clearFederationLogoutRecoveryIncident", {
        pathParams: { teamId, environmentId, incidentId },
        body: { reason },
      });
    },
    listFederationTrustAnchors({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listFederationTrustAnchors">) {
      return requestOperation("listFederationTrustAnchors", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken },
      });
    },
    createFederationTrustAnchor({
      teamId = null,
      environmentId,
      entityId,
      jwks,
      metadataPolicy,
    }: MethodInput<"createFederationTrustAnchor">) {
      return requestOperation("createFederationTrustAnchor", {
        pathParams: { teamId, environmentId },
        body: { entityId, jwks, metadataPolicy },
      });
    },
    getFederationTrustAnchor({
      teamId = null,
      environmentId,
      trustAnchorId,
    }: MethodInput<"getFederationTrustAnchor">) {
      return requestOperation("getFederationTrustAnchor", {
        pathParams: { teamId, environmentId, trustAnchorId },
      });
    },
    deleteFederationTrustAnchor({
      teamId = null,
      environmentId,
      trustAnchorId,
    }: MethodInput<"deleteFederationTrustAnchor">) {
      return requestOperation("deleteFederationTrustAnchor", {
        pathParams: { teamId, environmentId, trustAnchorId },
      });
    },
    listFederationEntityCache({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listFederationEntityCache">) {
      return requestOperation("listFederationEntityCache", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken },
      });
    },
    refreshFederationEntityCacheEntry({
      teamId = null,
      environmentId,
      entityCacheId,
    }: MethodInput<"refreshFederationEntityCacheEntry">) {
      return requestOperation("refreshFederationEntityCacheEntry", {
        pathParams: { teamId, environmentId, entityCacheId },
        body: {},
      });
    },
    deleteFederationEntityCacheEntry({
      teamId = null,
      environmentId,
      entityCacheId,
    }: MethodInput<"deleteFederationEntityCacheEntry">) {
      return requestOperation("deleteFederationEntityCacheEntry", {
        pathParams: { teamId, environmentId, entityCacheId },
        body: {},
      });
    },
    listFederationTrustChains({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listFederationTrustChains">) {
      return requestOperation("listFederationTrustChains", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken },
      });
    },
    refreshFederationTrustChain({
      teamId = null,
      environmentId,
      trustChainId,
    }: MethodInput<"refreshFederationTrustChain">) {
      return requestOperation("refreshFederationTrustChain", {
        pathParams: { teamId, environmentId, trustChainId },
        body: {},
      });
    },
    deleteFederationTrustChain({
      teamId = null,
      environmentId,
      trustChainId,
    }: MethodInput<"deleteFederationTrustChain">) {
      return requestOperation("deleteFederationTrustChain", {
        pathParams: { teamId, environmentId, trustChainId },
        body: {},
      });
    },
    getEnvironment({ teamId = null, environmentId }: MethodInput<"getEnvironment">) {
      return requestOperation("getEnvironment", {
        pathParams: { teamId, environmentId },
      });
    },
    updateEnvironment({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"updateEnvironment">) {
      return requestOperation("updateEnvironment", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "updateEnvironment"),
      });
    },
    deleteEnvironment({ teamId = null, environmentId }: MethodInput<"deleteEnvironment">) {
      return requestOperation("deleteEnvironment", {
        pathParams: { teamId, environmentId },
      });
    },
    getDcrBearerTokenStatus({
      teamId = null,
      environmentId,
    }: MethodInput<"getDcrBearerTokenStatus">) {
      return requestOperation("getDcrBearerTokenStatus", {
        pathParams: { teamId, environmentId },
      });
    },
    putDcrBearerToken({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"putDcrBearerToken">) {
      return requestOperation("putDcrBearerToken", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "putDcrBearerToken"),
      });
    },
    deleteDcrBearerToken({
      teamId = null,
      environmentId,
    }: MethodInput<"deleteDcrBearerToken">) {
      return requestOperation("deleteDcrBearerToken", {
        pathParams: { teamId, environmentId },
      });
    },
    listClients({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listClients">) {
      return requestOperation("listClients", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken },
      });
    },
    createClient({ teamId = null, environmentId, ...input }: MethodInput<"createClient">) {
      return requestOperation("createClient", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "createClient"),
      });
    },
    getClient({ teamId = null, environmentId, clientId }: MethodInput<"getClient">) {
      return requestOperation("getClient", {
        pathParams: { teamId, environmentId, clientId },
      });
    },
    updateClient({
      teamId = null,
      environmentId,
      clientId,
      ...input
    }: MethodInput<"updateClient">) {
      return requestOperation("updateClient", {
        pathParams: { teamId, environmentId, clientId },
        body: requirePlainObject(input, "updateClient"),
      });
    },
    deleteClient({
      teamId = null,
      environmentId,
      clientId,
      ...input
    }: MethodInput<"deleteClient">) {
      return requestOperation("deleteClient", {
        pathParams: { teamId, environmentId, clientId },
        body: requirePlainObject(input, "deleteClient"),
      });
    },
    listClientSecrets({
      teamId = null,
      environmentId,
      clientId,
    }: MethodInput<"listClientSecrets">) {
      return requestOperation("listClientSecrets", {
        pathParams: { teamId, environmentId, clientId },
      });
    },
    issueClientSecret({
      teamId = null,
      environmentId,
      clientId,
      ...input
    }: MethodInput<"issueClientSecret">) {
      return requestOperation("issueClientSecret", {
        pathParams: { teamId, environmentId, clientId },
        body: requirePlainObject(input, "issueClientSecret"),
      });
    },
    revokeClientSecret({
      teamId = null,
      environmentId,
      clientId,
      clientSecretId,
      ...input
    }: MethodInput<"revokeClientSecret">) {
      return requestOperation("revokeClientSecret", {
        pathParams: { teamId, environmentId, clientId, clientSecretId },
        body: requirePlainObject(input, "revokeClientSecret"),
      });
    },
    revokeAllClientSecrets({
      teamId = null,
      environmentId,
      clientId,
      ...input
    }: MethodInput<"revokeAllClientSecrets">) {
      return requestOperation("revokeAllClientSecrets", {
        pathParams: { teamId, environmentId, clientId },
        body: requirePlainObject(input, "revokeAllClientSecrets"),
      });
    },
    listConfigurationVersions({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
    }: MethodInput<"listConfigurationVersions">) {
      return requestOperation("listConfigurationVersions", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken },
      });
    },
    createConfigurationVersion({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"createConfigurationVersion">) {
      return requestOperation("createConfigurationVersion", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "createConfigurationVersion"),
      });
    },
    getConfigurationVersion({
      teamId = null,
      environmentId,
      configurationVersionId,
    }: MethodInput<"getConfigurationVersion">) {
      return requestOperation("getConfigurationVersion", {
        pathParams: { teamId, environmentId, configurationVersionId },
      });
    },
    activateConfigurationVersion({
      teamId = null,
      environmentId,
      configurationVersionId,
      ...input
    }: MethodInput<"activateConfigurationVersion">) {
      return requestOperation("activateConfigurationVersion", {
        pathParams: { teamId, environmentId, configurationVersionId },
        body: requirePlainObject(input, "activateConfigurationVersion"),
      });
    },
    archiveConfigurationVersion({
      teamId = null,
      environmentId,
      configurationVersionId,
      ...input
    }: MethodInput<"archiveConfigurationVersion">) {
      return requestOperation("archiveConfigurationVersion", {
        pathParams: { teamId, environmentId, configurationVersionId },
        ...(Object.keys(input).length > 0
          ? { body: requirePlainObject(input, "archiveConfigurationVersion") }
          : {}),
      });
    },
    getPolicies({ teamId = null, environmentId }: MethodInput<"getPolicies">) {
      return requestOperation("getPolicies", {
        pathParams: { teamId, environmentId },
      });
    },
    patchPolicies({ teamId = null, environmentId, ...input }: MethodInput<"patchPolicies">) {
      return requestOperation("patchPolicies", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "patchPolicies"),
      });
    },
    getPolicy({ teamId = null, environmentId }: MethodInput<"getPolicy">) {
      return requestOperation("getPolicies", {
        pathParams: { teamId, environmentId },
      });
    },
    patchPolicy({ teamId = null, environmentId, ...input }: MethodInput<"patchPolicy">) {
      return requestOperation("patchPolicies", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "patchPolicy"),
      });
    },
    getCurrentKeyStore({ teamId = null, environmentId }: MethodInput<"getCurrentKeyStore">) {
      return requestOperation("getCurrentKeyStore", {
        pathParams: { teamId, environmentId },
      });
    },
    putCurrentKeyStore({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"putCurrentKeyStore">) {
      return requestOperation("putCurrentKeyStore", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "putCurrentKeyStore"),
      });
    },
    getKeyStoreCurrent({ teamId = null, environmentId }: MethodInput<"getKeyStoreCurrent">) {
      return requestOperation("getCurrentKeyStore", {
        pathParams: { teamId, environmentId },
      });
    },
    updateKeyStoreCurrent({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"updateKeyStoreCurrent">) {
      return requestOperation("putCurrentKeyStore", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "updateKeyStoreCurrent"),
      });
    },
    listRuntimeKeys({ teamId = null, environmentId }: MethodInput<"listRuntimeKeys">) {
      return requestOperation("listRuntimeKeys", {
        pathParams: { teamId, environmentId },
      });
    },
    createRuntimeKey({ teamId = null, environmentId, ...input }: MethodInput<"createRuntimeKey">) {
      return requestOperation("createRuntimeKey", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "createRuntimeKey"),
      });
    },
    activateNextRuntimeKey({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"activateNextRuntimeKey">) {
      return requestOperation("activateNextRuntimeKey", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "activateNextRuntimeKey"),
      });
    },
    revokeRuntimeKey({
      teamId = null,
      environmentId,
      runtimeKeyId,
      ...input
    }: MethodInput<"revokeRuntimeKey">) {
      return requestOperation("revokeRuntimeKey", {
        pathParams: { teamId, environmentId, runtimeKeyId },
        body: requirePlainObject(input, "revokeRuntimeKey"),
      });
    },
    listUsers({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
      includeDeleted = null,
    }: MethodInput<"listUsers">) {
      return requestOperation("listUsers", {
        pathParams: { teamId, environmentId },
        query: { pageSize, pageToken, includeDeleted },
      });
    },
    createUser({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"createUser">) {
      return requestOperation("createUser", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "createUser"),
      });
    },
    getUser({ teamId = null, environmentId, userId }: MethodInput<"getUser">) {
      return requestOperation("getUser", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    updateUser({
      teamId = null,
      environmentId,
      userId,
      ...input
    }: MethodInput<"updateUser">) {
      return requestOperation("updateUser", {
        pathParams: { teamId, environmentId, userId },
        body: requirePlainObject(input, "updateUser"),
      });
    },
    deleteUser({ teamId = null, environmentId, userId }: MethodInput<"deleteUser">) {
      return requestOperation("deleteUser", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    restoreUser({ teamId = null, environmentId, userId }: MethodInput<"restoreUser">) {
      return requestOperation("restoreUser", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    suspendUser({ teamId = null, environmentId, userId }: MethodInput<"suspendUser">) {
      return requestOperation("suspendUser", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    unsuspendUser({ teamId = null, environmentId, userId }: MethodInput<"unsuspendUser">) {
      return requestOperation("unsuspendUser", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    invalidateUserSessions({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"invalidateUserSessions">) {
      return requestOperation("invalidateUserSessions", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    revokeUserRefreshTokens({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"revokeUserRefreshTokens">) {
      return requestOperation("revokeUserRefreshTokens", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    getUserCredentials({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"getUserCredentials">) {
      return requestOperation("getUserCredentials", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    issueActivationToken({
      teamId = null,
      environmentId,
      userId,
      ...input
    }: MethodInput<"issueActivationToken">) {
      return requestOperation("issueActivationToken", {
        pathParams: { teamId, environmentId, userId },
        body: requirePlainObject(input, "issueActivationToken"),
      });
    },
    issuePasswordResetToken({
      teamId = null,
      environmentId,
      userId,
      ...input
    }: MethodInput<"issuePasswordResetToken">) {
      return requestOperation("issuePasswordResetToken", {
        pathParams: { teamId, environmentId, userId },
        body: requirePlainObject(input, "issuePasswordResetToken"),
      });
    },
    revokeUserPasswordCredential({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"revokeUserPasswordCredential">) {
      return requestOperation("revokeUserPasswordCredential", {
        pathParams: { teamId, environmentId, userId },
        body: {},
      });
    },
    revokeUserRecoveryToken({
      teamId = null,
      environmentId,
      userId,
      tokenId,
    }: MethodInput<"revokeUserRecoveryToken">) {
      return requestOperation("revokeUserRecoveryToken", {
        pathParams: { teamId, environmentId, userId, tokenId },
        body: {},
      });
    },
    getUserProfile({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"getUserProfile">) {
      return requestOperation("getUserProfile", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    updateUserProfile({
      teamId = null,
      environmentId,
      userId,
      ...input
    }: MethodInput<"updateUserProfile">) {
      return requestOperation("updateUserProfile", {
        pathParams: { teamId, environmentId, userId },
        body: requirePlainObject(input, "updateUserProfile"),
      });
    },
    listUserSessions({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"listUserSessions">) {
      return requestOperation("listUserSessions", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    revokeUserSession({
      teamId = null,
      environmentId,
      userId,
      sessionId,
    }: MethodInput<"revokeUserSession">) {
      return requestOperation("revokeUserSession", {
        pathParams: { teamId, environmentId, userId, sessionId },
        body: {},
      });
    },
    listUserGrants({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"listUserGrants">) {
      return requestOperation("listUserGrants", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    revokeUserGrant({
      teamId = null,
      environmentId,
      userId,
      grantId,
    }: MethodInput<"revokeUserGrant">) {
      return requestOperation("revokeUserGrant", {
        pathParams: { teamId, environmentId, userId, grantId },
        body: {},
      });
    },
    listUserRefreshTokens({
      teamId = null,
      environmentId,
      userId,
    }: MethodInput<"listUserRefreshTokens">) {
      return requestOperation("listUserRefreshTokens", {
        pathParams: { teamId, environmentId, userId },
      });
    },
    revokeUserRefreshToken({
      teamId = null,
      environmentId,
      userId,
      refreshTokenId,
    }: MethodInput<"revokeUserRefreshToken">) {
      return requestOperation("revokeUserRefreshToken", {
        pathParams: { teamId, environmentId, userId, refreshTokenId },
        body: {},
      });
    },
    inviteUser({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"inviteUser">) {
      return requestOperation("inviteUser", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "inviteUser"),
      });
    },
    importUsersCsv({
      teamId = null,
      environmentId,
      ...input
    }: MethodInput<"importUsersCsv">) {
      return requestOperation("importUsersCsv", {
        pathParams: { teamId, environmentId },
        body: requirePlainObject(input, "importUsersCsv"),
      });
    },
    listTeamAuditEvents({
      teamId = null,
      pageSize = null,
      pageToken = null,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from = null,
      to = null,
    }: OptionalMethodInput<"listTeamAuditEvents"> = {}) {
      return requestOperation("listTeamAuditEvents", {
        pathParams: { teamId },
        query: {
          pageSize,
          pageToken,
          eventType,
          category,
          targetType,
          outcome,
          severity,
          from,
          to,
        },
      });
    },
    exportTeamAuditEvents({
      teamId = null,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from,
      to,
      format = null,
      limit = null,
    }: MethodInput<"exportTeamAuditEvents">) {
      return requestOperation("exportTeamAuditEvents", {
        pathParams: { teamId },
        query: { eventType, category, targetType, outcome, severity, from, to, format, limit },
      });
    },
    exportTeamAuditEventsCsv({
      teamId = null,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from,
      to,
      limit = null,
    }: MethodInput<"exportTeamAuditEventsCsv">) {
      return requestOperation("exportTeamAuditEventsCsv", {
        pathParams: { teamId },
        query: {
          eventType,
          category,
          targetType,
          outcome,
          severity,
          from,
          to,
          format: "csv",
          limit,
        },
      });
    },
    getAuditEvent({ teamId = null, auditEventId }: MethodInput<"getAuditEvent">) {
      return requestOperation("getAuditEvent", {
        pathParams: { teamId, auditEventId },
      });
    },
    listEnvironmentAuditEvents({
      teamId = null,
      environmentId,
      pageSize = null,
      pageToken = null,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from = null,
      to = null,
    }: MethodInput<"listEnvironmentAuditEvents">) {
      return requestOperation("listEnvironmentAuditEvents", {
        pathParams: { teamId, environmentId },
        query: {
          pageSize,
          pageToken,
          eventType,
          category,
          targetType,
          outcome,
          severity,
          from,
          to,
        },
      });
    },
    exportEnvironmentAuditEvents({
      teamId = null,
      environmentId,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from,
      to,
      format = null,
      limit = null,
    }: MethodInput<"exportEnvironmentAuditEvents">) {
      return requestOperation("exportEnvironmentAuditEvents", {
        pathParams: { teamId, environmentId },
        query: { eventType, category, targetType, outcome, severity, from, to, format, limit },
      });
    },
    exportEnvironmentAuditEventsCsv({
      teamId = null,
      environmentId,
      eventType = null,
      category = null,
      targetType = null,
      outcome = null,
      severity = null,
      from,
      to,
      limit = null,
    }: MethodInput<"exportEnvironmentAuditEventsCsv">) {
      return requestOperation("exportEnvironmentAuditEventsCsv", {
        pathParams: { teamId, environmentId },
        query: {
          eventType,
          category,
          targetType,
          outcome,
          severity,
          from,
          to,
          format: "csv",
          limit,
        },
      });
    },
    getSystemHealth() {
      return requestOperation("systemHealth");
    },
    getSystemVersion() {
      return requestOperation("systemVersion");
    },
    createSession({ email, password }: MethodInput<"createSession">) {
      return createAuthenticationSession({ email, password });
    },
    deleteCurrentSession() {
      return deleteCurrentAuthenticationSession();
    },
  };

  return Object.freeze(client);
}

export {
  validateClient,
  validateEnvironment,
  validateEnvironmentMutationResponse,
  validateErrorResponse,
  validateListResponse,
  validatePageInfo,
  validatePolicyDocument,
  validatePolicyPatchResponse,
  validateSystemVersionResponse,
  validateTeam,
  validateTenant,
};
