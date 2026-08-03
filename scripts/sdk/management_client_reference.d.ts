export type PageInfo = {
  nextPageToken?: string | null;
};

export type ErrorResponse = {
  errorCode: string;
  message: string;
  details?: unknown;
  requestId?: string | null;
};

export type CreateSessionRequest = {
  email: string;
  password: string;
};

export type AuditActor = {
  actorType: string;
  actorId?: string | null;
  ipAddress?: string | null;
  mfa?: boolean | null;
  userAgent?: string | null;
};

export type AuditTarget = {
  targetType: string;
  targetId?: string | null;
};

export type AuditRequestContext = {
  requestId: string;
  traceId?: string | null;
  spanId?: string | null;
};

export type AuditChange = {
  fromConfigurationVersionId?: string | null;
  toConfigurationVersionId?: string | null;
  jsonPatch?: unknown;
};

export type AuditEvent = {
  id: string;
  teamId: string;
  environmentId?: string | null;
  tenantId?: string | null;
  eventType: string;
  category: string;
  outcome: string;
  severity: string;
  occurredAt: string;
  actor: AuditActor;
  target: AuditTarget;
  request: AuditRequestContext;
  change?: AuditChange | null;
  data?: unknown;
};

export type Team = {
  id: string;
  name: string;
  slug?: string | null;
  createdAt: string;
  updatedAt: string;
};

export type CreateTeamRequest = {
  name: string;
  slug?: string | null;
};

export type UpdateTeamRequest = {
  name?: string | null;
};

export type Tenant = {
  id: string;
  teamId: string;
  slug: string;
  name: string;
  region: string;
  createdAt: string;
  updatedAt: string;
};

export type CreateTenantRequest = {
  slug: string;
  name: string;
  region: string;
};

export type UpdateTenantRequest = {
  name?: string | null;
};

export type Environment = {
  id: string;
  teamId: string;
  tenantId: string;
  name: string;
  slug: string;
  issuerHost: string;
  issuerUrl: string;
  activeConfigurationVersionId: string;
  createdAt: string;
  updatedAt: string;
};

export type DcrBearerTokenStatus = {
  environmentId: string;
  configured: boolean;
  hashAlgorithm?: string | null;
  updatedAt?: string | null;
};

export type OAuthProfile = {
  id: string;
  environmentId: string;
  configurationVersionId: string;
  name: string;
  description?: string | null;
  profileType: string;
  oauthVersion: string;
  isDefault: boolean;
  requirePkce: boolean;
  requireStateParameter: boolean;
  requireIssParameter: boolean;
  allowImplicit: boolean;
  allowRopc: boolean;
  senderConstrained: string;
  enforceRefreshSenderBinding: boolean;
  allowedGrantTypes: string[];
  allowedResponseTypes: string[];
  tokenEndpointAuthMethodsAllowed: string[];
  expiresAt?: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
};

export type CreateOAuthProfileRequest = {
  name: string;
  description?: string | null;
  profileType: string;
  oauthVersion: string;
  isDefault: boolean;
  requirePkce: boolean;
  requireStateParameter: boolean;
  requireIssParameter: boolean;
  allowImplicit: boolean;
  allowRopc: boolean;
  senderConstrained: string;
  enforceRefreshSenderBinding: boolean;
  allowedGrantTypes: string[];
  allowedResponseTypes: string[];
  tokenEndpointAuthMethodsAllowed: string[];
  expiresAt?: string | null;
};

export type UpdateOAuthProfileRequest = {
  name?: string | null;
  description?: string | null;
  profileType?: string | null;
  oauthVersion?: string | null;
  isDefault?: boolean | null;
  requirePkce?: boolean | null;
  requireStateParameter?: boolean | null;
  requireIssParameter?: boolean | null;
  allowImplicit?: boolean | null;
  allowRopc?: boolean | null;
  senderConstrained?: string | null;
  enforceRefreshSenderBinding?: boolean | null;
  allowedGrantTypes?: string[] | null;
  allowedResponseTypes?: string[] | null;
  tokenEndpointAuthMethodsAllowed?: string[] | null;
  expiresAt?: string | null;
};

export type Connection = {
  id: string;
  environmentId: string;
  configurationVersionId: string;
  oauthProfileId?: string | null;
  connectionIdentifier: string;
  name: string;
  connectionType: string;
  issuerUrl: string;
  clientId: string;
  clientAuthMethod: string;
  status: string;
  createdAt: string;
  updatedAt: string;
};

export type CreateConnectionRequest = {
  connectionIdentifier: string;
  name: string;
  connectionType?: string | null;
  issuerUrl: string;
  clientId: string;
  clientAuthMethod?: string | null;
  status?: string | null;
  oauthProfileId?: string | null;
};

export type UpdateConnectionRequest = {
  connectionIdentifier?: string | null;
  name?: string | null;
  connectionType?: string | null;
  issuerUrl?: string | null;
  clientId?: string | null;
  clientAuthMethod?: string | null;
  status?: string | null;
  oauthProfileId?: string | null;
};

export type CreateEnvironmentRequest = {
  name: string;
  slug: string;
};

export type UpdateEnvironmentRequest = {
  name?: string | null;
};

export type SetDcrBearerTokenRequest = {
  token: string;
};

export type Client = {
  id: string;
  environmentId: string;
  oauthProfileId?: string | null;
  clientIdentifier: string;
  name: string;
  clientType: string;
  redirectUris: string[];
  allowedGrantTypes: string[];
  allowedResponseTypes: string[];
  allowedScopes: string[];
  tokenEndpointAuthenticationMethod: string;
  requirePkce: boolean;
  createdAt: string;
  updatedAt: string;
};

export type CreateClientRequest = {
  baseConfigurationVersionId: string;
  name: string;
  clientType: string;
  redirectUris: string[];
  allowedGrantTypes?: string[] | null;
  allowedResponseTypes?: string[] | null;
  allowedScopes?: string[] | null;
  tokenEndpointAuthenticationMethod?: string | null;
  requirePkce?: boolean | null;
  comment?: string | null;
};

export type UpdateClientRequest = {
  baseConfigurationVersionId: string;
  name?: string | null;
  redirectUris?: string[] | null;
  allowedGrantTypes?: string[] | null;
  allowedResponseTypes?: string[] | null;
  allowedScopes?: string[] | null;
  tokenEndpointAuthenticationMethod?: string | null;
  requirePkce?: boolean | null;
  comment?: string | null;
};

export type ClientSecret = {
  id: string;
  clientId: string;
  status: string;
  createdAt: string;
  expiresAt: string;
  activeSlot?: number | null;
};

export type ConfigurationTransactionRequest = {
  baseConfigurationVersionId: string;
  comment?: string | null;
};

export type IssueClientSecretRequest = {
  baseConfigurationVersionId: string;
  expiresInDays?: number | null;
  comment?: string | null;
};

export type ConfigurationVersion = {
  id: string;
  environmentId: string;
  versionNumber: number;
  schemaVersion: number;
  configurationHash: string;
  status: string;
  createdAt: string;
  configurationDocument?: unknown;
  comment?: string | null;
};

export type CreateConfigurationVersionRequest = {
  baseConfigurationVersionId: string;
  configurationDocument: unknown;
  comment?: string | null;
};

export type ActivateConfigurationVersionRequest = {
  allowSecurityDowngrade?: boolean | null;
  reason?: string | null;
};

export type PolicyDocument = Record<string, unknown>;

export type PolicyPatchRequest = {
  baseConfigurationVersionId: string;
  [key: string]: unknown;
};

export type KeyStorePublicView = {
  type: string;
  configuration: unknown;
  redacted: boolean;
};

export type UpdateKeyStoreRequest = {
  type: string;
  configuration: unknown;
  baseConfigurationVersionId: string;
  allowSecurityDowngrade?: boolean | null;
  comment?: string | null;
  reason?: string | null;
};

export type RuntimeKey = {
  id: string;
  environmentId: string;
  usage: string;
  kid: string;
  algorithm: string;
  provider: string;
  status: string;
  publicJwk: unknown;
  providerConfiguration: unknown;
  createdAt: string;
};

export type CreateRuntimeKeyRequest = {
  baseConfigurationVersionId: string;
  usage: string;
  algorithm?: string | null;
  provider?: string | null;
  kid?: string | null;
  providerConfiguration?: unknown;
  privateKeyPem?: string | null;
  activate?: boolean | null;
  comment?: string | null;
};

export type ActivateRuntimeKeyRequest = {
  baseConfigurationVersionId: string;
  usage: string;
  comment?: string | null;
};

export type User = {
  id: string;
  environmentId: string;
  subject: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  email?: string | null;
};

export type CreateUserRequest = {
  subject: string;
  email?: string | null;
};

export type UpdateUserRequest = {
  subject?: string | null;
  email?: string | null;
};

export type UserProfile = {
  userId: string;
  subject: string;
  subjectPolicy: string;
  email?: string | null;
  emailVerified: boolean;
  displayName?: string | null;
  customClaims: Record<string, unknown>;
  version: number;
  updatedAt: string;
};

export type UpdateUserProfileRequest = {
  baseVersion: number;
  email?: string | null;
  emailVerified?: boolean | null;
  displayName?: string | null;
  customClaims?: Record<string, unknown> | null;
};

export type PasswordCredential = {
  id: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string | null;
};

export type RecoveryToken = {
  id: string;
  purpose: string;
  status: string;
  expiresAt: string;
  redeemedAt?: string | null;
  revokedAt?: string | null;
  createdAt: string;
};

export type UserCredentialsResponse = {
  password?: PasswordCredential | null;
  recoveryTokens: RecoveryToken[];
};

export type UserSessionInventoryEntry = {
  id: string;
  authTimeEpochSeconds: number;
  acr?: string | null;
};

export type ListUserSessionsResponse = {
  sessions: UserSessionInventoryEntry[];
};

export type UserGrantInventoryEntry = {
  id: string;
  source: string;
  clientId: string;
  scopes: string[];
  audience: string;
  authorizationDetails?: unknown;
  authTimeEpochSeconds?: number | null;
  acr?: string | null;
  expiresAtEpochSeconds: number;
};

export type ListUserGrantsResponse = {
  grants: UserGrantInventoryEntry[];
};

export type UserRefreshTokenInventoryEntry = {
  id: string;
  clientId: string;
  scopes: string[];
  resource?: string | null;
  senderBinding?: string | null;
  authorizationDetails?: unknown;
  authTimeEpochSeconds: number;
  acr?: string | null;
  expiresAtEpochSeconds: number;
  rotationCount: number;
};

export type ListUserRefreshTokensResponse = {
  refreshTokens: UserRefreshTokenInventoryEntry[];
};

export type IssueRecoveryTokenRequest = {
  expiresInSeconds?: number | null;
};

export type IssueRecoveryTokenResponse = {
  token: string;
  redeemUrl: string;
  recoveryToken: RecoveryToken;
};

export type InviteUserRequest = {
  subject: string;
  email?: string | null;
  expiresInSeconds?: number | null;
};

export type InviteUserResponse = {
  user: User;
  activation: IssueRecoveryTokenResponse;
};

export type ImportUsersCsvRequest = {
  csv: string;
  issueActivationTokens: boolean;
  activationTokenExpiresInSeconds?: number | null;
};

export type ImportedUserRow = {
  rowNumber: number;
  user: User;
  activation?: IssueRecoveryTokenResponse | null;
};

export type ImportUsersCsvResponse = {
  importedUsers: ImportedUserRow[];
};

export type ListTeamsResponse = {
  teams: Team[];
  pageInfo?: PageInfo | null;
};

export type ListTenantsResponse = {
  tenants: Tenant[];
  pageInfo?: PageInfo | null;
};

export type ListEnvironmentsResponse = {
  environments: Environment[];
  pageInfo?: PageInfo | null;
};

export type ListOAuthProfilesResponse = {
  oauthProfiles: OAuthProfile[];
  pageInfo?: PageInfo | null;
};

export type ListConnectionsResponse = {
  connections: Connection[];
  pageInfo?: PageInfo | null;
};

export type AccountLink = {
  id: string;
  environmentId: string;
  connectionId: string;
  connectionIdentifier: string;
  connectionName: string;
  upstreamIssuer: string;
  endUserId: string;
  endUserSubject: string;
  endUserEmail?: string | null;
  endUserStatus: string;
  hasRefreshToken: boolean;
  createdAt: string;
  lastUsedAt?: string | null;
};

export type ListAccountLinksResponse = {
  accountLinks: AccountLink[];
  pageInfo?: PageInfo | null;
};

export type AccountLinkConflictPreview = {
  requestedConnectionId: string;
  requestedConnectionIdentifier: string;
  requestedConnectionName: string;
  upstreamIssuer: string;
  upstreamSubject: string;
  existingAccountLink?: AccountLink | null;
  candidateEndUsers: AccountLinkConflictCandidate[];
};

export type AccountLinkConflictCandidate = {
  endUser: User;
  matchReasons: string[];
  recommended: boolean;
};

export type AccountLinkRefreshTokenHandling = "clear" | "retain";

export type AccountLinkLowConfidenceHandling = "allow_low_confidence";

export type AccountLinkInactiveTargetHandling = "allow_inactive";

export type ResolveAccountLinkConflictRequest = {
  connectionId: string;
  upstreamSubject: string;
  endUserId: string;
  upstreamRefreshTokenHandling?: AccountLinkRefreshTokenHandling | null;
  lowConfidenceHandling?: AccountLinkLowConfidenceHandling | null;
  inactiveTargetHandling?: AccountLinkInactiveTargetHandling | null;
};

export type RelinkAccountLinkRequest = {
  endUserId: string;
  upstreamRefreshTokenHandling?: AccountLinkRefreshTokenHandling | null;
  inactiveTargetHandling?: AccountLinkInactiveTargetHandling | null;
};

export type BulkRelinkAccountLinksRequest = {
  accountLinkIds: string[];
  endUserId: string;
  upstreamRefreshTokenHandling?: AccountLinkRefreshTokenHandling | null;
  inactiveTargetHandling?: AccountLinkInactiveTargetHandling | null;
};

export type BulkRelinkAccountLinksResponse = {
  accountLinks: AccountLink[];
};

export type FederationLogoutRecoveryIncident = {
  id: string;
  teamId: string;
  tenantId: string;
  environmentId: string;
  connectionId?: string | null;
  connectionIdentifier?: string | null;
  connectionName?: string | null;
  downstreamClientId?: string | null;
  upstreamIssuer: string;
  recoveryPolicy: string;
  status: string;
  sessionHintClaim?: string | null;
  sessionHintPresent: boolean;
  downstreamRedirectUri: string;
  downstreamStatePresent: boolean;
  failureReason?: string | null;
  requestId: string;
  createdAt: string;
  expiresAt: string;
  resolvedAt?: string | null;
};

export type ListFederationLogoutRecoveryIncidentsResponse = {
  incidents: FederationLogoutRecoveryIncident[];
  pageInfo?: PageInfo | null;
};

export type ClearFederationLogoutRecoveryIncidentRequest = {
  reason: string;
};

export type FederationTrustAnchor = {
  id: string;
  environmentId: string;
  entityId: string;
  jwks: unknown;
  metadataPolicy?: unknown;
  createdAt: string;
  updatedAt: string;
};

export type CreateFederationTrustAnchorRequest = {
  entityId: string;
  jwks: unknown;
  metadataPolicy?: unknown;
};

export type ListFederationTrustAnchorsResponse = {
  trustAnchors: FederationTrustAnchor[];
  pageInfo?: PageInfo | null;
};

export type FederationEntityCacheEntry = {
  id: string;
  environmentId: string;
  entityId: string;
  entityConfigurationJws: string;
  parsedStatement: unknown;
  fetchedAt: string;
  expiresAt: string;
};

export type ListFederationEntityCacheResponse = {
  entityCacheEntries: FederationEntityCacheEntry[];
  pageInfo?: PageInfo | null;
};

export type FederationTrustChainEntry = {
  id: string;
  environmentId: string;
  leafEntityId: string;
  anchorEntityId: string;
  chainJwts: unknown;
  resolvedAt: string;
  expiresAt: string;
};

export type ListFederationTrustChainsResponse = {
  trustChains: FederationTrustChainEntry[];
  pageInfo?: PageInfo | null;
};

export type ListClientsResponse = {
  clients: Client[];
  pageInfo?: PageInfo | null;
};

export type ListClientSecretsResponse = {
  clientSecrets: ClientSecret[];
};

export type ListConfigurationVersionsResponse = {
  configurationVersions: ConfigurationVersion[];
  pageInfo?: PageInfo | null;
};

export type ListRuntimeKeysResponse = {
  runtimeKeys: RuntimeKey[];
};

export type ListUsersResponse = {
  users: User[];
  pageInfo?: PageInfo | null;
};

export type ListAuditEventsResponse = {
  auditEvents: AuditEvent[];
  pageInfo?: PageInfo | null;
};

export type ExportTimeRange = {
  from: string;
  to: string;
};

export type ExportAuditEventsResponse = {
  totalCount: number;
  exportedAt: string;
  timeRange: ExportTimeRange;
  auditEvents: AuditEvent[];
};

export type EnvironmentMutationResponse = {
  environment: Environment;
};

export type OAuthProfileMutationResponse = {
  oauthProfile: OAuthProfile;
  environment: Environment;
};

export type ConnectionMutationResponse = {
  connection: Connection;
  environment: Environment;
};

export type ClientMutationResponse = {
  client: Client;
  environment: Environment;
};

export type ClientSecretMutationResponse = {
  clientSecret: ClientSecret;
  environment: Environment;
};

export type RuntimeKeyMutationResponse = {
  runtimeKey: RuntimeKey;
  environment: Environment;
};

export type IssueClientSecretResponse = {
  clientSecretValue: string;
  clientSecret: ClientSecret;
  environment: Environment;
};

export type PolicyPatchResponse = {
  policy: PolicyDocument;
  environment: Environment;
};

export type KeyStoreUpdateResponse = {
  keyStore: KeyStorePublicView;
  environment: Environment;
};

export type SystemVersionResponse = {
  version: string;
  commit?: string | null;
};

export type ManagementOperationDescriptor = {
  operationId: string;
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  path: string;
  responseType: 'json' | 'text' | 'empty';
};

export declare const MANAGEMENT_OPENAPI_METADATA: Readonly<{
  title: string;
  version: string;
  pathCount: number;
  sourceArtifact: string;
}>;

export declare const MANAGEMENT_CLIENT_DEFAULTS: Readonly<{
  basePath: string;
  csrfCookieName: string;
  sessionCookieName: string;
  credentials: string;
}>;

export declare const MANAGEMENT_OPERATIONS: Readonly<Record<string, ManagementOperationDescriptor>>;

export type ManagementCookieJar = {
  get(name: string): string | null;
  set(name: string, value: string): void;
  delete(name: string): void;
  clear(): void;
  applySetCookieHeaders(headersOrResponse: unknown): void;
  toHeader(): string | null;
  toJSON(): Record<string, string>;
  clone(): ManagementCookieJar;
};

export type ManagementSessionState = Readonly<{
  origin: string | null;
  teamId: string | null;
  csrfToken: string | null;
  csrfCookieName: string;
  credentials: string;
  cookieJar: ManagementCookieJar;
}>;

export type ManagementSessionStore = {
  getState(): ManagementSessionState;
  setOrigin(nextOrigin: string | null): ManagementSessionState;
  setTeamId(nextTeamId: string | null): ManagementSessionState;
  setCsrfToken(nextCsrfToken: string | null): ManagementSessionState;
  syncCsrfToken(): string | null;
  captureResponse(response: unknown): ManagementSessionState;
  clearSession(): ManagementSessionState;
  clone(overrides?: Partial<{
    origin: string | null;
    teamId: string | null;
    csrfToken: string | null;
    csrfCookieName: string;
    credentials: string;
    cookieJar: ManagementCookieJar;
    cookieReader: (() => string) | null;
  }>): ManagementSessionStore;
};

export declare function readCookieValue(cookieSource: string, name?: string): string | null;
export declare function createDocumentCookieReader(options?: {
  documentLike?: { cookie?: string } | null;
}): () => string;
export declare function createInMemoryCookieJar(options?: {
  initialCookies?: string | Record<string, string> | null;
}): ManagementCookieJar;
export declare function createInMemoryManagementSessionStore(options?: {
  origin?: string | null;
  teamId?: string | null;
  csrfToken?: string | null;
  csrfCookieName?: string;
  credentials?: string;
  cookieJar?: ManagementCookieJar;
  cookieReader?: (() => string) | null;
}): ManagementSessionStore;

export declare class ManagementApiError extends Error {
  constructor(message: string, details: {
    status: number;
    operationId: string;
    errorCode?: string | null;
    requestId?: string | null;
    details?: unknown;
    responseBody?: unknown;
  });
  status: number;
  operationId: string;
  errorCode: string | null;
  requestId: string | null;
  details: unknown;
  responseBody: unknown;
  error?: ErrorResponse;
  raw: unknown;
}

export type ManagementClient = {
  metadata: typeof MANAGEMENT_OPENAPI_METADATA;
  operations: typeof MANAGEMENT_OPERATIONS;
  sessionStore: ManagementSessionStore | null;
  requestOperation<T = unknown>(operationName: string, options?: {
    pathParams?: Record<string, string | null | undefined>;
    query?: Record<
      string,
      string | number | boolean | Array<string | number | boolean> | null | undefined
    >;
    body?: unknown;
    headers?: HeadersInit;
  }): Promise<T>;
  primeCsrf(): Promise<string>;
  withTeamId(teamId: string): ManagementClient;
  systemHealth(): Promise<string>;
  getSystemHealth(): Promise<string>;
  systemVersion(): Promise<SystemVersionResponse>;
  getSystemVersion(): Promise<SystemVersionResponse>;
  bootstrapOwner(input: {
    email: string;
    password: string;
    bootstrapToken?: string | null;
  }): Promise<null>;
  createAuthenticationSession(
    input: CreateSessionRequest,
  ): Promise<ManagementSessionState | null>;
  createSession(input: CreateSessionRequest): Promise<ManagementSessionState | null>;
  deleteCurrentAuthenticationSession(): Promise<null>;
  deleteCurrentSession(): Promise<null>;
  listTeams(query?: {
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListTeamsResponse>;
  createTeam(input: CreateTeamRequest): Promise<Team>;
  getTeam(input: { teamId: string }): Promise<Team>;
  updateTeam(input: { teamId: string } & UpdateTeamRequest): Promise<Team>;
  deleteTeam(input: { teamId: string }): Promise<null>;
  listTenants(input?: {
    teamId?: string | null;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListTenantsResponse>;
  createTenant(input: { teamId?: string | null } & CreateTenantRequest): Promise<Tenant>;
  getTenant(input: { teamId?: string | null; tenantId: string }): Promise<Tenant>;
  updateTenant(
    input: { teamId?: string | null; tenantId: string } & UpdateTenantRequest,
  ): Promise<Tenant>;
  deleteTenant(input: { teamId?: string | null; tenantId: string }): Promise<null>;
  listEnvironments(input: {
    teamId?: string | null;
    tenantId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListEnvironmentsResponse>;
  createEnvironment(
    input: { teamId?: string | null; tenantId: string } & CreateEnvironmentRequest,
  ): Promise<Environment>;
  listOAuthProfiles(input: {
    teamId?: string | null;
    environmentId: string;
    configurationVersionId?: string | null;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListOAuthProfilesResponse>;
  createOAuthProfile(
    input: {
      teamId?: string | null;
      environmentId: string;
      configurationVersionId?: string | null;
    } & CreateOAuthProfileRequest,
  ): Promise<OAuthProfileMutationResponse>;
  getOAuthProfile(input: {
    teamId?: string | null;
    environmentId: string;
    oauthProfileId: string;
  }): Promise<OAuthProfile>;
  updateOAuthProfile(
    input: {
      teamId?: string | null;
      environmentId: string;
      oauthProfileId: string;
    } & UpdateOAuthProfileRequest,
  ): Promise<OAuthProfileMutationResponse>;
  deleteOAuthProfile(input: {
    teamId?: string | null;
    environmentId: string;
    oauthProfileId: string;
  }): Promise<null>;
  listConnections(input: {
    teamId?: string | null;
    environmentId: string;
    configurationVersionId?: string | null;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListConnectionsResponse>;
  createConnection(
    input: {
      teamId?: string | null;
      environmentId: string;
      configurationVersionId?: string | null;
    } & CreateConnectionRequest,
  ): Promise<ConnectionMutationResponse>;
  getConnection(input: {
    teamId?: string | null;
    environmentId: string;
    connectionId: string;
  }): Promise<Connection>;
  updateConnection(
    input: {
      teamId?: string | null;
      environmentId: string;
      connectionId: string;
    } & UpdateConnectionRequest,
  ): Promise<ConnectionMutationResponse>;
  deleteConnection(input: {
    teamId?: string | null;
    environmentId: string;
    connectionId: string;
  }): Promise<null>;
  listAccountLinks(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
    upstreamIssuer?: string | null;
    upstreamSubject?: string | null;
    endUserSubject?: string | null;
    endUserEmail?: string | null;
    connectionIdentifier?: string | null;
  }): Promise<ListAccountLinksResponse>;
  createAccountLink(input: {
    teamId?: string | null;
    environmentId: string;
    connectionId: string;
    upstreamSubject: string;
    endUserId: string;
  }): Promise<AccountLink>;
  previewAccountLinkConflict(input: {
    teamId?: string | null;
    environmentId: string;
    connectionId: string;
    upstreamSubject: string;
  }): Promise<AccountLinkConflictPreview>;
  resolveAccountLinkConflict(
    input: { teamId?: string | null; environmentId: string } & ResolveAccountLinkConflictRequest,
  ): Promise<AccountLink>;
  deleteAccountLink(input: {
    teamId?: string | null;
    environmentId: string;
    accountLinkId: string;
  }): Promise<null>;
  bulkRelinkAccountLinks(
    input: { teamId?: string | null; environmentId: string } & BulkRelinkAccountLinksRequest,
  ): Promise<BulkRelinkAccountLinksResponse>;
  relinkAccountLink(
    input: {
      teamId?: string | null;
      environmentId: string;
      accountLinkId: string;
    } & RelinkAccountLinkRequest,
  ): Promise<AccountLink>;
  listFederationLogoutRecoveryIncidents(input: {
    teamId?: string | null;
    environmentId: string;
    connectionId?: string | null;
    status?: string | null;
    recoveryPolicy?: string | null;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListFederationLogoutRecoveryIncidentsResponse>;
  getFederationLogoutRecoveryIncident(input: {
    teamId?: string | null;
    environmentId: string;
    incidentId: string;
  }): Promise<FederationLogoutRecoveryIncident>;
  clearFederationLogoutRecoveryIncident(input: {
    teamId?: string | null;
    environmentId: string;
    incidentId: string;
  } & ClearFederationLogoutRecoveryIncidentRequest): Promise<null>;
  listFederationTrustAnchors(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListFederationTrustAnchorsResponse>;
  createFederationTrustAnchor(
    input: { teamId?: string | null; environmentId: string } & CreateFederationTrustAnchorRequest,
  ): Promise<FederationTrustAnchor>;
  getFederationTrustAnchor(input: {
    teamId?: string | null;
    environmentId: string;
    trustAnchorId: string;
  }): Promise<FederationTrustAnchor>;
  deleteFederationTrustAnchor(input: {
    teamId?: string | null;
    environmentId: string;
    trustAnchorId: string;
  }): Promise<null>;
  listFederationEntityCache(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListFederationEntityCacheResponse>;
  refreshFederationEntityCacheEntry(input: {
    teamId?: string | null;
    environmentId: string;
    entityCacheId: string;
  }): Promise<FederationEntityCacheEntry>;
  deleteFederationEntityCacheEntry(input: {
    teamId?: string | null;
    environmentId: string;
    entityCacheId: string;
  }): Promise<null>;
  listFederationTrustChains(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListFederationTrustChainsResponse>;
  refreshFederationTrustChain(input: {
    teamId?: string | null;
    environmentId: string;
    trustChainId: string;
  }): Promise<FederationTrustChainEntry>;
  deleteFederationTrustChain(input: {
    teamId?: string | null;
    environmentId: string;
    trustChainId: string;
  }): Promise<null>;
  getEnvironment(input: { teamId?: string | null; environmentId: string }): Promise<Environment>;
  updateEnvironment(
    input: { teamId?: string | null; environmentId: string } & UpdateEnvironmentRequest,
  ): Promise<Environment>;
  deleteEnvironment(input: { teamId?: string | null; environmentId: string }): Promise<null>;
  getDcrBearerTokenStatus(input: {
    teamId?: string | null;
    environmentId: string;
  }): Promise<DcrBearerTokenStatus>;
  putDcrBearerToken(
    input: { teamId?: string | null; environmentId: string } & SetDcrBearerTokenRequest,
  ): Promise<DcrBearerTokenStatus>;
  deleteDcrBearerToken(input: { teamId?: string | null; environmentId: string }): Promise<null>;
  listClients(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListClientsResponse>;
  createClient(
    input: { teamId?: string | null; environmentId: string } & CreateClientRequest,
  ): Promise<ClientMutationResponse>;
  getClient(input: {
    teamId?: string | null;
    environmentId: string;
    clientId: string;
  }): Promise<Client>;
  updateClient(
    input: {
      teamId?: string | null;
      environmentId: string;
      clientId: string;
    } & UpdateClientRequest,
  ): Promise<ClientMutationResponse>;
  deleteClient(
    input: {
      teamId?: string | null;
      environmentId: string;
      clientId: string;
    } & ConfigurationTransactionRequest,
  ): Promise<null>;
  listClientSecrets(input: {
    teamId?: string | null;
    environmentId: string;
    clientId: string;
  }): Promise<ListClientSecretsResponse>;
  issueClientSecret(
    input: {
      teamId?: string | null;
      environmentId: string;
      clientId: string;
    } & IssueClientSecretRequest,
  ): Promise<IssueClientSecretResponse>;
  revokeClientSecret(
    input: {
      teamId?: string | null;
      environmentId: string;
      clientId: string;
      clientSecretId: string;
    } & ConfigurationTransactionRequest,
  ): Promise<ClientSecretMutationResponse>;
  revokeAllClientSecrets(
    input: {
      teamId?: string | null;
      environmentId: string;
      clientId: string;
    } & ConfigurationTransactionRequest,
  ): Promise<EnvironmentMutationResponse>;
  listConfigurationVersions(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
  }): Promise<ListConfigurationVersionsResponse>;
  createConfigurationVersion(
    input: { teamId?: string | null; environmentId: string } & CreateConfigurationVersionRequest,
  ): Promise<ConfigurationVersion>;
  getConfigurationVersion(input: {
    teamId?: string | null;
    environmentId: string;
    configurationVersionId: string;
  }): Promise<ConfigurationVersion>;
  activateConfigurationVersion(
    input: {
      teamId?: string | null;
      environmentId: string;
      configurationVersionId: string;
    } & ActivateConfigurationVersionRequest,
  ): Promise<EnvironmentMutationResponse>;
  archiveConfigurationVersion(input: {
    teamId?: string | null;
    environmentId: string;
    configurationVersionId: string;
    comment?: string | null;
  }): Promise<null>;
  getPolicies(input: { teamId?: string | null; environmentId: string }): Promise<PolicyDocument>;
  getPolicy(input: { teamId?: string | null; environmentId: string }): Promise<PolicyDocument>;
  patchPolicies(
    input: { teamId?: string | null; environmentId: string } & PolicyPatchRequest,
  ): Promise<PolicyPatchResponse>;
  patchPolicy(
    input: { teamId?: string | null; environmentId: string } & PolicyPatchRequest,
  ): Promise<PolicyPatchResponse>;
  getCurrentKeyStore(input: {
    teamId?: string | null;
    environmentId: string;
  }): Promise<KeyStorePublicView>;
  getKeyStoreCurrent(input: {
    teamId?: string | null;
    environmentId: string;
  }): Promise<KeyStorePublicView>;
  putCurrentKeyStore(
    input: { teamId?: string | null; environmentId: string } & UpdateKeyStoreRequest,
  ): Promise<KeyStoreUpdateResponse>;
  updateKeyStoreCurrent(
    input: { teamId?: string | null; environmentId: string } & UpdateKeyStoreRequest,
  ): Promise<KeyStoreUpdateResponse>;
  listRuntimeKeys(input: {
    teamId?: string | null;
    environmentId: string;
  }): Promise<ListRuntimeKeysResponse>;
  createRuntimeKey(
    input: { teamId?: string | null; environmentId: string } & CreateRuntimeKeyRequest,
  ): Promise<RuntimeKeyMutationResponse>;
  activateNextRuntimeKey(
    input: { teamId?: string | null; environmentId: string } & ActivateRuntimeKeyRequest,
  ): Promise<RuntimeKeyMutationResponse>;
  revokeRuntimeKey(
    input: {
      teamId?: string | null;
      environmentId: string;
      runtimeKeyId: string;
    } & ConfigurationTransactionRequest,
  ): Promise<RuntimeKeyMutationResponse>;
  listUsers(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
    includeDeleted?: boolean | null;
  }): Promise<ListUsersResponse>;
  createUser(
    input: { teamId?: string | null; environmentId: string } & CreateUserRequest,
  ): Promise<User>;
  updateUser(
    input: {
      teamId?: string | null;
      environmentId: string;
      userId: string;
    } & UpdateUserRequest,
  ): Promise<User>;
  deleteUser(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<null>;
  restoreUser(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<User>;
  blockUser(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<User>;
  unblockUser(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<User>;
  invalidateUserSessions(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<null>;
  revokeUserRefreshTokens(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<null>;
  getUserCredentials(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<UserCredentialsResponse>;
  issueActivationToken(
    input: {
      teamId?: string | null;
      environmentId: string;
      userId: string;
    } & IssueRecoveryTokenRequest,
  ): Promise<IssueRecoveryTokenResponse>;
  issuePasswordResetToken(
    input: {
      teamId?: string | null;
      environmentId: string;
      userId: string;
    } & IssueRecoveryTokenRequest,
  ): Promise<IssueRecoveryTokenResponse>;
  revokeUserPasswordCredential(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<UserCredentialsResponse>;
  revokeUserRecoveryToken(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
    tokenId: string;
  }): Promise<UserCredentialsResponse>;
  getUserProfile(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<UserProfile>;
  updateUserProfile(
    input: {
      teamId?: string | null;
      environmentId: string;
      userId: string;
    } & UpdateUserProfileRequest,
  ): Promise<UserProfile>;
  listUserSessions(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<ListUserSessionsResponse>;
  revokeUserSession(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
    sessionId: string;
  }): Promise<null>;
  listUserGrants(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<ListUserGrantsResponse>;
  revokeUserGrant(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
    grantId: string;
  }): Promise<null>;
  listUserRefreshTokens(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
  }): Promise<ListUserRefreshTokensResponse>;
  revokeUserRefreshToken(input: {
    teamId?: string | null;
    environmentId: string;
    userId: string;
    refreshTokenId: string;
  }): Promise<null>;
  inviteUser(
    input: { teamId?: string | null; environmentId: string } & InviteUserRequest,
  ): Promise<InviteUserResponse>;
  importUsersCsv(
    input: { teamId?: string | null; environmentId: string } & ImportUsersCsvRequest,
  ): Promise<ImportUsersCsvResponse>;
  listTeamAuditEvents(input: {
    teamId?: string | null;
    pageSize?: number | null;
    pageToken?: string | null;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from?: string | null;
    to?: string | null;
  }): Promise<ListAuditEventsResponse>;
  exportTeamAuditEvents(input: {
    teamId?: string | null;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from: string;
    to: string;
    format?: string | null;
    limit?: number | null;
  }): Promise<ExportAuditEventsResponse>;
  exportTeamAuditEventsCsv(input: {
    teamId?: string | null;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from: string;
    to: string;
    limit?: number | null;
  }): Promise<string>;
  getAuditEvent(input: { teamId?: string | null; auditEventId: string }): Promise<AuditEvent>;
  listEnvironmentAuditEvents(input: {
    teamId?: string | null;
    environmentId: string;
    pageSize?: number | null;
    pageToken?: string | null;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from?: string | null;
    to?: string | null;
  }): Promise<ListAuditEventsResponse>;
  exportEnvironmentAuditEvents(input: {
    teamId?: string | null;
    environmentId: string;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from: string;
    to: string;
    format?: string | null;
    limit?: number | null;
  }): Promise<ExportAuditEventsResponse>;
  exportEnvironmentAuditEventsCsv(input: {
    teamId?: string | null;
    environmentId: string;
    eventType?: string | null;
    category?: string | null;
    targetType?: string | null;
    outcome?: string | null;
    severity?: string | null;
    from: string;
    to: string;
    limit?: number | null;
  }): Promise<string>;
};

export declare function buildManagementOperationUrl(options: {
  baseUrl: string;
  operationName: string;
  pathParams?: Record<string, string | null | undefined>;
  query?: Record<
    string,
    string | number | boolean | Array<string | number | boolean> | null | undefined
  >;
  defaultTeamId?: string | null;
  basePath?: string;
}): string;

export declare function createManagementClient(options: {
  baseUrl: string;
  fetchImpl?: typeof fetch | null;
  sessionStore?: ManagementSessionStore | null;
  defaultTeamId?: string | null;
  origin?: string | null;
  basePath?: string;
}): ManagementClient;
