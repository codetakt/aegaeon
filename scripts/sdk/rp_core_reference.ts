const DEFAULT_SCOPE = "openid";
const DEFAULT_RESPONSE_TYPE = "code";
const DEFAULT_CODE_CHALLENGE_METHOD = "S256";
const VERIFIED_CORE_OK = 0;

type PlainObject = Record<string, unknown>;
type OptionalString = string | null | undefined;
type ScopeInput = string | readonly string[];
type ExtraParamsInput = Record<string, string> | null | undefined;
type MaybePromise<T> = T | Promise<T>;
type PkceGenerateResult = {
  statusCode: number;
  challenge: string;
};
type RuntimeHandle = {
  pkceGenerate(input: { verifier: string }): MaybePromise<PkceGenerateResult>;
};
type RuntimeHandleInput = RuntimeHandle | { handle: RuntimeHandle };
type ExtraParams = Readonly<Record<string, string>>;
type IssuerMetadata = Readonly<{
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string | null;
  jwksUri: string | null;
  endSessionEndpoint: string | null;
  responseTypesSupported: readonly string[];
  codeChallengeMethodsSupported: readonly string[];
  scopesSupported: readonly string[];
  subjectTypesSupported: readonly string[];
  idTokenSigningAlgValuesSupported: readonly string[];
  raw: PlainObject;
}>;
type AuthorizationTransaction = Readonly<{
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  nonce: string | null;
  verifier: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  responseType: string;
  responseMode: string | null;
  prompt: string | null;
  audience: string | null;
  extraParams: ExtraParams;
}>;
type AuthorizationTransactionStore = {
  load(): MaybePromise<unknown>;
  save(transaction: unknown): MaybePromise<unknown>;
  clear(): MaybePromise<void>;
};
type FederatedSessionRecord = Readonly<{
  issuer: string | null;
  subject: string | null;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  nonce: string | null;
  authorizationCode: string;
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
  tokenType: string | null;
  tokenScope: string | null;
  expiresIn: number | null;
  createdAt: string;
  tokenResponse: PlainObject;
  extra: PlainObject;
}>;
type FederatedSessionStore = {
  load(): MaybePromise<unknown>;
  save(session: unknown): MaybePromise<unknown>;
  clear(): MaybePromise<void>;
};
type TokenResponseNormalized = Readonly<{
  accessToken: string | null;
  refreshToken: string | null;
  idToken: string | null;
  tokenType: string | null;
  scope: string | null;
  expiresIn: number | null;
  raw: PlainObject;
}>;
type PkceAuthorizationRequestResult = {
  verifier: string;
  codeChallenge: string;
  authorizationParameters: URLSearchParams;
  authorizationUrl: string;
};
type PkceAuthorizationTransactionResult = PkceAuthorizationRequestResult & {
  transaction: AuthorizationTransaction;
};
type StartFederatedLoginResult = PkceAuthorizationTransactionResult & {
  redirectUrl: string;
};
type BuildTokenRequestFromAuthorizationResponseResult = {
  response: AuthorizationResponse;
  tokenRequestBody: URLSearchParams;
  transaction: AuthorizationTransaction;
};
type FinishFederatedLoginResult = BuildTokenRequestFromAuthorizationResponseResult & {
  tokenResponse: TokenResponseNormalized;
  session: FederatedSessionRecord | null;
};
type AuthorizationRequestOptions = {
  clientId?: string | undefined;
  redirectUri?: string | undefined;
  scope?: ScopeInput | undefined;
  state?: string | undefined;
  nonce?: OptionalString;
  responseMode?: OptionalString;
  prompt?: OptionalString;
  audience?: OptionalString;
  responseType?: string | undefined;
  extraParams?: ExtraParamsInput;
};
type AuthorizationParameterOptions = AuthorizationRequestOptions & {
  codeChallenge?: string | undefined;
  codeChallengeMethod?: string | undefined;
};
type AuthorizationUrlOptions = AuthorizationParameterOptions & {
  authorizationEndpoint?: string | undefined;
};
type PkceAuthorizationRequestOptions = AuthorizationRequestOptions & {
  runtimeHandle?: RuntimeHandleInput | undefined;
  authorizationEndpoint?: string | undefined;
  verifier?: string | undefined;
};
type BuildTokenRequestBodyOptions = {
  code?: string | undefined;
  redirectUri?: string | undefined;
  clientId?: string | undefined;
  codeVerifier?: string | undefined;
  grantType?: string | undefined;
  extraParams?: ExtraParamsInput;
};
type AuthorizationResponseInput = string | URL | URLSearchParams | PlainObject;
type AuthorizationResponse = {
  code: string | null;
  state: string | null;
  error: string | null;
  errorDescription: string | null;
  errorUri: string | null;
};
type BuildTokenRequestFromAuthorizationResponseOptions = {
  input?: AuthorizationResponseInput | undefined;
  transaction?: unknown;
  grantType?: string | undefined;
  extraParams?: ExtraParamsInput;
};
type NormalizeIssuerMetadataOptions = {
  expectedIssuer?: OptionalString;
  requireAuthorizationCode?: boolean | undefined;
};
type FetchIssuerMetadataOptions = {
  issuer?: string | undefined;
  discoveryUrl?: OptionalString;
  fetch?: typeof globalThis.fetch | undefined;
  signal?: AbortSignal | null | undefined;
  expectedIssuer?: OptionalString;
  requireAuthorizationCode?: boolean | undefined;
  headers?: Record<string, string> | undefined;
};
type IssuerMetadataOptions = {
  issuerMetadata?: unknown;
};
type BuildEndSessionUrlOptions = {
  endSessionEndpoint?: string | undefined;
  idTokenHint?: string | undefined;
  postLogoutRedirectUri?: OptionalString;
  state?: OptionalString;
  clientId?: OptionalString;
  extraParams?: ExtraParamsInput;
};
type BuildEndSessionUrlFromIssuerMetadataOptions = Omit<BuildEndSessionUrlOptions, "endSessionEndpoint"> &
  IssuerMetadataOptions;
type BuildPkceAuthorizationFromIssuerMetadataOptions = Omit<PkceAuthorizationRequestOptions, "authorizationEndpoint"> &
  IssuerMetadataOptions;
type StartFederatedLoginOptions = PkceAuthorizationRequestOptions & {
  transactionStore?: unknown;
};
type StartFederatedLoginFromIssuerMetadataOptions = Omit<StartFederatedLoginOptions, "authorizationEndpoint"> &
  IssuerMetadataOptions;
type RestoreAuthorizationTransactionOptions = {
  transactionStore?: unknown;
  required?: boolean | undefined;
};
type ClearAuthorizationTransactionOptions = {
  transactionStore?: unknown;
};
type CreateAuthorizationTransactionStoreOptions = {
  initialTransaction?: unknown | null | undefined;
};
type CreateFederatedSessionStoreOptions = {
  initialSession?: unknown | null | undefined;
};
type RestoreFederatedSessionOptions = {
  sessionStore?: unknown;
  required?: boolean | undefined;
};
type ClearFederatedSessionOptions = {
  sessionStore?: unknown;
};
type BuildFederatedSessionRecordOptions = {
  transaction?: unknown;
  authorizationResponse?: unknown;
  tokenResponse?: unknown;
  issuer?: OptionalString;
  subject?: OptionalString;
  createdAt?: string | undefined;
  extra?: PlainObject | null | undefined;
};
type ExchangeAuthorizationCode = (input: {
  tokenRequestBody: URLSearchParams;
  authorizationResponse: AuthorizationResponse;
  transaction: AuthorizationTransaction;
}) => MaybePromise<unknown>;
type FinishFederatedLoginOptions = {
  input?: AuthorizationResponseInput | undefined;
  transactionStore?: unknown;
  exchangeAuthorizationCode?: ExchangeAuthorizationCode | undefined;
  sessionStore?: unknown | null | undefined;
  clearTransaction?: boolean | undefined;
  grantType?: string | undefined;
  extraParams?: ExtraParamsInput;
  issuer?: OptionalString;
  subject?: OptionalString;
  sessionExtra?: PlainObject | null | undefined;
};

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${fieldName} must be a non-empty string`);
  }
  return value;
}

function parseMaybeString(value: unknown, fieldName: string): string | null {
  if (value == null) {
    return null;
  }
  return requireString(value, fieldName);
}

function normalizePositiveInteger(value: unknown, fieldName: string): number | null {
  if (value == null) {
    return null;
  }
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new TypeError(`${fieldName} must be a non-negative integer when provided`);
  }
  return value;
}

function requirePlainObject(value: unknown, fieldName: string): PlainObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${fieldName} must be a plain object`);
  }
  return value as PlainObject;
}

function normalizeUrlString(value: unknown, fieldName: string): string {
  const url = new URL(requireString(value, fieldName));
  return url.toString();
}

function normalizeScope(scope: ScopeInput = DEFAULT_SCOPE): string {
  if (Array.isArray(scope)) {
    if (scope.length === 0 || scope.some((entry) => typeof entry !== "string" || entry.length === 0)) {
      throw new TypeError("scope array entries must be non-empty strings");
    }
    return scope.join(" ");
  }
  return requireString(scope, "scope");
}

function normalizeExtraParams(extraParams: ExtraParamsInput = {}): ExtraParams {
  if (extraParams == null) {
    return Object.freeze({}) as ExtraParams;
  }
  const params = requirePlainObject(extraParams, "extraParams");
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    normalized[requireString(key, "extraParams key")] = requireString(value, `extraParams.${key}`);
  }
  return Object.freeze(normalized);
}

function appendOptional(params: URLSearchParams, key: string, value: OptionalString): void {
  if (value == null) {
    return;
  }
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${key} must be a non-empty string when provided`);
  }
  params.set(key, value);
}

function appendExtraParams(params: URLSearchParams, extraParams: ExtraParamsInput = {}): void {
  for (const [key, value] of Object.entries(normalizeExtraParams(extraParams))) {
    if (params.has(key)) {
      throw new Error(`extraParams may not override standard parameter ${key}`);
    }
    appendOptional(params, key, value);
  }
}

function normalizeRuntimeHandle(runtimeOrHandle: RuntimeHandleInput | unknown): RuntimeHandle {
  if (!runtimeOrHandle || typeof runtimeOrHandle !== "object") {
    throw new TypeError("runtimeHandle must be an object");
  }
  if ("handle" in runtimeOrHandle && runtimeOrHandle.handle && typeof runtimeOrHandle.handle === "object") {
    const handle = runtimeOrHandle.handle as Partial<RuntimeHandle>;
    if (typeof handle.pkceGenerate === "function") {
      return handle as RuntimeHandle;
    }
  }
  const candidate = runtimeOrHandle as Partial<RuntimeHandle>;
  if (typeof candidate.pkceGenerate === "function") {
    return candidate as RuntimeHandle;
  }
  throw new TypeError("runtimeHandle must expose pkceGenerate()");
}

function normalizeTransaction(transaction: unknown, fieldName = "transaction"): AuthorizationTransaction {
  const value = requirePlainObject(transaction, fieldName);
  return Object.freeze({
    clientId: requireString(value.clientId, `${fieldName}.clientId`),
    redirectUri: requireString(value.redirectUri, `${fieldName}.redirectUri`),
    scope: normalizeScope(value.scope as ScopeInput | undefined),
    state: requireString(value.state, `${fieldName}.state`),
    nonce: parseMaybeString(value.nonce, `${fieldName}.nonce`),
    verifier: requireString(value.verifier, `${fieldName}.verifier`),
    codeChallenge: requireString(value.codeChallenge, `${fieldName}.codeChallenge`),
    codeChallengeMethod: requireString(value.codeChallengeMethod, `${fieldName}.codeChallengeMethod`),
    responseType: requireString(value.responseType, `${fieldName}.responseType`),
    responseMode: parseMaybeString(value.responseMode, `${fieldName}.responseMode`),
    prompt: parseMaybeString(value.prompt, `${fieldName}.prompt`),
    audience: parseMaybeString(value.audience, `${fieldName}.audience`),
    extraParams: normalizeExtraParams(value.extraParams as ExtraParamsInput),
  });
}

function normalizeTransactionStore(transactionStore: unknown): AuthorizationTransactionStore {
  const store = requirePlainObject(transactionStore, "transactionStore");
  if (typeof store.load !== "function") {
    throw new TypeError("transactionStore.load() is required");
  }
  if (typeof store.save !== "function") {
    throw new TypeError("transactionStore.save() is required");
  }
  if (typeof store.clear !== "function") {
    throw new TypeError("transactionStore.clear() is required");
  }
  return store as AuthorizationTransactionStore;
}

function normalizeSessionStore(sessionStore: unknown): FederatedSessionStore {
  const store = requirePlainObject(sessionStore, "sessionStore");
  if (typeof store.load !== "function") {
    throw new TypeError("sessionStore.load() is required");
  }
  if (typeof store.save !== "function") {
    throw new TypeError("sessionStore.save() is required");
  }
  if (typeof store.clear !== "function") {
    throw new TypeError("sessionStore.clear() is required");
  }
  return store as FederatedSessionStore;
}

function normalizeTokenResponse(tokenResponse: unknown, fieldName = "tokenResponse"): TokenResponseNormalized {
  const value = requirePlainObject(tokenResponse, fieldName);
  const accessToken = parseMaybeString(value.access_token ?? value.accessToken, `${fieldName}.access_token`);
  const refreshToken = parseMaybeString(value.refresh_token ?? value.refreshToken, `${fieldName}.refresh_token`);
  const idToken = parseMaybeString(value.id_token ?? value.idToken, `${fieldName}.id_token`);

  if (accessToken == null && refreshToken == null && idToken == null) {
    throw new Error(`${fieldName} must contain at least one token field`);
  }

  return Object.freeze({
    accessToken,
    refreshToken,
    idToken,
    tokenType: parseMaybeString(value.token_type ?? value.tokenType, `${fieldName}.token_type`),
    scope: parseMaybeString(value.scope, `${fieldName}.scope`),
    expiresIn: normalizePositiveInteger(value.expires_in ?? value.expiresIn ?? null, `${fieldName}.expires_in`),
    raw: Object.freeze({ ...value }),
  });
}

function normalizeSessionRecord(session: unknown, fieldName = "session"): FederatedSessionRecord {
  const value = requirePlainObject(session, fieldName);
  return Object.freeze({
    issuer: parseMaybeString(value.issuer, `${fieldName}.issuer`),
    subject: parseMaybeString(value.subject, `${fieldName}.subject`),
    clientId: requireString(value.clientId, `${fieldName}.clientId`),
    redirectUri: requireString(value.redirectUri, `${fieldName}.redirectUri`),
    scope: normalizeScope(value.scope as ScopeInput | undefined),
    state: requireString(value.state, `${fieldName}.state`),
    nonce: parseMaybeString(value.nonce, `${fieldName}.nonce`),
    authorizationCode: requireString(value.authorizationCode, `${fieldName}.authorizationCode`),
    accessToken: parseMaybeString(value.accessToken, `${fieldName}.accessToken`),
    refreshToken: parseMaybeString(value.refreshToken, `${fieldName}.refreshToken`),
    idToken: parseMaybeString(value.idToken, `${fieldName}.idToken`),
    tokenType: parseMaybeString(value.tokenType, `${fieldName}.tokenType`),
    tokenScope: parseMaybeString(value.tokenScope, `${fieldName}.tokenScope`),
    expiresIn: normalizePositiveInteger(value.expiresIn, `${fieldName}.expiresIn`),
    createdAt: requireString(value.createdAt, `${fieldName}.createdAt`),
    tokenResponse: Object.freeze({ ...requirePlainObject(value.tokenResponse ?? {}, `${fieldName}.tokenResponse`) }),
    extra: Object.freeze({ ...requirePlainObject(value.extra ?? {}, `${fieldName}.extra`) }),
  });
}

function normalizeIssuer(issuer: unknown, fieldName = "issuer"): string {
  const url = new URL(requireString(issuer, fieldName));
  const serialized = url.toString();
  if (!serialized.startsWith("https://") && !serialized.startsWith("http://")) {
    throw new TypeError(`${fieldName} must use http or https`);
  }
  return serialized.endsWith("/") ? serialized.slice(0, -1) : serialized;
}

function defaultDiscoveryEndpoint(issuer: unknown): string {
  const normalizedIssuer = normalizeIssuer(issuer);
  return `${normalizedIssuer}/.well-known/openid-configuration`;
}

function normalizeArrayOfStrings(value: unknown, fieldName: string): readonly string[] {
  if (!Array.isArray(value) || value.length === 0 || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new TypeError(`${fieldName} must be a non-empty string array`);
  }
  return Object.freeze([...value]);
}

function normalizeStringArray(
  value: unknown,
  fieldName: string,
  { allowEmpty = false }: { allowEmpty?: boolean | undefined } = {},
): readonly string[] {
  if (!Array.isArray(value) || (!allowEmpty && value.length === 0) || value.some((entry) => typeof entry !== "string" || entry.length === 0)) {
    throw new TypeError(`${fieldName} must be a ${allowEmpty ? "" : "non-empty "}string array`);
  }
  return Object.freeze([...value]);
}

export function normalizeIssuerMetadata(
  metadata: unknown,
  { expectedIssuer = null, requireAuthorizationCode = true }: NormalizeIssuerMetadataOptions = {},
): IssuerMetadata {
  const value = requirePlainObject(metadata, "metadata");
  const issuer = normalizeIssuer(value.issuer, "metadata.issuer");
  const normalizedExpectedIssuer = expectedIssuer == null ? null : normalizeIssuer(expectedIssuer, "expectedIssuer");
  if (normalizedExpectedIssuer != null && issuer !== normalizedExpectedIssuer) {
    throw new Error("issuer metadata issuer mismatch");
  }

  const authorizationEndpoint = normalizeUrlString(
    value.authorization_endpoint ?? value.authorizationEndpoint,
    "metadata.authorization_endpoint",
  );
  const tokenEndpoint = parseMaybeString(value.token_endpoint ?? value.tokenEndpoint, "metadata.token_endpoint");
  const endSessionEndpoint = parseMaybeString(value.end_session_endpoint ?? value.endSessionEndpoint, "metadata.end_session_endpoint");
  const jwksUri = parseMaybeString(value.jwks_uri ?? value.jwksUri, "metadata.jwks_uri");
  const responseTypesSupported = (value.response_types_supported ?? value.responseTypesSupported) == null
    ? Object.freeze([DEFAULT_RESPONSE_TYPE])
    : normalizeArrayOfStrings(value.response_types_supported ?? value.responseTypesSupported, "metadata.response_types_supported");
  const codeChallengeMethodsSupported = (value.code_challenge_methods_supported ?? value.codeChallengeMethodsSupported) == null
    ? Object.freeze([DEFAULT_CODE_CHALLENGE_METHOD])
    : normalizeArrayOfStrings(value.code_challenge_methods_supported ?? value.codeChallengeMethodsSupported, "metadata.code_challenge_methods_supported");
  const scopesSupported = (value.scopes_supported ?? value.scopesSupported) == null
    ? Object.freeze([DEFAULT_SCOPE])
    : normalizeArrayOfStrings(value.scopes_supported ?? value.scopesSupported, "metadata.scopes_supported");
  const subjectTypesSupported = (value.subject_types_supported ?? value.subjectTypesSupported) == null
    ? Object.freeze(["public"])
    : normalizeArrayOfStrings(value.subject_types_supported ?? value.subjectTypesSupported, "metadata.subject_types_supported");
  const idTokenSigningAlgValuesSupported = (value.id_token_signing_alg_values_supported ?? value.idTokenSigningAlgValuesSupported) == null
    ? Object.freeze([])
    : normalizeStringArray(
      value.id_token_signing_alg_values_supported ?? value.idTokenSigningAlgValuesSupported,
      "metadata.id_token_signing_alg_values_supported",
      { allowEmpty: true },
    );

  if (requireAuthorizationCode && !responseTypesSupported.includes(DEFAULT_RESPONSE_TYPE)) {
    throw new Error("issuer metadata must support response_type=code");
  }
  if (!codeChallengeMethodsSupported.includes(DEFAULT_CODE_CHALLENGE_METHOD)) {
    throw new Error("issuer metadata must support PKCE S256");
  }

  return Object.freeze({
    issuer,
    authorizationEndpoint,
    tokenEndpoint: tokenEndpoint == null ? null : normalizeUrlString(tokenEndpoint, "metadata.token_endpoint"),
    jwksUri: jwksUri == null ? null : normalizeUrlString(jwksUri, "metadata.jwks_uri"),
    endSessionEndpoint: endSessionEndpoint == null ? null : normalizeUrlString(endSessionEndpoint, "metadata.end_session_endpoint"),
    responseTypesSupported,
    codeChallengeMethodsSupported,
    scopesSupported,
    subjectTypesSupported,
    idTokenSigningAlgValuesSupported,
    raw: Object.freeze({ ...value }),
  });
}

export async function fetchIssuerMetadata({
  issuer,
  discoveryUrl = null,
  fetch: fetchImpl = globalThis.fetch,
  signal = undefined,
  expectedIssuer = null,
  requireAuthorizationCode = true,
  headers = {},
}: FetchIssuerMetadataOptions = {}): Promise<IssuerMetadata> {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetch must be a function");
  }
  const normalizedIssuer = normalizeIssuer(issuer, "issuer");
  const resolvedDiscoveryUrl = discoveryUrl == null
    ? defaultDiscoveryEndpoint(normalizedIssuer)
    : normalizeUrlString(discoveryUrl, "discoveryUrl");
  const requestInit: RequestInit = {
    method: "GET",
    headers: {
      accept: "application/json",
      ...headers,
    },
  };
  if (signal != null) {
    requestInit.signal = signal;
  }
  const response = await fetchImpl(resolvedDiscoveryUrl, requestInit);
  if (!response || typeof response.ok !== "boolean") {
    throw new Error("issuer metadata fetch did not return a Response-like object");
  }
  if (!response.ok) {
    throw new Error(`issuer metadata fetch failed with status ${response.status}`);
  }
  const payload = await response.json();
  return normalizeIssuerMetadata(payload, {
    expectedIssuer: expectedIssuer ?? normalizedIssuer,
    requireAuthorizationCode,
  });
}

export function buildAuthorizationUrlFromIssuerMetadata({
  issuerMetadata,
  ...options
}: IssuerMetadataOptions & AuthorizationUrlOptions = {}): string {
  const metadata = normalizeIssuerMetadata(issuerMetadata);
  return buildAuthorizationUrl({
    authorizationEndpoint: metadata.authorizationEndpoint,
    ...options,
  });
}

export async function buildPkceAuthorizationRequestFromIssuerMetadata({
  issuerMetadata,
  ...options
}: BuildPkceAuthorizationFromIssuerMetadataOptions = {}) {
  const metadata = normalizeIssuerMetadata(issuerMetadata);
  return buildPkceAuthorizationRequest({
    authorizationEndpoint: metadata.authorizationEndpoint,
    ...options,
  });
}

export async function buildPkceAuthorizationTransactionFromIssuerMetadata({
  issuerMetadata,
  ...options
}: BuildPkceAuthorizationFromIssuerMetadataOptions = {}) {
  const metadata = normalizeIssuerMetadata(issuerMetadata);
  return buildPkceAuthorizationTransaction({
    authorizationEndpoint: metadata.authorizationEndpoint,
    ...options,
  });
}

export async function startFederatedLoginFromIssuerMetadata({
  issuerMetadata,
  ...options
}: StartFederatedLoginFromIssuerMetadataOptions = {}) {
  const metadata = normalizeIssuerMetadata(issuerMetadata);
  return startFederatedLogin({
    authorizationEndpoint: metadata.authorizationEndpoint,
    ...options,
  });
}

export function buildEndSessionUrlFromIssuerMetadata({
  issuerMetadata,
  idTokenHint,
  postLogoutRedirectUri = null,
  state = null,
  clientId = null,
  extraParams = {},
}: BuildEndSessionUrlFromIssuerMetadataOptions = {}): string {
  const metadata = normalizeIssuerMetadata(issuerMetadata, { requireAuthorizationCode: false });
  if (metadata.endSessionEndpoint == null) {
    throw new Error("issuer metadata does not advertise end_session_endpoint");
  }
  return buildEndSessionUrl({
    endSessionEndpoint: metadata.endSessionEndpoint,
    idTokenHint,
    postLogoutRedirectUri,
    state,
    clientId,
    extraParams,
  });
}

function buildTransactionRecord({
  clientId,
  redirectUri,
  scope,
  state,
  nonce,
  verifier,
  codeChallenge,
  codeChallengeMethod,
  responseType,
  responseMode,
  prompt,
  audience,
  extraParams,
}: {
  clientId: string;
  redirectUri: string;
  scope: ScopeInput;
  state: string;
  nonce: OptionalString;
  verifier: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  responseType: string;
  responseMode: OptionalString;
  prompt: OptionalString;
  audience: OptionalString;
  extraParams: ExtraParamsInput;
}): AuthorizationTransaction {
  return normalizeTransaction({
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    verifier,
    codeChallenge,
    codeChallengeMethod,
    responseType,
    responseMode,
    prompt,
    audience,
    extraParams,
  });
}

export function buildAuthorizationParameters({
  clientId,
  redirectUri,
  scope = DEFAULT_SCOPE,
  state,
  nonce,
  codeChallenge,
  codeChallengeMethod = DEFAULT_CODE_CHALLENGE_METHOD,
  responseMode = null,
  prompt = null,
  audience = null,
  responseType = DEFAULT_RESPONSE_TYPE,
  extraParams = {},
}: AuthorizationParameterOptions = {}): URLSearchParams {
  const normalizedScope = normalizeScope(scope);
  const params = new URLSearchParams();
  params.set("client_id", requireString(clientId, "clientId"));
  params.set("redirect_uri", requireString(redirectUri, "redirectUri"));
  params.set("response_type", requireString(responseType, "responseType"));
  params.set("scope", normalizedScope);
  params.set("state", requireString(state, "state"));
  params.set("code_challenge", requireString(codeChallenge, "codeChallenge"));
  params.set("code_challenge_method", requireString(codeChallengeMethod, "codeChallengeMethod"));

  if (normalizedScope.split(/\s+/).includes("openid")) {
    params.set("nonce", requireString(nonce, "nonce"));
  } else {
    appendOptional(params, "nonce", nonce);
  }

  appendOptional(params, "response_mode", responseMode);
  appendOptional(params, "prompt", prompt);
  appendOptional(params, "audience", audience);
  appendExtraParams(params, extraParams);
  return params;
}

export function buildAuthorizationUrl({
  authorizationEndpoint,
  ...options
}: AuthorizationUrlOptions = {}): string {
  const url = new URL(requireString(authorizationEndpoint, "authorizationEndpoint"));
  url.search = buildAuthorizationParameters(options).toString();
  return url.toString();
}

export async function buildPkceAuthorizationRequest({
  runtimeHandle,
  authorizationEndpoint,
  clientId,
  redirectUri,
  verifier,
  scope = DEFAULT_SCOPE,
  state,
  nonce,
  responseMode = null,
  prompt = null,
  audience = null,
  responseType = DEFAULT_RESPONSE_TYPE,
  extraParams = {},
}: PkceAuthorizationRequestOptions = {}): Promise<PkceAuthorizationRequestResult> {
  const handle = normalizeRuntimeHandle(runtimeHandle);
  const pkceResult = await handle.pkceGenerate({
    verifier: requireString(verifier, "verifier"),
  });
  if (!pkceResult || pkceResult.statusCode !== VERIFIED_CORE_OK || typeof pkceResult.challenge !== "string") {
    throw new Error("pkceGenerate failed");
  }

  const authorizationParameters = buildAuthorizationParameters({
    clientId,
    redirectUri,
    scope,
    state,
    nonce,
    codeChallenge: pkceResult.challenge,
    codeChallengeMethod: DEFAULT_CODE_CHALLENGE_METHOD,
    responseMode,
    prompt,
    audience,
    responseType,
    extraParams,
  });

  return {
    verifier: requireString(verifier, "verifier"),
    codeChallenge: pkceResult.challenge,
    authorizationParameters,
    authorizationUrl: buildAuthorizationUrl({
      authorizationEndpoint,
      clientId,
      redirectUri,
      scope,
      state,
      nonce,
      codeChallenge: pkceResult.challenge,
      codeChallengeMethod: DEFAULT_CODE_CHALLENGE_METHOD,
      responseMode,
      prompt,
      audience,
      responseType,
      extraParams,
    }),
  };
}

export async function buildPkceAuthorizationTransaction({
  runtimeHandle,
  authorizationEndpoint,
  clientId,
  redirectUri,
  verifier,
  scope = DEFAULT_SCOPE,
  state,
  nonce,
  responseMode = null,
  prompt = null,
  audience = null,
  responseType = DEFAULT_RESPONSE_TYPE,
  extraParams = {},
}: PkceAuthorizationRequestOptions = {}): Promise<PkceAuthorizationTransactionResult> {
  const normalizedScope = normalizeScope(scope);
  const request = await buildPkceAuthorizationRequest({
    runtimeHandle,
    authorizationEndpoint,
    clientId,
    redirectUri,
    verifier,
    scope: normalizedScope,
    state,
    nonce,
    responseMode,
    prompt,
    audience,
    responseType,
    extraParams,
  });
  return {
    ...request,
    transaction: buildTransactionRecord({
      clientId: requireString(clientId, "clientId"),
      redirectUri: requireString(redirectUri, "redirectUri"),
      scope: normalizedScope,
      state: requireString(state, "state"),
      nonce: normalizedScope.split(/\s+/).includes("openid") ? requireString(nonce, "nonce") : (nonce ?? null),
      verifier: requireString(verifier, "verifier"),
      codeChallenge: request.codeChallenge,
      codeChallengeMethod: DEFAULT_CODE_CHALLENGE_METHOD,
      responseType: requireString(responseType, "responseType"),
      responseMode,
      prompt,
      audience,
      extraParams,
    }),
  };
}

export function createInMemoryAuthorizationTransactionStore({
  initialTransaction = null,
}: CreateAuthorizationTransactionStoreOptions = {}): AuthorizationTransactionStore {
  let currentTransaction = initialTransaction == null ? null : normalizeTransaction(initialTransaction, "initialTransaction");
  return {
    async load() {
      return currentTransaction;
    },
    async save(transaction) {
      currentTransaction = normalizeTransaction(transaction);
      return currentTransaction;
    },
    async clear() {
      currentTransaction = null;
    },
  };
}

export async function restoreAuthorizationTransaction({
  transactionStore,
  required = false,
}: RestoreAuthorizationTransactionOptions = {}): Promise<AuthorizationTransaction | null> {
  const store = normalizeTransactionStore(transactionStore);
  const transaction = await store.load();
  if (transaction == null) {
    if (required) {
      throw new Error("authorization transaction not found");
    }
    return null;
  }
  return normalizeTransaction(transaction);
}

export async function clearAuthorizationTransaction({
  transactionStore,
}: ClearAuthorizationTransactionOptions = {}): Promise<void> {
  const store = normalizeTransactionStore(transactionStore);
  await store.clear();
}

export async function startFederatedLogin({
  transactionStore,
  ...options
}: StartFederatedLoginOptions = {}): Promise<StartFederatedLoginResult> {
  const store = normalizeTransactionStore(transactionStore);
  const request = await buildPkceAuthorizationTransaction(options);
  const transaction = normalizeTransaction(await store.save(request.transaction), "transactionStore.save");
  return {
    ...request,
    redirectUrl: request.authorizationUrl,
    transaction,
  };
}

export function buildTokenRequestBody({
  code,
  redirectUri,
  clientId,
  codeVerifier,
  grantType = "authorization_code",
  extraParams = {},
}: BuildTokenRequestBodyOptions = {}): URLSearchParams {
  const params = new URLSearchParams();
  params.set("grant_type", requireString(grantType, "grantType"));
  params.set("code", requireString(code, "code"));
  params.set("redirect_uri", requireString(redirectUri, "redirectUri"));
  params.set("client_id", requireString(clientId, "clientId"));
  params.set("code_verifier", requireString(codeVerifier, "codeVerifier"));
  appendExtraParams(params, extraParams);
  return params;
}

export function parseAuthorizationResponse(input: AuthorizationResponseInput): AuthorizationResponse {
  let params;
  if (input instanceof URLSearchParams) {
    params = input;
  } else if (input instanceof URL) {
    params = input.searchParams;
  } else if (typeof input === "string") {
    params = new URL(input, "https://rp.invalid/callback").searchParams;
  } else if (input && typeof input === "object") {
    params = new URLSearchParams(
      Object.entries(requirePlainObject(input, "input")).flatMap(([key, value]) =>
        typeof value === "string" ? [[key, value] as [string, string]] : [],
      ),
    );
  } else {
    throw new TypeError("input must be a string, URL, URLSearchParams, or plain object");
  }

  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");
  const errorDescription = params.get("error_description");
  const errorUri = params.get("error_uri");

  if (code && error) {
    throw new Error("authorization response may not contain both code and error");
  }

  return {
    code,
    state,
    error,
    errorDescription,
    errorUri,
  };
}

export function validateAuthorizationResponse({
  input,
  expectedState = null,
  requireCode = true,
}: {
  input?: AuthorizationResponseInput | undefined;
  expectedState?: OptionalString;
  requireCode?: boolean | undefined;
} = {}): AuthorizationResponse {
  const response = parseAuthorizationResponse(input ?? {});
  if (response.error) {
    throw new Error(`authorization response returned error ${response.error}`);
  }
  if (expectedState != null && response.state !== expectedState) {
    throw new Error("authorization response state mismatch");
  }
  if (requireCode && !response.code) {
    throw new Error("authorization response missing code");
  }
  return response;
}

export function buildTokenRequestFromAuthorizationResponse({
  input,
  transaction,
  grantType = "authorization_code",
  extraParams = {},
}: BuildTokenRequestFromAuthorizationResponseOptions = {}): BuildTokenRequestFromAuthorizationResponseResult {
  const normalizedTransaction = normalizeTransaction(transaction);
  const response = validateAuthorizationResponse({
    input,
    expectedState: normalizedTransaction.state ?? null,
    requireCode: true,
  });
  return {
    response,
    tokenRequestBody: buildTokenRequestBody({
      code: requireString(response.code, "authorizationResponse.code"),
      redirectUri: normalizedTransaction.redirectUri,
      clientId: normalizedTransaction.clientId,
      codeVerifier: normalizedTransaction.verifier,
      grantType,
      extraParams,
    }),
    transaction: normalizedTransaction,
  };
}

export function createInMemoryFederatedSessionStore({
  initialSession = null,
}: CreateFederatedSessionStoreOptions = {}): FederatedSessionStore {
  let currentSession = initialSession == null ? null : normalizeSessionRecord(initialSession, "initialSession");
  return {
    async load() {
      return currentSession;
    },
    async save(session) {
      currentSession = normalizeSessionRecord(session);
      return currentSession;
    },
    async clear() {
      currentSession = null;
    },
  };
}

export async function restoreFederatedSession({
  sessionStore,
  required = false,
}: RestoreFederatedSessionOptions = {}): Promise<FederatedSessionRecord | null> {
  const store = normalizeSessionStore(sessionStore);
  const session = await store.load();
  if (session == null) {
    if (required) {
      throw new Error("federated session not found");
    }
    return null;
  }
  return normalizeSessionRecord(session);
}

export async function clearFederatedSession({
  sessionStore,
}: ClearFederatedSessionOptions = {}): Promise<void> {
  const store = normalizeSessionStore(sessionStore);
  await store.clear();
}

export function buildFederatedSessionRecord({
  transaction,
  authorizationResponse,
  tokenResponse,
  issuer = null,
  subject = null,
  createdAt = new Date().toISOString(),
  extra = {},
}: BuildFederatedSessionRecordOptions = {}): FederatedSessionRecord {
  const normalizedTransaction = normalizeTransaction(transaction);
  const normalizedAuthorizationResponse = requirePlainObject(authorizationResponse, "authorizationResponse");
  const normalizedTokenResponse = normalizeTokenResponse(tokenResponse);
  const normalizedExtra = extra == null ? {} : requirePlainObject(extra, "extra");

  return normalizeSessionRecord({
    issuer,
    subject,
    clientId: normalizedTransaction.clientId,
    redirectUri: normalizedTransaction.redirectUri,
    scope: normalizedTransaction.scope,
    state: normalizedTransaction.state,
    nonce: normalizedTransaction.nonce,
    authorizationCode: requireString(normalizedAuthorizationResponse.code, "authorizationResponse.code"),
    accessToken: normalizedTokenResponse.accessToken,
    refreshToken: normalizedTokenResponse.refreshToken,
    idToken: normalizedTokenResponse.idToken,
    tokenType: normalizedTokenResponse.tokenType,
    tokenScope: normalizedTokenResponse.scope,
    expiresIn: normalizedTokenResponse.expiresIn,
    createdAt: requireString(createdAt, "createdAt"),
    tokenResponse: normalizedTokenResponse.raw,
    extra: normalizedExtra,
  });
}

export async function finishFederatedLogin({
  input,
  transactionStore,
  exchangeAuthorizationCode,
  sessionStore = null,
  clearTransaction = true,
  grantType = "authorization_code",
  extraParams = {},
  issuer = null,
  subject = null,
  sessionExtra = {},
}: FinishFederatedLoginOptions = {}): Promise<FinishFederatedLoginResult> {
  const store = normalizeTransactionStore(transactionStore);
  const exchange = buildTokenRequestFromAuthorizationResponse({
    input,
    transaction: await restoreAuthorizationTransaction({
      transactionStore: store,
      required: true,
    }),
    grantType,
    extraParams,
  });

  if (typeof exchangeAuthorizationCode !== "function") {
    throw new TypeError("exchangeAuthorizationCode must be a function");
  }

  const tokenResponse = normalizeTokenResponse(await exchangeAuthorizationCode({
    tokenRequestBody: exchange.tokenRequestBody,
    authorizationResponse: exchange.response,
    transaction: exchange.transaction,
  }));

  let session: FederatedSessionRecord | null = null;
  if (sessionStore != null) {
    const normalizedSessionStore = normalizeSessionStore(sessionStore);
    session = normalizeSessionRecord(
      await normalizedSessionStore.save(
        buildFederatedSessionRecord({
          transaction: exchange.transaction,
          authorizationResponse: exchange.response,
          tokenResponse,
          issuer,
          subject,
          extra: sessionExtra,
        }),
      ),
      "sessionStore.save",
    );
  }

  if (clearTransaction) {
    await store.clear();
  }

  return {
    ...exchange,
    tokenResponse,
    session,
  };
}

export function buildEndSessionUrl({
  endSessionEndpoint,
  idTokenHint,
  postLogoutRedirectUri = null,
  state = null,
  clientId = null,
  extraParams = {},
}: BuildEndSessionUrlOptions = {}): string {
  const url = new URL(requireString(endSessionEndpoint, "endSessionEndpoint"));
  const params = new URLSearchParams();
  params.set("id_token_hint", requireString(idTokenHint, "idTokenHint"));
  appendOptional(params, "post_logout_redirect_uri", postLogoutRedirectUri);
  appendOptional(params, "state", state);
  appendOptional(params, "client_id", clientId);
  appendExtraParams(params, extraParams);
  url.search = params.toString();
  return url.toString();
}

export const RP_DEFAULTS = Object.freeze({
  scope: DEFAULT_SCOPE,
  responseType: DEFAULT_RESPONSE_TYPE,
  codeChallengeMethod: DEFAULT_CODE_CHALLENGE_METHOD,
});
