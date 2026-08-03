import {
  CLIENT_CRYPTO_PROFILES,
  DEFAULT_CLIENT_CRYPTO_PROFILE,
  initCore as initIssuerSpaRuntime,
} from "@aegaeon/runtime-web";
import {
  buildEndSessionUrlFromIssuerMetadata,
  buildFederatedSessionRecord,
  buildEndSessionUrl,
  buildPkceAuthorizationTransaction,
  buildTokenRequestFromAuthorizationResponse,
  createInMemoryFederatedSessionStore,
  fetchIssuerMetadata as fetchFederatedIssuerMetadata,
  finishFederatedLogin,
  restoreFederatedSession,
  startFederatedLoginFromIssuerMetadata as startRpFederatedLoginFromIssuerMetadata,
} from "@aegaeon/rp-core";

const DEFAULT_TRANSACTION_STORAGE_KEY = "aegaeon.issuer-spa.transaction";
const DEFAULT_SESSION_STORAGE_KEY = "aegaeon.issuer-spa.session";

type PlainObject = Record<string, unknown>;
type OptionalString = string | null | undefined;
type ExtraParamsInput = Record<string, string> | null | undefined;
type ExtraParams = Readonly<Record<string, string>>;
type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;
type RuntimeHandleInput = NonNullable<
  NonNullable<Parameters<typeof buildPkceAuthorizationTransaction>[0]>["runtimeHandle"]
>;
type AuthorizationTransaction = Awaited<
  ReturnType<typeof buildPkceAuthorizationTransaction>
>["transaction"];
type SessionRecord = ReturnType<typeof buildFederatedSessionRecord>;
type MaybePromise<T> = T | Promise<T>;
type TransactionStore = {
  load(): MaybePromise<unknown>;
  save(transaction: unknown): MaybePromise<unknown>;
  clear(): MaybePromise<void>;
};
type SessionStore = {
  load(): MaybePromise<unknown>;
  save(session: unknown): MaybePromise<unknown>;
  clear(): MaybePromise<void>;
};
type AuthorizationResponseInput = string | URL | URLSearchParams | PlainObject;
type ExchangeAuthorizationCode = NonNullable<
  NonNullable<Parameters<typeof finishFederatedLogin>[0]>["exchangeAuthorizationCode"]
>;
type RestoreLoginTransactionOptions = {
  transactionStore?: unknown;
  required?: boolean;
};
type ClearLoginTransactionOptions = {
  transactionStore?: unknown;
};
type RestoreLoginSessionOptions = {
  sessionStore?: unknown;
  required?: boolean;
};
type ClearLoginSessionOptions = {
  sessionStore?: unknown;
};
type StartLoginOptions = {
  runtimeHandle?: RuntimeHandleInput;
  transactionStore?: unknown;
  authorizationEndpoint?: string;
  clientId?: string;
  redirectUri?: string;
  verifier?: string;
  scope?: string | readonly string[];
  state?: string;
  nonce?: OptionalString;
  responseMode?: OptionalString;
  prompt?: OptionalString;
  audience?: OptionalString;
  responseType?: string;
  extraParams?: ExtraParamsInput;
};
type FetchIssuerMetadataOptions = {
  issuer?: string;
  discoveryUrl?: OptionalString;
  fetch?: typeof globalThis.fetch;
  signal?: AbortSignal | null;
  expectedIssuer?: OptionalString;
  requireAuthorizationCode?: boolean;
  headers?: Record<string, string>;
};
type StartLoginFromIssuerMetadataOptions = Omit<StartLoginOptions, "authorizationEndpoint"> & {
  issuerMetadata?: unknown;
};
type StartLoginWithDiscoveryOptions = Omit<StartLoginFromIssuerMetadataOptions, "issuerMetadata"> &
  FetchIssuerMetadataOptions;
type FinishLoginOptions = {
  input?: AuthorizationResponseInput;
  transactionStore?: unknown;
  clearTransaction?: boolean;
  grantType?: string;
  extraParams?: ExtraParamsInput;
};
type PersistLoginSessionOptions = {
  sessionStore?: unknown;
  transaction?: unknown;
  authorizationResponse?: unknown;
  tokenResponse?: unknown;
  issuer?: OptionalString;
  subject?: OptionalString;
  createdAt?: string;
  extra?: PlainObject | null;
};
type CompleteLoginOptions = FinishLoginOptions & {
  sessionStore?: unknown | null;
  exchangeAuthorizationCode?: ExchangeAuthorizationCode;
  issuer?: OptionalString;
  subject?: OptionalString;
  sessionExtra?: PlainObject | null;
};
type BuildLogoutUrlOptions = {
  endSessionEndpoint?: string;
  idTokenHint?: string;
  postLogoutRedirectUri?: OptionalString;
  state?: OptionalString;
  clientId?: OptionalString;
  extraParams?: ExtraParamsInput;
};
type BuildLogoutUrlFromIssuerMetadataOptions = Omit<
  BuildLogoutUrlOptions,
  "endSessionEndpoint"
> & {
  issuerMetadata?: unknown;
};

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

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

function parseMaybeString(value: unknown, fieldName: string): string | null {
  if (value == null) {
    return null;
  }
  return requireString(value, fieldName);
}

function normalizeOptionalNumber(value: unknown, fieldName: string): number | null {
  if (value == null) {
    return null;
  }
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new TypeError(`${fieldName} must be a finite number`);
  }
  return value;
}

function normalizeOptionalPlainObject(value: unknown, fieldName: string): PlainObject {
  if (value == null) {
    return {};
  }
  return requirePlainObject(value, fieldName);
}

function normalizeExtraParams(extraParams: ExtraParamsInput = {}): ExtraParams {
  if (extraParams == null) {
    return Object.freeze({});
  }
  if (!extraParams || typeof extraParams !== "object" || Array.isArray(extraParams)) {
    throw new TypeError("extraParams must be a plain object when provided");
  }
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(extraParams)) {
    normalized[requireString(key, "extraParams key")] = requireString(value, `extraParams.${key}`);
  }
  return Object.freeze(normalized);
}

function normalizeTransaction(
  transaction: unknown,
  fieldName = "transaction",
): AuthorizationTransaction {
  const record = requirePlainObject(transaction, fieldName);
  return Object.freeze({
    clientId: requireString(record.clientId, `${fieldName}.clientId`),
    redirectUri: requireString(record.redirectUri, `${fieldName}.redirectUri`),
    scope: requireString(record.scope, `${fieldName}.scope`),
    state: requireString(record.state, `${fieldName}.state`),
    nonce: parseMaybeString(record.nonce, `${fieldName}.nonce`),
    verifier: requireString(record.verifier, `${fieldName}.verifier`),
    codeChallenge: requireString(record.codeChallenge, `${fieldName}.codeChallenge`),
    codeChallengeMethod: requireString(record.codeChallengeMethod, `${fieldName}.codeChallengeMethod`),
    responseType: requireString(record.responseType, `${fieldName}.responseType`),
    responseMode: parseMaybeString(record.responseMode, `${fieldName}.responseMode`),
    prompt: parseMaybeString(record.prompt, `${fieldName}.prompt`),
    audience: parseMaybeString(record.audience, `${fieldName}.audience`),
    extraParams: normalizeExtraParams(record.extraParams as ExtraParamsInput),
  });
}

function requireTransactionStore(transactionStore: unknown): TransactionStore {
  if (!transactionStore || typeof transactionStore !== "object") {
    throw new TypeError("transactionStore must be an object");
  }
  const record = transactionStore as Record<string, unknown>;
  if (typeof record.load !== "function") {
    throw new TypeError("transactionStore.load() is required");
  }
  if (typeof record.save !== "function") {
    throw new TypeError("transactionStore.save() is required");
  }
  if (typeof record.clear !== "function") {
    throw new TypeError("transactionStore.clear() is required");
  }
  return transactionStore as TransactionStore;
}

function requireSessionStore(sessionStore: unknown): SessionStore {
  if (!sessionStore || typeof sessionStore !== "object") {
    throw new TypeError("sessionStore must be an object");
  }
  const record = sessionStore as Record<string, unknown>;
  if (typeof record.load !== "function") {
    throw new TypeError("sessionStore.load() is required");
  }
  if (typeof record.save !== "function") {
    throw new TypeError("sessionStore.save() is required");
  }
  if (typeof record.clear !== "function") {
    throw new TypeError("sessionStore.clear() is required");
  }
  return sessionStore as SessionStore;
}

function requireStorageLike(storage: unknown): StorageLike {
  if (!storage || typeof storage !== "object") {
    throw new TypeError("storage must be an object");
  }
  const record = storage as Record<string, unknown>;
  if (typeof record.getItem !== "function" || typeof record.setItem !== "function" || typeof record.removeItem !== "function") {
    throw new TypeError("storage must expose getItem(), setItem(), and removeItem()");
  }
  return storage as StorageLike;
}

export function createInMemoryTransactionStore({
  initialTransaction = null,
}: {
  initialTransaction?: unknown | null;
} = {}): TransactionStore {
  let currentTransaction =
    initialTransaction == null ? null : normalizeTransaction(initialTransaction, "initialTransaction");
  return {
    async load() {
      return currentTransaction;
    },
    async save(transaction: unknown) {
      currentTransaction = normalizeTransaction(transaction);
      return currentTransaction;
    },
    async clear() {
      currentTransaction = null;
    },
  };
}

export function createSessionStorageTransactionStore({
  storage = globalThis.sessionStorage,
  key = DEFAULT_TRANSACTION_STORAGE_KEY,
}: {
  storage?: StorageLike;
  key?: string;
} = {}): TransactionStore {
  const normalizedStorage = requireStorageLike(storage);
  const storageKey = requireString(key, "key");
  return {
    async load() {
      const serialized = normalizedStorage.getItem(storageKey);
      if (serialized == null) {
        return null;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(serialized);
      } catch (error) {
        throw new Error(`stored transaction at ${storageKey} is not valid JSON: ${errorMessage(error)}`);
      }
      return normalizeTransaction(parsed, `stored transaction ${storageKey}`);
    },
    async save(transaction: unknown) {
      const normalized = normalizeTransaction(transaction);
      normalizedStorage.setItem(storageKey, JSON.stringify(normalized));
      return normalized;
    },
    async clear() {
      normalizedStorage.removeItem(storageKey);
    },
  };
}

function normalizeSession(session: unknown, fieldName = "session"): SessionRecord {
  const record = requirePlainObject(session, fieldName);
  return Object.freeze({
    issuer: parseMaybeString(record.issuer, `${fieldName}.issuer`),
    subject: parseMaybeString(record.subject, `${fieldName}.subject`),
    clientId: requireString(record.clientId, `${fieldName}.clientId`),
    redirectUri: requireString(record.redirectUri, `${fieldName}.redirectUri`),
    scope: requireString(record.scope, `${fieldName}.scope`),
    state: requireString(record.state, `${fieldName}.state`),
    nonce: parseMaybeString(record.nonce, `${fieldName}.nonce`),
    authorizationCode: requireString(record.authorizationCode, `${fieldName}.authorizationCode`),
    accessToken: parseMaybeString(record.accessToken, `${fieldName}.accessToken`),
    refreshToken: parseMaybeString(record.refreshToken, `${fieldName}.refreshToken`),
    idToken: parseMaybeString(record.idToken, `${fieldName}.idToken`),
    tokenType: parseMaybeString(record.tokenType, `${fieldName}.tokenType`),
    tokenScope: parseMaybeString(record.tokenScope, `${fieldName}.tokenScope`),
    expiresIn: normalizeOptionalNumber(record.expiresIn, `${fieldName}.expiresIn`),
    createdAt: requireString(record.createdAt, `${fieldName}.createdAt`),
    tokenResponse: Object.freeze(
      { ...normalizeOptionalPlainObject(record.tokenResponse, `${fieldName}.tokenResponse`) },
    ),
    extra: Object.freeze({ ...normalizeOptionalPlainObject(record.extra, `${fieldName}.extra`) }),
  });
}

export function createInMemorySessionStore({
  initialSession = null,
}: {
  initialSession?: unknown | null;
} = {}): SessionStore {
  return createInMemoryFederatedSessionStore({ initialSession });
}

export function createSessionStorageSessionStore({
  storage = globalThis.sessionStorage,
  key = DEFAULT_SESSION_STORAGE_KEY,
}: {
  storage?: StorageLike;
  key?: string;
} = {}): SessionStore {
  const normalizedStorage = requireStorageLike(storage);
  const storageKey = requireString(key, "key");
  return {
    async load() {
      const serialized = normalizedStorage.getItem(storageKey);
      if (serialized == null) {
        return null;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(serialized);
      } catch (error) {
        throw new Error(`stored session at ${storageKey} is not valid JSON: ${errorMessage(error)}`);
      }
      return normalizeSession(parsed, `stored session ${storageKey}`);
    },
    async save(session: unknown) {
      const normalized = normalizeSession(session);
      normalizedStorage.setItem(storageKey, JSON.stringify(normalized));
      return normalized;
    },
    async clear() {
      normalizedStorage.removeItem(storageKey);
    },
  };
}

export async function restoreLoginTransaction({
  transactionStore,
  required = false,
}: RestoreLoginTransactionOptions = {}): Promise<AuthorizationTransaction | null> {
  const store = requireTransactionStore(transactionStore);
  const transaction = await store.load();
  if (transaction == null) {
    if (required) {
      throw new Error("login transaction not found");
    }
    return null;
  }
  return normalizeTransaction(transaction);
}

export async function clearLoginTransaction({
  transactionStore,
}: ClearLoginTransactionOptions = {}): Promise<void> {
  const store = requireTransactionStore(transactionStore);
  await store.clear();
}

export async function restoreLoginSession({
  sessionStore,
  required = false,
}: RestoreLoginSessionOptions = {}): Promise<SessionRecord | null> {
  const store = requireSessionStore(sessionStore);
  const session = await restoreFederatedSession({
    sessionStore: store,
    required,
  });
  if (session == null) {
    return null;
  }
  return normalizeSession(session);
}

export async function clearLoginSession({
  sessionStore,
}: ClearLoginSessionOptions = {}): Promise<void> {
  const store = requireSessionStore(sessionStore);
  await store.clear();
}

export async function startLogin({
  runtimeHandle,
  transactionStore,
  authorizationEndpoint,
  clientId,
  redirectUri,
  verifier,
  scope = "openid",
  state,
  nonce,
  responseMode = null,
  prompt = null,
  audience = null,
  responseType = "code",
  extraParams = {},
}: StartLoginOptions = {}): Promise<{
  redirectUrl: string;
  transaction: AuthorizationTransaction;
  verifier: string;
  codeChallenge: string;
  authorizationParameters: URLSearchParams;
  authorizationUrl: string;
}> {
  const store = requireTransactionStore(transactionStore);
  const request = await buildPkceAuthorizationTransaction({
    runtimeHandle,
    authorizationEndpoint,
    clientId,
    redirectUri,
    verifier,
    scope,
    state,
    nonce,
    responseMode,
    prompt,
    audience,
    responseType,
    extraParams,
  });
  const transaction = await store.save(request.transaction);
  return {
    ...request,
    redirectUrl: request.authorizationUrl,
    transaction: normalizeTransaction(transaction, "stored transaction"),
  };
}

export async function fetchIssuerMetadata({
  issuer,
  discoveryUrl = null,
  fetch = globalThis.fetch,
  signal = undefined,
  expectedIssuer = null,
  requireAuthorizationCode = true,
  headers = {},
}: FetchIssuerMetadataOptions = {}): Promise<Awaited<ReturnType<typeof fetchFederatedIssuerMetadata>>> {
  return fetchFederatedIssuerMetadata({
    ...(issuer === undefined ? {} : { issuer }),
    discoveryUrl,
    fetch,
    signal,
    expectedIssuer,
    requireAuthorizationCode,
    headers,
  });
}

export async function startLoginFromIssuerMetadata({
  transactionStore,
  issuerMetadata,
  ...options
}: StartLoginFromIssuerMetadataOptions = {}): Promise<{
  redirectUrl: string;
  transaction: AuthorizationTransaction;
  verifier: string;
  codeChallenge: string;
  authorizationParameters: URLSearchParams;
  authorizationUrl: string;
}> {
  const store = requireTransactionStore(transactionStore);
  const request = await startRpFederatedLoginFromIssuerMetadata({
    issuerMetadata,
    transactionStore: store,
    ...options,
  });
  return {
    ...request,
    redirectUrl: request.authorizationUrl,
    transaction: request.transaction,
  };
}

export async function startLoginWithDiscovery({
  issuer,
  discoveryUrl = null,
  fetch = globalThis.fetch,
  signal = undefined,
  expectedIssuer = null,
  requireAuthorizationCode = true,
  headers = {},
  ...options
}: StartLoginWithDiscoveryOptions = {}): Promise<{
  issuerMetadata: Awaited<ReturnType<typeof fetchFederatedIssuerMetadata>>;
  redirectUrl: string;
  transaction: AuthorizationTransaction;
  verifier: string;
  codeChallenge: string;
  authorizationParameters: URLSearchParams;
  authorizationUrl: string;
}> {
  const issuerMetadata = await fetchIssuerMetadata({
    ...(issuer === undefined ? {} : { issuer }),
    discoveryUrl,
    fetch,
    ...(signal === undefined ? {} : { signal }),
    expectedIssuer,
    requireAuthorizationCode,
    headers,
  });
  const login = await startLoginFromIssuerMetadata({
    issuerMetadata,
    ...options,
  });
  return {
    ...login,
    issuerMetadata,
  };
}

export async function finishLogin({
  input,
  transactionStore,
  clearTransaction = true,
  grantType = "authorization_code",
  extraParams = {},
}: FinishLoginOptions = {}): Promise<ReturnType<typeof buildTokenRequestFromAuthorizationResponse>> {
  const store = requireTransactionStore(transactionStore);
  const transaction = await restoreLoginTransaction({
    transactionStore: store,
    required: true,
  });
  const result = buildTokenRequestFromAuthorizationResponse({
    input,
    transaction,
    grantType,
    extraParams,
  });
  if (clearTransaction) {
    await store.clear();
  }
  return result;
}

export async function persistLoginSession({
  sessionStore,
  transaction,
  authorizationResponse,
  tokenResponse,
  issuer = null,
  subject = null,
  createdAt = new Date().toISOString(),
  extra = {},
}: PersistLoginSessionOptions = {}): Promise<SessionRecord> {
  const store = requireSessionStore(sessionStore);
  const session = buildFederatedSessionRecord({
    transaction,
    authorizationResponse,
    tokenResponse,
    issuer,
    subject,
    createdAt,
    extra,
  });
  return normalizeSession(await store.save(session), "stored session");
}

export async function completeLogin({
  input,
  transactionStore,
  sessionStore = null,
  exchangeAuthorizationCode,
  clearTransaction = true,
  grantType = "authorization_code",
  extraParams = {},
  issuer = null,
  subject = null,
  sessionExtra = {},
}: CompleteLoginOptions = {}): Promise<Awaited<ReturnType<typeof finishFederatedLogin>>> {
  return finishFederatedLogin({
    input,
    transactionStore,
    sessionStore,
    exchangeAuthorizationCode,
    clearTransaction,
    grantType,
    extraParams,
    issuer,
    subject,
    sessionExtra,
  });
}

export function buildLogoutUrl({
  endSessionEndpoint,
  idTokenHint,
  postLogoutRedirectUri = null,
  state = null,
  clientId = null,
  extraParams = {},
}: BuildLogoutUrlOptions = {}): string {
  return buildEndSessionUrl({
    endSessionEndpoint,
    idTokenHint,
    postLogoutRedirectUri,
    state,
    clientId,
    extraParams,
  });
}

export function buildLogoutUrlFromIssuerMetadata({
  issuerMetadata,
  idTokenHint,
  postLogoutRedirectUri = null,
  state = null,
  clientId = null,
  extraParams = {},
}: BuildLogoutUrlFromIssuerMetadataOptions = {}): string {
  return buildEndSessionUrlFromIssuerMetadata({
    issuerMetadata,
    idTokenHint,
    postLogoutRedirectUri,
    state,
    clientId,
    extraParams,
  });
}

export const ISSUER_SPA_DEFAULTS = Object.freeze({
  transactionStorageKey: DEFAULT_TRANSACTION_STORAGE_KEY,
  sessionStorageKey: DEFAULT_SESSION_STORAGE_KEY,
});

export {
  CLIENT_CRYPTO_PROFILES,
  DEFAULT_CLIENT_CRYPTO_PROFILE,
  initIssuerSpaRuntime,
};
