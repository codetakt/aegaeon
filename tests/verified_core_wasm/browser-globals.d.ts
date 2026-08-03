interface AegaeonBrowserHarnessStatus {
  done: boolean;
  ok: boolean;
  passed: number;
  failed: number;
}

interface AegaeonRuntimeWebSmokeStatus extends AegaeonBrowserHarnessStatus {
  allowInsecureTestContext?: boolean;
}

declare global {
  interface Window {
    __AEGAEON_WEB_SMOKE__?: AegaeonRuntimeWebSmokeStatus;
    __AEGAEON_ISSUER_E2E__?: AegaeonBrowserHarnessStatus;
    __AEGAEON_EXTERNAL_PROVIDER_E2E__?: AegaeonBrowserHarnessStatus;
  }
}

export {};
