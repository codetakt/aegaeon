use opentelemetry::{global, trace::TracerProvider};
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{RandomIdGenerator, Sampler, SdkTracerProvider},
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::ObservabilityConfig;

/// Initialize distributed tracing with OpenTelemetry
pub fn init_tracing(config: &ObservabilityConfig) {
    // Set up propagator for W3C Trace Context
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Create simple tracer provider without OTLP for now
    // This avoids the complex API changes in v0.30
    let tracer_provider = SdkTracerProvider::builder()
        .with_sampler(Sampler::TraceIdRatioBased(config.trace_sampling_rate))
        .with_id_generator(RandomIdGenerator::default())
        .build();

    // Set global tracer provider
    global::set_tracer_provider(tracer_provider.clone());

    // Get tracer
    let tracer = tracer_provider.tracer("aegaeon-oauth");

    // Create telemetry layer
    let telemetry_layer = OpenTelemetryLayer::new(tracer);

    // Create formatting layer for console output
    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_level(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .json();

    // Create env filter
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,aegaeon=debug"));

    // Initialize subscriber with layers
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(telemetry_layer)
        .init();

    tracing::info!(
        service.name = %config.service_name,
        otlp.endpoint = %config.otlp_endpoint,
        sampling.rate = %config.trace_sampling_rate,
        "Distributed tracing initialized"
    );
}

/// Create a span for OAuth-specific operations
#[macro_export]
macro_rules! oauth_span {
    ($name:expr) => {
        tracing::info_span!(
            $name,
            otel.kind = "server",
            oauth.flow = tracing::field::Empty,
            oauth.client_id = tracing::field::Empty,
            oauth.grant_type = tracing::field::Empty,
            oauth.scope = tracing::field::Empty,
        )
    };
    ($name:expr, $($field:tt)*) => {
        tracing::info_span!(
            $name,
            otel.kind = "server",
            oauth.flow = tracing::field::Empty,
            oauth.client_id = tracing::field::Empty,
            oauth.grant_type = tracing::field::Empty,
            oauth.scope = tracing::field::Empty,
            $($field)*
        )
    };
}

/// Trace context for OAuth operations
pub struct OAuthTraceContext {
    pub request_id: String,
    pub client_id: Option<String>,
    pub user_id: Option<String>,
    pub grant_type: Option<String>,
    pub scope: Option<String>,
}

impl OAuthTraceContext {
    #[must_use]
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            client_id: None,
            user_id: None,
            grant_type: None,
            scope: None,
        }
    }

    #[must_use]
    pub fn with_client(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    #[must_use]
    pub fn with_user(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    #[must_use]
    pub fn with_grant_type(mut self, grant_type: String) -> Self {
        self.grant_type = Some(grant_type);
        self
    }

    #[must_use]
    pub fn with_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Record context in current span
    pub fn record_in_span(&self) {
        let span = tracing::Span::current();
        span.record("oauth.request_id", self.request_id.as_str());

        if let Some(ref client_id) = self.client_id {
            span.record("oauth.client_id", client_id.as_str());
        }

        if let Some(ref user_id) = self.user_id {
            span.record("oauth.user_id", user_id.as_str());
        }

        if let Some(ref grant_type) = self.grant_type {
            span.record("oauth.grant_type", grant_type.as_str());
        }

        if let Some(ref scope) = self.scope {
            span.record("oauth.scope", scope.as_str());
        }
    }
}

/// Instrumentation helpers for specific OAuth operations
pub mod instrumentation {
    use tracing::{error, info, instrument, warn};

    #[instrument(skip_all, fields(
        oauth.operation = "token_issue",
        oauth.token_type = %token_type,
        oauth.client_id = %client_id,
    ))]
    pub async fn trace_token_issue<F, T>(token_type: &str, client_id: &str, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        info!("Issuing {} token for client {}", token_type, client_id);
        let result = f.await;
        info!("Token issued successfully");
        result
    }

    #[instrument(skip_all, fields(
        oauth.operation = "dpop_validation",
        oauth.proof_jti = %jti,
    ))]
    /// # Errors
    ///
    /// Propagates the validation error returned by `f` unchanged.
    pub async fn trace_dpop_validation<F, T>(jti: &str, f: F) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        info!("Validating DPoP proof");
        match f.await {
            Ok(result) => {
                info!("DPoP proof validated successfully");
                Ok(result)
            }
            Err(e) => {
                warn!("DPoP validation failed: {}", e);
                Err(e)
            }
        }
    }

    #[instrument(skip_all, fields(
        oauth.operation = "pkce_verification",
        oauth.client_id = %client_id,
    ))]
    /// # Errors
    ///
    /// Propagates the verification error returned by `f` unchanged.
    pub async fn trace_pkce_verification<F>(client_id: &str, f: F) -> Result<(), String>
    where
        F: std::future::Future<Output = Result<(), String>>,
    {
        info!("Verifying PKCE challenge");
        match f.await {
            Ok(()) => {
                info!("PKCE verification successful");
                Ok(())
            }
            Err(e) => {
                warn!("PKCE verification failed: {}", e);
                Err(e)
            }
        }
    }

    #[instrument(skip_all, fields(
        oauth.operation = "par_request",
        oauth.client_id = %client_id,
    ))]
    /// # Errors
    ///
    /// Propagates the request-processing error returned by `f` unchanged.
    pub async fn trace_par_request<F, T>(client_id: &str, f: F) -> Result<T, String>
    where
        F: std::future::Future<Output = Result<T, String>>,
    {
        info!("Processing PAR request");
        match f.await {
            Ok(result) => {
                info!("PAR request processed successfully");
                Ok(result)
            }
            Err(e) => {
                error!("PAR request failed: {}", e);
                Err(e)
            }
        }
    }

    #[instrument(skip_all, fields(
        oauth.operation = "introspection",
        oauth.token_hint = %token_hint,
    ))]
    pub async fn trace_introspection<F, T>(token_hint: &str, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        info!("Introspecting token");
        let result = f.await;
        info!("Introspection complete");
        result
    }

    #[instrument(skip_all, fields(
        oauth.operation = "revocation",
        oauth.token_type = %token_type,
    ))]
    /// # Errors
    ///
    /// Propagates the revocation error returned by `f` unchanged.
    pub async fn trace_revocation<F>(token_type: &str, f: F) -> Result<(), String>
    where
        F: std::future::Future<Output = Result<(), String>>,
    {
        info!("Revoking {} token", token_type);
        match f.await {
            Ok(()) => {
                info!("Token revoked successfully");
                Ok(())
            }
            Err(e) => {
                error!("Token revocation failed: {}", e);
                Err(e)
            }
        }
    }
}

/// Extract trace context from HTTP headers
#[must_use]
pub fn extract_trace_context(headers: &http::HeaderMap) -> opentelemetry::Context {
    use opentelemetry::propagation::Extractor;

    struct HeaderExtractor<'a>(&'a http::HeaderMap);

    impl Extractor for HeaderExtractor<'_> {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).and_then(|v| v.to_str().ok())
        }

        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(http::HeaderName::as_str).collect()
        }
    }

    let extractor = HeaderExtractor(headers);
    global::get_text_map_propagator(|propagator| propagator.extract(&extractor))
}

/// Inject trace context into HTTP headers
pub fn inject_trace_context(headers: &mut http::HeaderMap) {
    use http::{HeaderName, HeaderValue};
    use opentelemetry::propagation::Injector;

    struct HeaderInjector<'a>(&'a mut http::HeaderMap);

    impl Injector for HeaderInjector<'_> {
        fn set(&mut self, key: &str, value: String) {
            if let Ok(header_name) = HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = HeaderValue::from_str(&value) {
                    self.0.insert(header_name, header_value);
                }
            }
        }
    }

    let mut injector = HeaderInjector(headers);
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&opentelemetry::Context::current(), &mut injector);
    });
}
