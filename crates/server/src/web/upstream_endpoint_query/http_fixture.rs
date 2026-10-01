use axum::{
    body::{to_bytes, Body},
    http::Request,
    response::IntoResponse,
    Router,
};
use tokio::{sync::mpsc, task::JoinHandle};

pub(in crate::web) struct EndpointFixture {
    pub(in crate::web) base: String,
    requests: mpsc::UnboundedReceiver<(String, String)>,
    task: JoinHandle<()>,
}
impl Drop for EndpointFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl EndpointFixture {
    pub(in crate::web) async fn start(body: String) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| e.to_string())?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let (sender, requests) = mpsc::unbounded_channel();
        let app = Router::new().fallback(move |request: Request<Body>| {
            let sender = sender.clone();
            let body = body.clone();
            async move {
                let target = request
                    .uri()
                    .path_and_query()
                    .map_or("/", |value| value.as_str())
                    .to_string();
                let bytes = to_bytes(request.into_body(), 16384)
                    .await
                    .expect("bounded test request");
                sender
                    .send((
                        target,
                        String::from_utf8(bytes.to_vec()).expect("form UTF-8"),
                    ))
                    .expect("receiver live");
                ([("content-type", "application/json")], body).into_response()
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("fixture server");
        });
        Ok(Self {
            base: format!("http://{address}"),
            requests,
            task,
        })
    }
    pub(in crate::web) async fn received(&mut self) -> Result<(String, String), String> {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.requests.recv())
            .await
            .map_err(|_| "request timeout".to_string())?
            .ok_or_else(|| "request channel closed".to_string())
    }
    pub(in crate::web) fn assert_no_request(&mut self) {
        assert!(self.requests.try_recv().is_err());
    }
}
