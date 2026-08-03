use utoipa::openapi::OpenApi;
use utoipa::OpenApi as _;

mod management;
mod ops;
mod types;

pub use management::ManagementApiV1;
pub use ops::OpsApiV1;

#[must_use]
pub fn management_openapi() -> OpenApi {
    ManagementApiV1::openapi()
}

#[must_use]
pub fn ops_openapi() -> OpenApi {
    OpsApiV1::openapi()
}
