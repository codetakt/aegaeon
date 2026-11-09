//! PostgreSQL-only exports of the pinned SQLx core and driver.
//!
//! This retains Aegaeon's selected SQLx 0.8.6 implementation and features without
//! the umbrella crate's unused SQLite/MySQL dependencies in its lockfiles.
//! Re-export declarations are adapted from SQLx 0.8.6; see NOTICE.

pub use sqlx_core::acquire::Acquire;
pub use sqlx_core::arguments::{Arguments, IntoArguments};
pub use sqlx_core::column::{Column, ColumnIndex};
pub use sqlx_core::connection::{ConnectOptions, Connection};
pub use sqlx_core::database::{self, Database};
pub use sqlx_core::describe::Describe;
pub use sqlx_core::error::{self, Error, Result};
pub use sqlx_core::executor::{Execute, Executor};
pub use sqlx_core::from_row::FromRow;
pub use sqlx_core::pool::{self, Pool};
#[doc(hidden)]
pub use sqlx_core::query::query_with_result as __query_with_result;
pub use sqlx_core::query::{query, query_with};
pub use sqlx_core::query_as::{query_as, query_as_with};
pub use sqlx_core::query_builder::{self, QueryBuilder};
#[doc(hidden)]
pub use sqlx_core::query_scalar::query_scalar_with_result as __query_scalar_with_result;
pub use sqlx_core::query_scalar::{query_scalar, query_scalar_with};
pub use sqlx_core::raw_sql::{raw_sql, RawSql};
pub use sqlx_core::row::Row;
#[doc(hidden)]
pub use sqlx_core::rt as __rt;
#[doc(hidden)]
pub use sqlx_core::rt::test_block_on;
pub use sqlx_core::statement::Statement;
pub use sqlx_core::transaction::{Transaction, TransactionManager};
pub use sqlx_core::type_info::TypeInfo;
pub use sqlx_core::types::Type;
pub use sqlx_core::value::{Value, ValueRef};
pub use sqlx_core::Either;
pub use sqlx_postgres::{
    self as postgres, PgConnection, PgExecutor, PgPool, PgTransaction, Postgres,
};

pub mod types {
    pub use sqlx_core::types::*;
}

pub mod encode {
    pub use sqlx_core::encode::{Encode, IsNull};
}

pub use encode::Encode;

pub mod decode {
    pub use sqlx_core::decode::Decode;
}

pub use decode::Decode;

pub mod query {
    pub use sqlx_core::query::{Map, Query};
    pub use sqlx_core::query_as::QueryAs;
    pub use sqlx_core::query_scalar::QueryScalar;
}

pub mod prelude {
    pub use super::{
        Acquire, ConnectOptions, Connection, Decode, Encode, Executor, FromRow, IntoArguments, Row,
        Statement, Type,
    };
}
