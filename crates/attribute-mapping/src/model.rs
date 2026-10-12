use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EXPRESSION_DEPTH: usize = 32;
pub const MAX_POLICY_NODES: usize = 2048;
pub const MAX_EVALUATION_STEPS: usize = 32768;
pub const MAX_INPUT_BYTES: usize = 262_144;
pub const MAX_OUTPUT_BYTES: usize = 65_536;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_COLLECTION_ITEMS: usize = 1024;
pub const MAX_IDENTIFIER_BYTES: usize = 512;

/// Internal owner identifiers, not editable attributes or an OIDC subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub environment_id: String,
    pub user_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "name",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Surface {
    IdToken,
    Userinfo,
    Profile(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub environment_id: String,
    pub client_id: String,
    pub surface: Surface,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeKey {
    pub source: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Local,
    External,
    Transient,
}

/// Established by the authorized source adapter, never inferred by a mapper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub kind: SourceKind,
    pub authority: String,
    pub source_revision: String,
    pub observed_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AttributeValue {
    Missing,
    Present(Value),
}

impl AttributeValue {
    pub fn as_ref(&self) -> Option<&Value> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    pub key: AttributeKey,
    pub owner: Subject,
    /// Missing and present JSON null remain distinct across serialization.
    pub value: AttributeValue,
    pub provenance: Provenance,
    /// An empty set discloses to nobody. No implicit wildcard or same-RP fallback.
    pub recipients: BTreeSet<Recipient>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PathStep {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expression {
    Read {
        attribute: AttributeKey,
        path: Vec<PathStep>,
    },
    Literal {
        value: Value,
    },
    Object {
        fields: BTreeMap<String, Expression>,
    },
    Array {
        items: Vec<Expression>,
    },
    Coalesce {
        choices: Vec<Expression>,
    },
    LowerAscii {
        input: Box<Expression>,
    },
    Concat {
        parts: Vec<Expression>,
        separator: String,
    },
    Map {
        input: Box<Expression>,
        item: Box<Expression>,
    },
    /// The current item of the innermost Map; invalid outside Map.
    Item {
        path: Vec<PathStep>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSchema {
    String,
    Boolean,
    Number,
    Integer,
    Null,
    Array {
        items: Box<ValueSchema>,
    },
    Object {
        properties: BTreeMap<String, FieldSchema>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldSchema {
    pub required: bool,
    pub schema: ValueSchema,
}

/// A protocol adapter supplies this contract; a mapping policy cannot edit it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputContract {
    pub fields: BTreeMap<String, FieldSchema>,
    pub additional_reserved_names: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingPolicy {
    pub schema_version: u32,
    pub revision: String,
    pub recipient: Recipient,
    pub inputs: BTreeSet<AttributeKey>,
    pub outputs: BTreeMap<String, Expression>,
    /// Distinct from transformation rules: defining a rule does not release it.
    pub released_outputs: BTreeSet<String>,
}

impl MappingPolicy {
    /// Validate a policy against its adapter-owned output contract before storage.
    /// Input existence, ownership, grants and freshness are checked at evaluation.
    ///
    /// # Errors
    /// Returns [`MappingError`] for an invalid policy or output contract.
    pub fn validate(&self, contract: &OutputContract) -> Result<(), MappingError> {
        crate::validation::policy(self, contract)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("unsupported mapping schema version")]
    SchemaVersion,
    #[error("invalid mapping identifier")]
    Identifier,
    #[error("mapping resource limit exceeded")]
    ResourceLimit,
    #[error("mapping recipient does not match the selected context")]
    RecipientMismatch,
    #[error("attribute owner does not match the selected subject")]
    SubjectMismatch,
    #[error("duplicate input attribute")]
    DuplicateAttribute,
    #[error("unknown input attribute")]
    UnknownAttribute,
    #[error("input transformation is not permitted")]
    InputDenied,
    #[error("attribute disclosure is not permitted")]
    DisclosureDenied,
    #[error("output disclosure is not permitted")]
    OutputDenied,
    #[error("invalid attribute observation or expiry")]
    InvalidTime,
    #[error("input attribute has expired")]
    Expired,
    #[error("expression input has an incompatible type")]
    TypeMismatch,
    #[error("required output value is missing")]
    MissingRequired,
    #[error("mapping attempts to write a protocol-owned claim")]
    ReservedClaim,
    #[error("output does not match the supplied contract")]
    OutputContract,
    #[error("array item reference is outside a map expression")]
    ItemScope,
    #[error("invalid mapping expression")]
    Expression,
}
