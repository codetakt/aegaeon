//! Selectors cover current topology and immutable object incarnations.
//! Snapshot membership is resolved by the transaction-scoped SQL adapter; an
//! absent or unavailable supplier never becomes current/future coverage.

use super::lineage::Identity;

const MAX_PATH_NODES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResourceKind {
    Installation,
    Team,
    Tenant,
    Environment,
    User,
    Organization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Resource {
    pub(crate) installation: Identity,
    pub(crate) id: Identity,
    pub(crate) incarnation: Identity,
    pub(crate) kind: ResourceKind,
}

impl Resource {
    fn valid(self) -> bool {
        self.installation.is_present()
            && self.id.is_present()
            && self.incarnation.is_present()
            && (self.kind != ResourceKind::Installation || self.id == self.installation)
    }
}

#[derive(Debug)]
pub(crate) struct CurrentPath<'a> {
    nodes: &'a [Resource],
}

impl<'a> CurrentPath<'a> {
    /// The SQL adapter supplies leaf-to-root rows from the same read snapshot.
    pub(crate) fn new(nodes: &'a [Resource]) -> Option<Self> {
        if nodes.is_empty() || nodes.len() > MAX_PATH_NODES {
            return None;
        }
        let installation = nodes[0].installation;
        for (index, resource) in nodes.iter().enumerate() {
            if !resource.valid() || resource.installation != installation {
                return None;
            }
            let expected_parent = match resource.kind {
                ResourceKind::Installation => None,
                ResourceKind::Team => Some(ResourceKind::Installation),
                ResourceKind::Tenant => Some(ResourceKind::Team),
                ResourceKind::Environment => Some(ResourceKind::Tenant),
                ResourceKind::User | ResourceKind::Organization => Some(ResourceKind::Environment),
            };
            if nodes.get(index + 1).map(|parent| parent.kind) != expected_parent {
                return None;
            }
        }
        Some(Self { nodes })
    }

    pub(crate) fn resource(&self) -> Resource {
        self.nodes[0]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Selector {
    Exact(Resource),
    CurrentDescendants {
        anchor: Resource,
        snapshot_id: Identity,
    },
    CurrentAndFutureDescendants {
        anchor: Resource,
    },
}

impl Selector {
    /// Descendant selectors include their anchor. Stored membership alone is
    /// insufficient: current ancestry and the original incarnation must match.
    pub(crate) fn covers<E>(
        self,
        path: &CurrentPath<'_>,
        mut snapshot_member: impl FnMut(Identity, Resource) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let (anchor, snapshot) = match self {
            Self::Exact(resource) => return Ok(resource.valid() && resource == path.resource()),
            Self::CurrentDescendants {
                anchor,
                snapshot_id,
            } => {
                if !snapshot_id.is_present() {
                    return Ok(false);
                }
                (anchor, Some(snapshot_id))
            }
            Self::CurrentAndFutureDescendants { anchor } => (anchor, None),
        };
        if !anchor.valid() || !path.nodes.contains(&anchor) {
            return Ok(false);
        }
        match snapshot {
            Some(snapshot_id) => snapshot_member(snapshot_id, path.resource()),
            None => Ok(true),
        }
    }
}

#[cfg(test)]
mod tests;
