//! Private worker custody. The application server needs only public sealing keys.
use super::{invitations::transport::Credential, notification_envelope::*};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::{io::Read, os::unix::fs::MetadataExt, path::Path};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_FILE: usize = 256 * 1024;

/// One explicitly loaded private snapshot; no Debug, Serialize or secret export.
pub struct Configuration {
    pub(crate) ring: PrivateKeyRing,
    pub(crate) credential: Credential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    version: u32,
    credential: &'a str,
    #[serde(borrow)]
    keys: Vec<Key<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key<'a> {
    version: String,
    deployment_id: Uuid,
    scope: KeyScope,
    not_before: i64,
    seal_until: i64,
    open_until: i64,
    spki_sha256: String,
    pkcs8: &'a str,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum KeyScope {
    Environment {
        environment_id: Uuid,
    },
    Domain {
        environment_id: Uuid,
        domain_id: Uuid,
    },
    Organization {
        environment_id: Uuid,
        domain_id: Uuid,
        organization_id: Uuid,
    },
}
impl From<KeyScope> for Scope {
    fn from(scope: KeyScope) -> Self {
        match scope {
            KeyScope::Environment { environment_id } => Self::Environment { environment_id },
            KeyScope::Domain {
                environment_id,
                domain_id,
            } => Self::Domain {
                environment_id,
                domain_id,
            },
            KeyScope::Organization {
                environment_id,
                domain_id,
                organization_id,
            } => Self::Organization {
                environment_id,
                domain_id,
                organization_id,
            },
        }
    }
}

impl Configuration {
    /// Read one bounded regular file owned by this worker, with no group/other
    /// permissions or final symlink. Its directory is operator-managed custody.
    ///
    /// # Errors
    /// Refuses invalid ownership, shape, keys, scope, fingerprints or credentials.
    pub fn load(path: &Path) -> Result<Self, Error> {
        use rustix::fs::{self, Mode, OFlags};
        if !path.is_absolute() || path.as_os_str().len() > 4096 {
            return Err(Error::InvalidKey);
        }
        let file = std::fs::File::from(
            fs::open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::InvalidKey)?,
        );
        let info = file.metadata().map_err(|_| Error::InvalidKey)?;
        if !info.is_file()
            || info.uid() != rustix::process::geteuid().as_raw()
            || info.mode() & 0o077 != 0
            || info.nlink() != 1
            || info.len() == 0
            || info.len() > MAX_FILE as u64
        {
            return Err(Error::InvalidKey);
        }
        let mut input = Zeroizing::new(Vec::with_capacity(MAX_FILE + 1));
        file.take((MAX_FILE + 1) as u64)
            .read_to_end(&mut input)
            .map_err(|_| Error::InvalidKey)?;
        if input.is_empty() || input.len() > MAX_FILE {
            return Err(Error::InvalidKey);
        }
        Self::parse(&input)
    }

    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let document: Document<'_> =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidKey)?;
        if document.version != 1 || document.keys.is_empty() || document.keys.len() > 16 {
            return Err(Error::InvalidKey);
        }
        let credential =
            Credential::parse(document.credential.to_owned()).map_err(|_| Error::InvalidKey)?;
        let mut keys = Vec::with_capacity(document.keys.len());
        for key in document.keys {
            let pin: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&key.spki_sha256)
                .map_err(|_| Error::InvalidKey)?
                .try_into()
                .map_err(|_| Error::InvalidKey)?;
            if URL_SAFE_NO_PAD.encode(pin) != key.spki_sha256 || key.pkcs8.len() > 10924 {
                return Err(Error::InvalidKey);
            }
            let mut der = Zeroizing::new(vec![0u8; 8192]);
            let length = URL_SAFE_NO_PAD
                .decode_slice(key.pkcs8, der.as_mut_slice())
                .map_err(|_| Error::InvalidKey)?;
            der.truncate(length);
            let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(der.as_slice()));
            if canonical.as_str() != key.pkcs8 {
                return Err(Error::InvalidKey);
            }
            keys.push(PrivateDeliveryKey::new(
                KeyVersion {
                    id: key.version,
                    deployment_id: key.deployment_id,
                    scope: key.scope.into(),
                    not_before: key.not_before,
                    seal_until: key.seal_until,
                    open_until: key.open_until,
                },
                der,
                pin,
            )?);
        }
        Ok(Self {
            ring: PrivateKeyRing::new(keys)?,
            credential,
        })
    }
}

#[cfg(test)]
mod tests;
