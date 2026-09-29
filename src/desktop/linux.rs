use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use secret_service::blocking::{Collection, SecretService};
use secret_service::{EncryptionType, Error as ServiceError};
use tauri::{AppHandle, Runtime};
use zeroize::Zeroizing;

use super::{software, Opened};
use crate::models::{Backing, SealResponse};
use crate::sealed;
use crate::{Error, Result};

const SCHEME: &str = "aes-gcm-secretservice";

const APP_ATTRIBUTE: &str = "crypto-hw";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

const NO_SECRET: &str = "There is no secret kept under that name on this device.";
const LOCKED: &str = "Your keyring is locked. Unlock it and try again.";
const REFUSED: &str = "Your keyring would not keep that secret. Try again.";
const DAMAGED_KEY: &str =
    "The key for that secret is damaged. Delete it and seal the secret again.";
const UNREADABLE: &str = "That secret could not be opened. Seal it again.";
const KEYRING_AWAY: &str =
    "Your keyring is not available, so that secret cannot be opened. Start it and try again.";
const NOT_KEPT: &str = "That secret could not be kept on this device. Try again.";

/// Which of this platform's two ways holds the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rung {
    Keyring,
    File,
}

pub(crate) fn seal<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    plaintext: &[u8],
) -> Result<SealResponse> {
    let Some(key) = in_keyring(|collection| key_in(collection, identifier, Missing::Create))?
    else {
        return software::seal(app, identifier, plaintext);
    };

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto(NOT_KEPT.to_string()))?;

    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    Ok(SealResponse {
        sealed: sealed::format(SCHEME, &payload),
        backing: Backing::System,
    })
}

pub(crate) fn open<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    sealed_text: &str,
) -> Result<Opened> {
    let parsed = sealed::parse(sealed_text)?;
    if rung_for(&parsed.scheme)? == Rung::File {
        return software::open(app, identifier, sealed_text);
    }
    if parsed.bytes.len() < NONCE_LEN {
        return Err(Error::Crypto(sealed::FOREIGN.to_string()));
    }
    let (nonce, ciphertext) = parsed.bytes.split_at(NONCE_LEN);

    // A secret the keyring holds the key to cannot be opened without it, so an
    // absent keyring is not an invitation to fall to the key file.
    let key = in_keyring(|collection| key_in(collection, identifier, Missing::Report))?
        .ok_or_else(|| Error::Unavailable(KEYRING_AWAY.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

    Ok(Opened {
        plaintext: Zeroizing::new(plaintext),
        backing: Backing::System,
    })
}

/// Both rungs are cleared, because either could be holding this name: the
/// keyring item, and the key file a machine without a keyring wrote.
pub(crate) fn delete<R: Runtime>(app: &AppHandle<R>, identifier: &str) -> Result<bool> {
    let from_keyring = in_keyring(|collection| {
        let mut removed = false;
        for item in items_for(collection, identifier)? {
            item.delete().map_err(from_service)?;
            removed = true;
        }
        Ok(removed)
    })?
    .unwrap_or(false);

    Ok(software::delete(app, identifier)? || from_keyring)
}

fn rung_for(scheme: &str) -> Result<Rung> {
    match scheme {
        SCHEME => Ok(Rung::Keyring),
        software::SCHEME => Ok(Rung::File),
        _ => Err(Error::Crypto(sealed::FOREIGN.to_string())),
    }
}

/// A machine with no session bus, or nothing answering the secret service on
/// it, has no keyring; a keyring that is there and says no is a failure the
/// person can act on, not a reason to keep the secret more weakly.
fn keyring_away(trouble: &ServiceError) -> bool {
    matches!(
        trouble,
        ServiceError::Unavailable | ServiceError::Zbus(_) | ServiceError::ZbusFdo(_)
    )
}

/// Runs `job` on a thread of its own, which the keyring calls need: the secret
/// service crate blocks on a tokio runtime it keeps, and tokio panics when a
/// thread already driving one blocks on another — which is every thread a
/// command arrives on.
fn off_the_async_runtime<T: Send>(job: impl FnOnce() -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|threads| {
        threads
            .spawn(job)
            .join()
            .unwrap_or_else(|_| Err(Error::Unavailable(REFUSED.to_string())))
    })
}

/// Runs `job` against the unlocked default collection. `None` is a machine with
/// no keyring at all, which the caller answers for itself.
fn in_keyring<T: Send>(job: impl FnOnce(&Collection<'_>) -> Result<T> + Send) -> Result<Option<T>> {
    off_the_async_runtime(move || {
        let service = match SecretService::connect(EncryptionType::Dh) {
            Ok(service) => service,
            Err(trouble) if keyring_away(&trouble) => return Ok(None),
            Err(trouble) => return Err(from_service(trouble)),
        };
        let collection = match service.get_default_collection() {
            Ok(collection) => collection,
            Err(ServiceError::NoResult) => return Ok(None),
            Err(trouble) if keyring_away(&trouble) => return Ok(None),
            Err(trouble) => return Err(from_service(trouble)),
        };
        if collection.is_locked().map_err(from_service)? {
            collection.unlock().map_err(from_service)?;
        }
        job(&collection).map(Some)
    })
}

/// What to do when the keyring holds no key for this name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Missing {
    Create,
    Report,
}

fn key_in(
    collection: &Collection<'_>,
    identifier: &str,
    missing: Missing,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if let Some(item) = items_for(collection, identifier)?.into_iter().next() {
        let held = Zeroizing::new(item.get_secret().map_err(from_service)?);
        let bytes = Zeroizing::new(
            STANDARD
                .decode(held.as_slice())
                .map_err(|_| Error::Crypto(DAMAGED_KEY.to_string()))?,
        );
        if bytes.len() != KEY_LEN {
            return Err(Error::Crypto(DAMAGED_KEY.to_string()));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    if missing == Missing::Report {
        return Err(Error::NotFound(NO_SECRET.to_string()));
    }

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut_slice());
    let written = Zeroizing::new(STANDARD.encode(key.as_slice()));
    collection
        .create_item(
            &std::format!("Sealed secret for {identifier}"),
            attributes(identifier),
            written.as_bytes(),
            true,
            "text/plain",
        )
        .map_err(from_service)?;
    Ok(key)
}

fn items_for<'a>(
    collection: &'a Collection<'a>,
    identifier: &str,
) -> Result<Vec<secret_service::blocking::Item<'a>>> {
    collection
        .search_items(attributes(identifier))
        .map_err(from_service)
}

fn attributes(identifier: &str) -> HashMap<&str, &str> {
    HashMap::from([("app", APP_ATTRIBUTE), ("identifier", identifier)])
}

fn from_service(trouble: ServiceError) -> Error {
    match trouble {
        ServiceError::Locked | ServiceError::Prompt | ServiceError::PromptDisconnected => {
            Error::Unavailable(LOCKED.to_string())
        }
        _ => Error::Unavailable(REFUSED.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_rung_out_of_the_scheme() {
        assert_eq!(rung_for(SCHEME).unwrap(), Rung::Keyring);
        assert_eq!(rung_for(software::SCHEME).unwrap(), Rung::File);
    }

    #[test]
    fn refuses_a_scheme_this_platform_never_writes() {
        for scheme in ["ecies-p256", "aes-gcm-keystore", "rsa-oaep-tpm", "dpapi"] {
            let trouble = rung_for(scheme).unwrap_err();
            assert_eq!(trouble.to_string(), sealed::FOREIGN, "{scheme}");
        }
    }

    #[test]
    fn falls_to_the_key_file_only_where_there_is_no_keyring() {
        assert!(keyring_away(&ServiceError::Unavailable));
        assert!(!keyring_away(&ServiceError::Locked));
        assert!(!keyring_away(&ServiceError::Prompt));
        assert!(!keyring_away(&ServiceError::PromptDisconnected));
        assert!(!keyring_away(&ServiceError::NoResult));
        assert!(!keyring_away(&ServiceError::Crypto("")));
    }

    #[test]
    fn tells_a_locked_keyring_apart_from_one_that_refused() {
        assert_eq!(from_service(ServiceError::Locked).to_string(), LOCKED);
        assert_eq!(from_service(ServiceError::Prompt).to_string(), LOCKED);
        assert_eq!(from_service(ServiceError::NoResult).to_string(), REFUSED);
    }

    #[test]
    fn speaks_to_the_keyring_away_from_the_caller_s_thread() {
        let here = std::thread::current().id();
        let there = off_the_async_runtime(|| Ok(std::thread::current().id())).unwrap();
        assert_ne!(here, there);
    }

    #[test]
    fn marks_every_item_as_this_app_s() {
        let attributes = attributes("notes");
        assert_eq!(attributes.get("app"), Some(&APP_ATTRIBUTE));
        assert_eq!(attributes.get("identifier"), Some(&"notes"));
    }
}
