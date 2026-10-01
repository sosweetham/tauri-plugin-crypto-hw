use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use tauri::{AppHandle, Manager, Runtime};
use zeroize::Zeroizing;

use super::Opened;
use crate::models::{Backing, SealResponse};
use crate::sealed;
use crate::{Error, Result};

pub(crate) const SCHEME: &str = "aes-gcm-software";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

const NO_SECRET: &str = "There is no secret kept under that name on this device.";
const DAMAGED_KEY: &str =
    "The key for that secret is damaged. Delete it and seal the secret again.";
const UNREADABLE: &str = "That secret could not be opened. Seal it again.";

pub(crate) fn seal<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    plaintext: &[u8],
) -> Result<SealResponse> {
    seal_in(&key_dir(app)?, identifier, plaintext)
}

pub(crate) fn open<R: Runtime>(
    app: &AppHandle<R>,
    identifier: &str,
    sealed: &str,
) -> Result<Opened> {
    open_in(&key_dir(app)?, identifier, sealed)
}

pub(crate) fn delete<R: Runtime>(app: &AppHandle<R>, identifier: &str) -> Result<bool> {
    delete_in(&key_dir(app)?, identifier)
}

fn seal_in(dir: &Path, identifier: &str, plaintext: &[u8]) -> Result<SealResponse> {
    let key = load_or_create_key(dir, identifier)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    Ok(SealResponse {
        sealed: sealed::format(SCHEME, &payload),
        backing: Backing::Software,
    })
}

fn open_in(dir: &Path, identifier: &str, sealed: &str) -> Result<Opened> {
    let parsed = sealed::parse(sealed)?;
    if parsed.scheme != SCHEME {
        return Err(Error::Crypto(sealed::FOREIGN.to_string()));
    }
    if parsed.bytes.len() < NONCE_LEN {
        return Err(Error::Crypto(sealed::FOREIGN.to_string()));
    }
    let (nonce, ciphertext) = parsed.bytes.split_at(NONCE_LEN);

    let path = key_path(dir, identifier);
    if !path.exists() {
        return Err(Error::NotFound(NO_SECRET.to_string()));
    }
    let key = read_key(&path)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::Crypto(UNREADABLE.to_string()))?;

    Ok(Opened {
        plaintext: Zeroizing::new(plaintext),
        backing: Backing::Software,
    })
}

fn delete_in(dir: &Path, identifier: &str) -> Result<bool> {
    match fs::remove_file(key_path(dir, identifier)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn key_dir<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf> {
    let base = app.path().app_data_dir().map_err(|_| {
        Error::Unavailable("This device has nowhere for the app to keep secrets.".to_string())
    })?;
    Ok(base.join("crypto-hw"))
}

/// An identifier is text a person chose, so it is encoded rather than used as a
/// path segment: `../` in an identifier must not reach outside the key directory.
fn key_path(dir: &Path, identifier: &str) -> PathBuf {
    dir.join(std::format!(
        "{}.key",
        URL_SAFE_NO_PAD.encode(identifier.as_bytes())
    ))
}

fn load_or_create_key(dir: &Path, identifier: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let path = key_path(dir, identifier);
    if path.exists() {
        return read_key(&path);
    }

    fs::create_dir_all(dir)?;
    restrict_to_owner(dir, 0o700)?;

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(key.as_mut_slice());
    match write_key(&path, key.as_slice()) {
        Ok(()) => Ok(key),
        // Another seal of the same name got there first, and its key is the one.
        Err(Error::Io(trouble)) if trouble.kind() == std::io::ErrorKind::AlreadyExists => {
            read_key(&path)
        }
        Err(trouble) => Err(trouble),
    }
}

fn read_key(path: &Path) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = Zeroizing::new(fs::read(path)?);
    if bytes.len() != KEY_LEN {
        return Err(Error::Crypto(DAMAGED_KEY.to_string()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(unix)]
fn write_key(path: &Path, key: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(key)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_key(path: &Path, key: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(key)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn restrict_to_owner(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_to_owner(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn seals_and_opens_the_same_text() {
        let dir = TempDir::new().unwrap();
        let sealed = seal_in(dir.path(), "notes", b"the quick brown fox").unwrap();
        assert_eq!(sealed.backing, Backing::Software);
        assert!(sealed.sealed.starts_with("aes-gcm-software:"));

        let opened = open_in(dir.path(), "notes", &sealed.sealed).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"the quick brown fox");
        assert_eq!(opened.backing, Backing::Software);
    }

    #[test]
    fn seals_the_same_text_differently_each_time() {
        let dir = TempDir::new().unwrap();
        let first = seal_in(dir.path(), "notes", b"same").unwrap();
        let second = seal_in(dir.path(), "notes", b"same").unwrap();
        assert_ne!(first.sealed, second.sealed);
        assert_eq!(
            open_in(dir.path(), "notes", &first.sealed)
                .unwrap()
                .plaintext
                .as_slice(),
            b"same"
        );
    }

    #[test]
    fn keeps_one_key_per_identifier() {
        let dir = TempDir::new().unwrap();
        let mine = seal_in(dir.path(), "mine", b"secret").unwrap();
        seal_in(dir.path(), "yours", b"secret").unwrap();
        assert!(open_in(dir.path(), "yours", &mine.sealed).is_err());
    }

    #[test]
    fn refuses_a_string_another_backend_wrote() {
        let dir = TempDir::new().unwrap();
        seal_in(dir.path(), "notes", b"secret").unwrap();
        let err = open_in(dir.path(), "notes", "dpapi:QUJD").unwrap_err();
        assert_eq!(err.to_string(), sealed::FOREIGN);
    }

    #[test]
    fn refuses_a_tampered_payload() {
        let dir = TempDir::new().unwrap();
        let sealed = seal_in(dir.path(), "notes", b"secret").unwrap();
        let mut bytes = crate::sealed::parse(&sealed.sealed).unwrap().bytes;
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = crate::sealed::format(SCHEME, &bytes);
        assert!(open_in(dir.path(), "notes", &tampered).is_err());
    }

    #[test]
    fn says_nothing_is_kept_under_an_unknown_name() {
        let dir = TempDir::new().unwrap();
        let sealed = seal_in(dir.path(), "notes", b"secret").unwrap();
        let err = open_in(dir.path(), "absent", &sealed.sealed).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn deleting_reports_whether_there_was_anything_to_delete() {
        let dir = TempDir::new().unwrap();
        assert!(!delete_in(dir.path(), "notes").unwrap());
        seal_in(dir.path(), "notes", b"secret").unwrap();
        assert!(delete_in(dir.path(), "notes").unwrap());
        assert!(!delete_in(dir.path(), "notes").unwrap());
    }

    #[test]
    fn an_identifier_cannot_reach_outside_the_key_directory() {
        let dir = TempDir::new().unwrap();
        let escaping = key_path(dir.path(), "../../etc/passwd");
        assert_eq!(escaping.parent(), Some(dir.path()));
    }

    #[cfg(unix)]
    #[test]
    fn writes_the_key_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        seal_in(dir.path(), "notes", b"secret").unwrap();
        let mode = fs::metadata(key_path(dir.path(), "notes"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
