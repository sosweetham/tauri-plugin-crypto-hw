use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{Error, Result};

/// Told to someone whose sealed string this backend cannot open.
pub(crate) const FOREIGN: &str = "This was sealed on a different device or in a different way.";

const MALFORMED: &str = "This is not a sealed secret from this app.";

/// Every scheme any platform of this plugin writes. A string naming anything else
/// did not come from a build of this plugin, whatever its shape.
const SCHEMES: &[&str] = &[
    "ecies-p256",
    "aes-gcm-keystore",
    "rsa-oaep-tpm",
    "dpapi",
    "aes-gcm-secretservice",
    "aes-gcm-software",
];

/// A sealed string taken apart: `<scheme>:<base64url-nopad(bytes)>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Sealed {
    pub scheme: String,
    pub bytes: Vec<u8>,
}

pub(crate) fn format(scheme: &str, bytes: &[u8]) -> String {
    std::format!("{scheme}:{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn parse(s: &str) -> Result<Sealed> {
    let (scheme, payload) = s.split_once(':').ok_or_else(malformed)?;
    if !SCHEMES.contains(&scheme) {
        return Err(malformed());
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| malformed())?;
    Ok(Sealed {
        scheme: scheme.to_string(),
        bytes,
    })
}

fn malformed() -> Error {
    Error::Crypto(MALFORMED.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for bytes in [
            vec![],
            vec![0u8],
            b"\xff\x00\xfe\x01hello".to_vec(),
            (0..=255u8).collect(),
        ] {
            let s = format("aes-gcm-software", &bytes);
            let back = parse(&s).expect("a string we just wrote parses");
            assert_eq!(back.scheme, "aes-gcm-software");
            assert_eq!(back.bytes, bytes);
        }
    }

    #[test]
    fn formats_without_padding_or_url_unsafe_characters() {
        let s = format("dpapi", &[251u8, 255, 191, 254]);
        assert!(!s.contains('='), "{s}");
        assert!(!s.contains('+') && !s.contains('/'), "{s}");
    }

    #[test]
    fn rejects_a_missing_colon() {
        assert!(parse("aes-gcm-software").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn rejects_an_empty_or_unknown_scheme() {
        assert!(parse(":QUJD").is_err());
        assert!(parse("rot13:QUJD").is_err());
        assert!(parse("AES-GCM-SOFTWARE:QUJD").is_err());
    }

    #[test]
    fn rejects_bad_base64() {
        assert!(parse("dpapi:not base64").is_err());
        assert!(parse("dpapi:QUJD=").is_err());
        assert!(parse("dpapi:QQ==").is_err());
    }

    #[test]
    fn every_scheme_the_contract_names_is_known() {
        for scheme in SCHEMES {
            assert!(parse(&format(scheme, b"payload")).is_ok(), "{scheme}");
        }
    }
}
