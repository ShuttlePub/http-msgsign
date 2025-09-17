use crate::errors::InvalidDigestDataFormat;
use base64::Engine;
use http::HeaderMap;
use http_content_digest::DigestHash;
use http_content_digest::errors::ExtractHeaderError;

pub const DIGEST: &str = "digest";

#[derive(Debug, Clone)]
pub(crate) struct Digest {
    pub alg: String,
    pub digest: DigestHash,
}

impl Digest {
    //noinspection DuplicatedCode
    pub fn from_header(map: &HeaderMap) -> Result<Digest, ExtractHeaderError> {
        let header = match map.get(DIGEST).map(|header| header.to_str()) {
            Some(Ok(header)) => header,
            Some(Err(e)) => return Err(ExtractHeaderError::FailedToStr(e)),
            None => {
                return Err(ExtractHeaderError::NoExist {
                    header_name: DIGEST,
                });
            }
        };

        // `Digest` can specify multiple algorithms, but this is not permitted in `draft-cavage-http-signatures-12`.
        // This is because, unlike Content-Digest,
        // there is no way to distinguish the `=` that appears when the digest value is Base64-encoded from `<alg_name>=<digest_value>`.
        let Some((alg, digest)) = header.split_once("=") else {
            return Err(InvalidDigestDataFormat {
                reason: "no `=` found"
            })?;
        };

        let digest = base64::engine::general_purpose::STANDARD.decode(digest)?;

        Ok(Self {
            alg: alg.to_string(),
            digest: DigestHash::new(digest),
        })
    }
}
