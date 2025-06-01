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

        let items = header.split("=").collect::<Vec<&str>>();

        if items.len() != 2 {
            return Err(InvalidDigestDataFormat {
                reason: "`Digest` can specify multiple algorithms, but this is not permitted in `draft-cavage-http-signatures-12`.",
            })?;
        }

        let alg = items[0].to_string();
        let digest = base64::engine::general_purpose::STANDARD.decode(items[1])?;

        Ok(Self {
            alg,
            digest: DigestHash::new(digest),
        })
    }
}
