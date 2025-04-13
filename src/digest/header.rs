use crate::digest::DigestHash;
use crate::errors::{ExtractHeaderError, InvalidContentDigest, TooManyDigestValues};

pub const CONTENT_DIGEST: &str = "content-digest";

pub(crate) struct ContentDigest {
    pub alg: String,
    pub digest: DigestHash,
}

pub(crate) fn extract_content_digest(
    map: &http::HeaderMap,
) -> Result<ContentDigest, ExtractHeaderError> {
    let header = match map.get(CONTENT_DIGEST).map(|header| header.to_str()) {
        Some(Ok(header)) => header,
        Some(Err(e)) => return Err(ExtractHeaderError::FailedToStr(e)),
        None => {
            return Err(ExtractHeaderError::NoExist {
                header_name: CONTENT_DIGEST,
            });
        }
    };

    let dictionary = sfv::Parser::new(header.as_bytes()).parse_dictionary()?;

    // Content-Digest can include more than one as follows, but there is no choice of algorithm for the digest on RFC9421.
    // Content-Digest: <digest-algorithm>=<digest-value>,<digest-algorithm>=<digest-value>, …
    if dictionary.len() != 1 {
        return Err(TooManyDigestValues.into());
    }

    let Some((alg, digest)) = dictionary.into_iter().next() else {
        unreachable!("Empty should also be covered by a last minute check.");
    };

    let digest = match digest {
        sfv::ListEntry::Item(sfv::Item {
            bare_item: sfv::BareItem::ByteSequence(bytes),
            ..
        }) => bytes,
        _ => return Err(InvalidContentDigest.into()),
    };

    Ok(ContentDigest {
        alg: alg.to_string(),
        digest: DigestHash::new(digest),
    })
}
