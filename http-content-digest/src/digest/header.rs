use std::collections::HashMap;

use crate::digest::DigestHash;
use crate::errors::{ExtractHeaderError, InvalidContentDigest};

pub const CONTENT_DIGEST: &str = "content-digest";

pub(crate) struct ContentDigest(HashMap<String, DigestHash>);

impl ContentDigest {
    //noinspection DuplicatedCode
    pub fn from_header(map: &http::HeaderMap) -> Result<ContentDigest, ExtractHeaderError> {
        let header = match map.get(CONTENT_DIGEST).map(|header| header.to_str()) {
            Some(Ok(header)) => header,
            Some(Err(e)) => return Err(ExtractHeaderError::FailedToStr(e)),
            None => {
                return Err(ExtractHeaderError::NoExist {
                    header_name: CONTENT_DIGEST,
                });
            }
        };

        let dict = sfv::Parser::new(header.as_bytes())
            .parse_dictionary()?
            .into_iter()
            .map(|(alg, digest)| match digest {
                sfv::ListEntry::Item(sfv::Item {
                    bare_item: sfv::BareItem::ByteSequence(bytes),
                    ..
                }) => Ok((alg.into(), DigestHash::new(bytes))),
                _ => Err(InvalidContentDigest),
            })
            .collect::<Result<HashMap<String, _>, InvalidContentDigest>>()?;

        Ok(Self(dict))
    }

    pub fn find(self, find: &str) -> Option<DigestHash> {
        self.0
            .into_iter()
            .find(|(alg, _)| alg.eq(find))
            .map(|(_, digest)| digest)
    }
}
