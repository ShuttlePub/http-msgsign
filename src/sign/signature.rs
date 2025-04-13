use crate::errors::{InvalidFormat, SignatureError};
use sfv::{BareItem, Item, ListEntry};
use std::collections::HashMap;

#[derive(Debug)]
pub struct Signatures(HashMap<String, Vec<u8>>);

impl Signatures {
    pub fn from_header(header: &http::HeaderMap) -> Result<Self, SignatureError> {
        let Some(signature) = header.get(crate::sign::header::SIGNATURE) else {
            return Err(SignatureError::NotExistInHeader);
        };

        let mut signatures = HashMap::new();
        for (key, signature) in sfv::Parser::new(signature.as_bytes())
            .parse_dictionary()
            .unwrap()
        {
            let ListEntry::Item(Item {
                bare_item: BareItem::ByteSequence(signature),
                ..
            }) = signature
            else {
                return Err(InvalidFormat::ByteSequence)?;
            };
            signatures.insert(key.to_string(), signature);
        }

        Ok(Self(signatures))
    }

    pub fn get(&self, key: &str) -> Result<&[u8], SignatureError> {
        self.0
            .get(key)
            .map(AsRef::as_ref)
            .ok_or(SignatureError::NotExist(key.to_string()))
    }
}
