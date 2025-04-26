use std::collections::HashMap;

use indexmap::IndexSet;
use sfv::{BareItem, InnerList, ListEntry};

use crate::components::TargetField;
use crate::errors::{InvalidFormat, SignatureInputError};

#[derive(Debug, Default)]
pub struct SignatureInput {
    pub(crate) covered: IndexSet<TargetField>,
    pub(crate) created: Option<u64>,
    pub(crate) expires: Option<u64>,
    pub(crate) algorithm: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) tag: Option<String>,
}

impl SignatureInput {
    pub fn from_header(
        header: &http::HeaderMap,
    ) -> Result<HashMap<String, SignatureInput>, SignatureInputError> {
        let Some(input) = header.get(crate::sign::header::SIGNATURE_INPUT) else {
            return Err(SignatureInputError::NotExistInHeader);
        };

        let dictionary = sfv::Parser::new(input.as_bytes())
            .parse_dictionary()
            .map_err(InvalidFormat::Dictionary)?;

        let mut profiles: HashMap<String, SignatureInput> = HashMap::new();
        for (key, entry) in dictionary {
            let mut input = SignatureInput::default();
            let ListEntry::InnerList(InnerList { items, params }) = entry else {
                return Err(InvalidFormat::InnerList)?;
            };

            let covered = items
                .into_iter()
                .map(TargetField::try_from)
                .collect::<Result<IndexSet<_>, InvalidFormat>>()?;

            input.covered = covered;
            input.assign_parameters(params)?;

            profiles.insert(key.into(), input);
        }

        Ok(profiles)
    }

    //noinspection SpellCheckingInspection
    fn assign_parameters(&mut self, params: sfv::Parameters) -> Result<(), SignatureInputError> {
        for (key, item) in params {
            match (key.as_str(), item) {
                ("created", BareItem::Integer(created)) => {
                    self.created = Some(created.try_into().map_err(InvalidFormat::Integer)?)
                }
                ("expires", BareItem::Integer(expires)) => {
                    self.expires = Some(expires.try_into().map_err(InvalidFormat::Integer)?)
                }
                ("alg", BareItem::String(alg)) => self.algorithm = Some(alg.into()),
                ("keyid", BareItem::String(key_id)) => self.key_id = Some(key_id.into()),
                ("nonce", BareItem::String(nonce)) => self.nonce = Some(nonce.into()),
                ("tag", BareItem::String(tag)) => self.tag = Some(tag.into()),
                _ => { /* No-op ;P */ }
            }
        }
        Ok(())
    }
}
