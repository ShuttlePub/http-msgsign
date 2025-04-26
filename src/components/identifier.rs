use std::fmt::Display;

use crate::components::Derive;
use crate::errors::InvalidFormat;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Identifier {
    Derived(Derive),
    Standard(http::HeaderName),
}

impl Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Identifier::Derived(derived) => Display::fmt(&derived, f),
            Identifier::Standard(name) => write!(f, "\"{name}\""),
        }
    }
}

impl From<http::HeaderName> for Identifier {
    fn from(value: http::HeaderName) -> Self {
        Self::Standard(value)
    }
}

impl TryFrom<sfv::BareItem> for Identifier {
    type Error = InvalidFormat;

    fn try_from(value: sfv::BareItem) -> Result<Self, Self::Error> {
        if Derive::contains(&value) {
            Derive::try_from(value).map(Identifier::Derived)
        } else {
            let sfv::BareItem::String(ident) = value else {
                return Err(InvalidFormat::String);
            };
            Ok(Identifier::Standard(
                http::HeaderName::try_from(String::from(ident))
                    .map_err(|e| InvalidFormat::HeaderName(e.into()))?,
            ))
        }
    }
}
