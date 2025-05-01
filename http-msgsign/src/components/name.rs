use std::fmt::Display;

use crate::components::Derive;
use crate::errors::InvalidFormat;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NameType {
    Derived(Derive),
    Field(http::HeaderName),
}

impl Display for NameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameType::Derived(derived) => Display::fmt(&derived, f),
            NameType::Field(name) => write!(f, "\"{name}\""),
        }
    }
}

impl From<http::HeaderName> for NameType {
    fn from(value: http::HeaderName) -> Self {
        Self::Field(value)
    }
}

impl TryFrom<sfv::BareItem> for NameType {
    type Error = InvalidFormat;

    fn try_from(value: sfv::BareItem) -> Result<Self, Self::Error> {
        if Derive::contains(&value) {
            Derive::try_from(value).map(NameType::Derived)
        } else {
            let sfv::BareItem::String(ident) = value else {
                return Err(InvalidFormat::String);
            };
            Ok(NameType::Field(
                http::HeaderName::try_from(String::from(ident))
                    .map_err(|e| InvalidFormat::HeaderName(e.into()))?,
            ))
        }
    }
}
