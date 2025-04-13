use std::fmt::Display;

use crate::components::Derived;
use crate::errors::InvalidFormat;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NameType {
    Standard(http::HeaderName),
    Derived(Derived),
}

impl Display for NameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameType::Standard(name) => write!(f, "\"{name}\""),
            NameType::Derived(derived) => Display::fmt(&derived, f),
        }
    }
}

impl From<http::HeaderName> for NameType {
    fn from(value: http::HeaderName) -> Self {
        Self::Standard(value)
    }
}

impl TryFrom<sfv::BareItem> for NameType {
    type Error = InvalidFormat;

    fn try_from(value: sfv::BareItem) -> Result<Self, Self::Error> {
        if Derived::contains(&value) {
            Derived::try_from(value).map(NameType::Derived)
        } else {
            let sfv::BareItem::String(ident) = value else {
                return Err(InvalidFormat::String);
            };
            Ok(NameType::Standard(
                http::HeaderName::try_from(String::from(ident))
                    .map_err(|e| InvalidFormat::HeaderName(e.into()))?,
            ))
        }
    }
}
