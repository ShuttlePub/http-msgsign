use std::fmt::Display;
use crate::sign::components::Derived;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum NameType {
    Standard(http::HeaderName),
    Derived(Derived),
    SignatureParams,
}

impl Display for NameType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameType::Standard(name) => write!(f, "\"{name}\""),
            NameType::Derived(derived) => Display::fmt(&derived, f),
            NameType::SignatureParams => f.write_str("\"@signature-params\""),
        }
    }
}

impl From<http::HeaderName> for NameType {
    fn from(value: http::HeaderName) -> Self {
        Self::Standard(value)
    }
}