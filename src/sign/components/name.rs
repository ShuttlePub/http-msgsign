use std::fmt::Display;
use crate::sign::components::Derived;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Name {
    Standard(http::HeaderName),
    Derived(Derived),
    SignatureParams,
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Name::Standard(name) => write!(f, "\"{name}\""),
            Name::Derived(derived) => Display::fmt(&derived, f),
            Name::SignatureParams => f.write_str("\"@signature-params\""),
        }
    }
}

impl From<http::HeaderName> for Name {
    fn from(value: http::HeaderName) -> Self {
        Self::Standard(value)
    }
}