mod derived;
mod identifier;
mod parameters;
mod name;

pub use self::{
    identifier::*,
    name::*,
    derived::*,
    parameters::*,
};

use std::fmt::{Display, Formatter};


/// Canonical HTTP messages as per the rules defined in [RFC9421 HTTP Message Components](https://datatracker.ietf.org/doc/html/rfc9421#name-http-message-components)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct HttpComponent {
    id: Identifier,
    value: Option<String>
}

impl HttpComponent {
    pub fn new(id: impl Into<Identifier>, value: Option<String>) -> HttpComponent {
        Self { id: id.into(), value }
    }
    
    pub fn id(&self) -> &Identifier {
        &self.id
    }
    
    pub fn value(&self) -> Option<&String> {
        self.value.as_ref()
    }
}

impl Display for HttpComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Empty HTTP fields can also be signed when present in a message.
        // https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-13
        let value = match self.value {
            Some(ref value) => value.to_string(),
            None => String::new()
        };
        write!(f, "{}: {}", self.id, value)
    }
}