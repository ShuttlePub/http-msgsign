pub mod derive;
mod identifier;
mod name;
mod parameters;

pub use self::{derive::Derived, identifier::*, name::*, parameters::*};

use crate::errors::HttpFieldComponentError;
use std::fmt::{Display, Formatter};

/// Canonical HTTP messages as per the rules defined in [RFC9421 HTTP Message Components](https://datatracker.ietf.org/doc/html/rfc9421#name-http-message-components)
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct HttpComponent {
    pub(crate) id: String,
    pub(crate) value: Option<String>,
}

pub trait ToComponent {
    type Parameters;
    fn to_component_with_request<B>(
        &self,
        request: &http::Request<B>,
        params: &Self::Parameters,
    ) -> Result<HttpComponent, HttpFieldComponentError>;
    fn to_component_with_response<B>(
        &self,
        response: &http::Response<B>,
        params: &Self::Parameters,
    ) -> Result<HttpComponent, HttpFieldComponentError> {
        todo!()
    }
}

impl Display for HttpComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Empty HTTP fields can also be signed when present in a message.
        // https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-13
        match self.value {
            Some(ref value) => write!(f, "{}: {}", self.id, value),
            None => write!(f, "{}: ", self.id),
        }
    }
}
