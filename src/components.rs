pub mod derive;
mod field;
mod identifier;
pub mod params;
pub(crate) mod values;

pub use self::{derive::Derive, field::*, identifier::*};

use std::fmt::{Display, Formatter};

use http::{Request, Response};

use crate::errors::HttpComponentError;
use crate::sign::ExchangeRecord;

/// Canonical HTTP messages as per the rules defined in [RFC9421 HTTP Message Components](https://datatracker.ietf.org/doc/html/rfc9421#name-http-message-components)
#[derive(Debug, Eq, PartialEq, Hash)]
pub struct HttpComponent {
    pub(crate) id: String,
    pub(crate) value: Option<String>,
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

pub trait ToComponent {
    fn to_component(&self, target_field: &TargetField) -> Result<HttpComponent, HttpComponentError>;
}


impl<B> ToComponent for Request<B> {
    fn to_component(&self, target_field: &TargetField) -> Result<HttpComponent, HttpComponentError> {
        target_field.seek_request(self)
    }
}

impl<B> ToComponent for Response<B> {
    fn to_component(&self, target_field: &TargetField) -> Result<HttpComponent, HttpComponentError> {
        target_field.seek_response(self)
    }
}

impl<Req, Res> ToComponent for ExchangeRecord<'_, Req, Res> {
    fn to_component(&self, target_field: &TargetField) -> Result<HttpComponent, HttpComponentError> {
        target_field.seek_record(self)
    }
}
