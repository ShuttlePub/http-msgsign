use http::Request;
use std::fmt::Display;

use crate::sign::components::{HttpComponent, Identifier, NameType, Parameters};

/// See [RFC9421 HTTP Message Signatures §2.2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Derived {
    Method,
    TargetUri,
    Authority,
    Scheme,
    RequestTarget,
    Path,
    Query,
    QueryParam(String),
    Status,
}

/// See [RFC9421 HTTP Message Signatures §2.2-2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2-2)
impl Display for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Derived::Method => f.write_str("\"@method\""),
            Derived::TargetUri => f.write_str("\"@target-uri\""),
            Derived::Authority => f.write_str("\"@authority\""),
            Derived::Scheme => f.write_str("\"@scheme\""),
            Derived::RequestTarget => f.write_str("\"@request-target\""),
            Derived::Path => f.write_str("\"@path\""),
            Derived::Query => f.write_str("\"@query\""),
            Derived::QueryParam(name) => f.write_fmt(format_args!("\"@query-param\";name=\"{name}\"")),
            Derived::Status => f.write_str("\"@status\""),
        }
    }
}

impl From<Derived> for NameType {
    fn from(derived: Derived) -> Self {
        NameType::Derived(derived)
    }
}

impl From<Derived> for Identifier {
    fn from(derived: Derived) -> Self {
        Identifier::new(derived.into(), Parameters::default())
    }
}

impl Derived {
    pub fn parse_request<B>(self, req: &Request<B>) -> HttpComponent {
        match self {
            Derived::Method => {
                HttpComponent::new(self, Some(req.method().to_string()))
            }
            Derived::TargetUri => {
                HttpComponent::new(self, Some(req.uri().to_string()))
            }
            Derived::Authority => {
                HttpComponent::new(self, req.uri().authority().map(|authority| authority.to_string()))
            }
            Derived::Scheme => {
                HttpComponent::new(self, req.uri().scheme().map(|scheme| scheme.to_string()))
            }
            Derived::RequestTarget => {
                HttpComponent::new(self, req.uri().path_and_query().map(|req_target| req_target.to_string()))
            }
            Derived::Path => {
                HttpComponent::new(self, Some(req.uri().path().to_string()))
            }
            Derived::Query => {
                HttpComponent::new(self, Some(req.uri().query().unwrap_or("?")).map(|query| query.to_string()))
            }
            Derived::QueryParam(ref name) => {
                let query = req.uri().query().unwrap()
                    .split("&")
                    .map(|kv| kv.split("=").collect::<Vec<_>>())
                    .collect::<Vec<_>>();
                let value = query.iter()
                    .find(|kv| kv[0] == name)
                    .map(|kv| kv[1]);
                HttpComponent::new(self, value.map(|val| val.to_string()))
            }
            _ => {
                unimplemented!()
            }
        }
    }
}