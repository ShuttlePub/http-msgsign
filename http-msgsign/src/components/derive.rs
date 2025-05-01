use std::fmt::Display;

use http::{Request, Response};

use crate::components::params::Serializer;
use crate::components::NameType;
use crate::errors::{HttpComponentError, InvalidDerivedComponent, InvalidFormat};

/// See [RFC9421 HTTP Message Signatures §2.2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Derive {
    Method,
    TargetUri,
    Authority,
    Scheme,
    RequestTarget,
    Path,
    Query,
    QueryParam,
    Status,
}

impl AsRef<str> for Derive {
    fn as_ref(&self) -> &str {
        match self {
            Derive::Method => "@method",
            Derive::TargetUri => "@target-uri",
            Derive::Authority => "@authority",
            Derive::Scheme => "@scheme",
            Derive::RequestTarget => "@request-target",
            Derive::Path => "@path",
            Derive::Query => "@query",
            Derive::QueryParam => "@query-param",
            Derive::Status => "@status",
        }
    }
}

/// See [RFC9421 HTTP Message Signatures §2.2-2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2-2)
impl Display for Derive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.as_ref())
    }
}

impl From<Derive> for NameType {
    fn from(derived: Derive) -> Self {
        NameType::Derived(derived)
    }
}

impl Derive {
    /// Reference [RFC9421 HTTP Message Signatures §6.4.2](https://datatracker.ietf.org/doc/html/rfc9421#name-initial-contents-3)
    pub fn seek_request<B>(
        &self, 
        request: &Request<B>, 
        params: &Serializer
    ) -> Result<Option<String>, HttpComponentError> {
        Ok(match self {
            Derive::Method => Some(request.method().to_string()),
            Derive::TargetUri => Some(request.uri().to_string()),
            Derive::Authority => {
                request
                    .uri()
                    .authority()
                    .map(|authority| authority.to_string())
            } 
            Derive::Scheme => request.uri().scheme().map(|scheme| scheme.to_string()),
            Derive::RequestTarget => {
                request
                    .uri()
                    .path_and_query()
                    .map(|req_target| req_target.to_string())
            }
            Derive::Path => Some(request.uri().path().to_string()),
            Derive::Query => request.uri().query().map(|query| query.to_string()),
            Derive::QueryParam => {
                extract_query_value(params, request)?.map(|val| val.to_string())
            },
            _ => {
                return Err(HttpComponentError::UnsupportedComponent(
                    self.to_string(),
                ));
            }
        })
    }
    
    pub fn seek_response<B>(
        &self, 
        response: &Response<B>, 
    ) -> Result<Option<String>, HttpComponentError> {
        Ok(match self {
            Derive::Status => Some(response.status().as_u16().to_string()),
            _ => {
                return Err(HttpComponentError::UnsupportedComponent(
                    self.to_string(),
                ));
            }
        })
    }
}


impl TryFrom<sfv::BareItem> for Derive {
    type Error = InvalidFormat;

    fn try_from(item: sfv::BareItem) -> Result<Self, Self::Error> {
        let sfv::BareItem::String(ident) = item else {
            return Err(InvalidFormat::String);
        };

        Ok(match ident.as_str() {
            "@method" => Derive::Method,
            "@target-uri" => Derive::TargetUri,
            "@authority" => Derive::Authority,
            "@scheme" => Derive::Scheme,
            "@request-target" => Derive::RequestTarget,
            "@path" => Derive::Path,
            "@query" => Derive::Query,
            "@query-param" => Derive::QueryParam,
            "@status" => Derive::Status,
            _ => return Err(InvalidDerivedComponent)?,
        })
    }
}

impl Derive {
    pub fn contains(other: &sfv::BareItem) -> bool {
        if let sfv::BareItem::String(ident) = other {
            let ident = ident.as_str();
            ident == "@method"
                || ident == "@target-uri"
                || ident == "@authority"
                || ident == "@scheme"
                || ident == "@request-target"
                || ident == "@path"
                || ident == "@query"
                || ident == "@query-param"
                || ident == "@status"
        } else {
            false
        }
    }
}

fn extract_query_value<'a, B>(
    params: &'a Serializer,
    req: &'a Request<B>,
) -> Result<Option<&'a str>, HttpComponentError> {
    let Some(require) = params.name() else {
        return Err(HttpComponentError::UnmetRequirement {
            reason: "`@query-param` must have a `name` parameter. https://datatracker.ietf.org/doc/html/rfc9421#section-2.2.8-1",
        })
    };

    let Some(query) = req.uri().query().map(|params| {
        params
            .split("&")
            .map(|kv| kv.split("=").collect::<Vec<_>>())
            .collect::<Vec<_>>()
    }) else {
        return Ok(None);
    };
    let value = query.iter().find(|kv| kv[0] == require).map(|kv| kv[1]);
    Ok(value.to_owned())
}
