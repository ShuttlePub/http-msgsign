use crate::components::parameter::Name;
use crate::components::{HttpComponent, Identifier, NameType, FieldParameter, FieldParameters, ToComponent};
use crate::errors::{HttpFieldComponentError, InvalidDerivedComponent, InvalidFormat};
use std::fmt::Display;

pub fn method() -> (Derived, FieldParameters) {
    (Derived::Method, FieldParameters::default())
}

pub fn target_uri() -> (Derived, FieldParameters) {
    (Derived::TargetUri, FieldParameters::default())
}

pub fn authority() -> (Derived, FieldParameters) {
    (Derived::Authority, FieldParameters::default())
}

pub fn scheme() -> (Derived, FieldParameters) {
    (Derived::Scheme, FieldParameters::default())
}

pub fn request_target() -> (Derived, FieldParameters) {
    (Derived::RequestTarget, FieldParameters::default())
}

pub fn path() -> (Derived, FieldParameters) {
    (Derived::Path, FieldParameters::default())
}

pub fn query() -> (Derived, FieldParameters) {
    (Derived::Query, FieldParameters::default())
}

pub fn query_param(name: impl Into<String>) -> (Derived, FieldParameters) {
    let params = FieldParameters::default().append(FieldParameter::Name(name.into()));
    (Derived::QueryParam, params)
}

pub fn status() -> (Derived, FieldParameters) {
    (Derived::Status, FieldParameters::default())
}

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
    QueryParam,
    Status,
}

impl AsRef<str> for Derived {
    fn as_ref(&self) -> &str {
        match self {
            Derived::Method => "@method",
            Derived::TargetUri => "@target-uri",
            Derived::Authority => "@authority",
            Derived::Scheme => "@scheme",
            Derived::RequestTarget => "@request-target",
            Derived::Path => "@path",
            Derived::Query => "@query",
            Derived::QueryParam => "@query-param",
            Derived::Status => "@status",
        }
    }
}

/// See [RFC9421 HTTP Message Signatures §2.2-2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.2-2)
impl Display for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self.as_ref())
    }
}

impl From<Derived> for NameType {
    fn from(derived: Derived) -> Self {
        NameType::Derived(derived)
    }
}

impl From<Derived> for Identifier {
    fn from(derived: Derived) -> Self {
        Identifier::new(derived.into(), FieldParameters::default())
    }
}

impl ToComponent for Derived {
    type Parameters = FieldParameters;

    fn to_component_with_request<B>(
        &self,
        request: &http::Request<B>,
        params: &Self::Parameters,
    ) -> Result<HttpComponent, HttpFieldComponentError> {
        Ok(match self {
            Derived::Method => HttpComponent {
                id: self.to_string(),
                value: Some(request.method().to_string()),
            },
            Derived::TargetUri => HttpComponent {
                id: self.to_string(),
                value: Some(request.uri().to_string()),
            },
            Derived::Authority => HttpComponent {
                id: self.to_string(),
                value: request
                    .uri()
                    .authority()
                    .map(|authority| authority.to_string()),
            },
            Derived::Scheme => HttpComponent {
                id: self.to_string(),
                value: request.uri().scheme().map(|scheme| scheme.to_string()),
            },
            Derived::RequestTarget => HttpComponent {
                id: self.to_string(),
                value: request
                    .uri()
                    .path_and_query()
                    .map(|req_target| req_target.to_string()),
            },
            Derived::Path => HttpComponent {
                id: self.to_string(),
                value: Some(request.uri().path().to_string()),
            },
            Derived::Query => HttpComponent {
                id: self.to_string(),
                value: request.uri().query().map(|query| query.to_string()),
            },
            Derived::QueryParam => HttpComponent {
                id: self.to_string(),
                value: extract_query_value(params, request)?.map(|val| val.to_string()),
            },
            _ => {
                return Err(HttpFieldComponentError::UnsupportedComponent(
                    self.to_string(),
                ));
            }
        })
    }
}

impl TryFrom<sfv::BareItem> for Derived {
    type Error = InvalidFormat;

    fn try_from(item: sfv::BareItem) -> Result<Self, Self::Error> {
        let sfv::BareItem::String(ident) = item else {
            return Err(InvalidFormat::String);
        };

        Ok(match ident.as_str() {
            "@method" => Derived::Method,
            "@target-uri" => Derived::TargetUri,
            "@authority" => Derived::Authority,
            "@scheme" => Derived::Scheme,
            "@request-target" => Derived::RequestTarget,
            "@path" => Derived::Path,
            "@query" => Derived::Query,
            "@query-param" => Derived::QueryParam,
            "@status" => Derived::Status,
            _ => return Err(InvalidDerivedComponent)?,
        })
    }
}

impl Derived {
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
    params: &'a FieldParameters,
    req: &'a http::Request<B>,
) -> Result<Option<&'a str>, HttpFieldComponentError> {
    let Some(FieldParameter::Name(require)) = params.iter().find(|name| name.eq(&&Name)) else {
        return Err(HttpFieldComponentError::UnmetRequirement {
            reason: "`@query-param` must have a `name` parameter. https://datatracker.ietf.org/doc/html/rfc9421#section-2.2.8-1",
        });
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
