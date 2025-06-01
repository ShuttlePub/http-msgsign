use crate::errors::{HttpPayloadSeekError, InvalidValue};
use crate::sign::component::SignBaseComponent;
use http::{HeaderMap, HeaderName, Request, Response};
use std::time::{Duration, SystemTime};

pub const REQUEST_TARGET: &str = "(request-target)";
pub const CREATED: &str = "(created)";
pub const EXPIRES: &str = "(expires)";

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum TargetField {
    RequestTarget,
    Created(Option<u64>),
    Expires(TimeOrDuration),
    HeaderField(HeaderName),
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub(crate) enum TimeOrDuration {
    Time(u64),
    Duration(Duration),
}

impl TargetField {
    //noinspection DuplicatedCode
    pub fn seek_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<SignBaseComponent, HttpPayloadSeekError> {
        match self {
            TargetField::RequestTarget => {
                let value = format!(
                    "{} {}",
                    request.method().as_str().to_ascii_lowercase(),
                    request
                        .uri()
                        .path_and_query()
                        .map(|paq| paq.as_str())
                        .unwrap(),
                );
                Ok(SignBaseComponent {
                    id: REQUEST_TARGET.to_string(),
                    value: Some(value),
                })
            }
            TargetField::Created(at) => {
                let at = at.or_else(|| {
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                });

                Ok(SignBaseComponent {
                    id: CREATED.to_string(),
                    value: at.map(|t| t.to_string()),
                })
            }
            TargetField::Expires(at) => {
                let at = match at {
                    TimeOrDuration::Time(at) => Some(at.to_owned()),
                    TimeOrDuration::Duration(duration) => SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|delta| delta.as_secs() + duration.as_secs()),
                };

                Ok(SignBaseComponent {
                    id: EXPIRES.to_string(),
                    value: at.map(|t| t.to_string()),
                })
            }
            TargetField::HeaderField(name) => Ok(SignBaseComponent {
                id: name.to_string(),
                value: extract_header_value(name, request.headers())?,
            }),
        }
    }

    //noinspection DuplicatedCode
    pub fn seek_response<B>(
        &self,
        response: &Response<B>,
    ) -> Result<SignBaseComponent, HttpPayloadSeekError> {
        match self {
            TargetField::RequestTarget => Err(HttpPayloadSeekError::InvalidTarget {
                target: "response",
                incompatible: REQUEST_TARGET,
            }),
            TargetField::Created(at) => {
                let at = at.or_else(|| {
                    SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|d| d.as_secs())
                });

                Ok(SignBaseComponent {
                    id: "(created)".to_string(),
                    value: at.map(|t| t.to_string()),
                })
            }
            TargetField::Expires(at) => {
                let at = match at {
                    TimeOrDuration::Time(at) => Some(at.to_owned()),
                    TimeOrDuration::Duration(duration) => SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .ok()
                        .map(|delta| delta.as_secs() + duration.as_secs()),
                };

                Ok(SignBaseComponent {
                    id: "(expires)".to_string(),
                    value: at.map(|t| t.to_string()),
                })
            }
            TargetField::HeaderField(name) => Ok(SignBaseComponent {
                id: name.to_string(),
                value: extract_header_value(name, response.headers())?,
            }),
        }
    }
}

//noinspection DuplicatedCode
fn extract_header_value(
    name: &HeaderName,
    map: &HeaderMap,
) -> Result<Option<String>, InvalidValue> {
    match map
        .get_all(name)
        .iter()
        .map(|value| value.to_str().map(|st| st.to_string()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(ascii_values) => {
            let normalized = ascii_values
                .into_iter()
                .reduce(|mut acc, next| {
                    acc += &format!(", {}", next);
                    acc
                })
                .map(|joined| joined.trim_ascii().to_string());

            Ok(normalized)
        }
        Err(_) => Err(InvalidValue::String),
    }
}
