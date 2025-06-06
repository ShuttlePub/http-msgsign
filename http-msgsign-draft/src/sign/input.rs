use crate::errors::{HttpPayloadSeekError, InvalidValue, SignatureInputError};
use crate::sign::SignatureBase;
use crate::sign::field::{CREATED, EXPIRES, REQUEST_TARGET, TargetField, TimeOrDuration};
use base64::Engine;
use http::{HeaderMap, HeaderName, Request, Response};
use indexmap::{IndexSet, indexset};
use std::collections::HashMap;
use std::str::FromStr;

#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct SignatureInput {
    pub key_id: String,
    pub algorithm: String,
    pub created: Option<u64>,
    pub expires: Option<u64>,
    pub headers: IndexSet<TargetField>,
    pub signature: Vec<u8>,
}

impl SignatureInput {
    pub fn seek_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<SignatureBase, HttpPayloadSeekError> {
        let seeked = self
            .headers
            .iter()
            .map(|target| target.seek_request(request))
            .collect::<Result<IndexSet<_>, _>>()?;

        Ok(SignatureBase::from_components(seeked))
    }

    pub fn seek_response<B>(
        &self,
        response: &Response<B>,
    ) -> Result<SignatureBase, HttpPayloadSeekError> {
        let seeked = self
            .headers
            .iter()
            .map(|target| target.seek_response(response))
            .collect::<Result<IndexSet<_>, _>>()?;

        Ok(SignatureBase::from_components(seeked))
    }

    pub fn from_header(header: &HeaderMap) -> Result<SignatureInput, SignatureInputError> {
        // Look for the Signature header defined in the RFC,
        // or if none, look for the Authorization header and get its value.
        // In the case of an Authorization header,
        // remove the `Signature ` prefix and set the value to the same state as the value of the Signature header.
        let params = match header.get("signature") {
            Some(params) => params.to_str(),
            None => match header.get(http::header::AUTHORIZATION) {
                Some(params) => params
                    .to_str()
                    .map(|params| params.strip_prefix("Signature ").unwrap()),
                None => return Err(SignatureInputError::NotExist),
            },
        }
        .map_err(|_| InvalidValue::String)?;

        Self::parse(params)
    }

    fn parse(value: &str) -> Result<SignatureInput, SignatureInputError> {
        let params = value
            .split(',')
            .flat_map(|st| st.split_once('='))
            .map(|(key, value)| (key, value.trim_matches('"')))
            .collect::<HashMap<&str, &str>>();

        let Some(key_id) = params.get("keyId") else {
            return Err(SignatureInputError::RequireParameter("keyId"));
        };

        // This is not required within the document (also RECOMMENDED) but would be almost mandatory.
        let Some(algorithm) = params.get("algorithm") else {
            return Err(SignatureInputError::RequireParameter("algorithm"));
        };

        let created = params
            .get("created")
            .map(|s| u64::from_str(s))
            .transpose()
            .map_err(|_| InvalidValue::Integer)?;

        let expires = params
            .get("expires")
            .map(|s| u64::from_str(s))
            .transpose()
            .map_err(|_| InvalidValue::Integer)?;

        let headers = match params.get("headers") {
            None => {
                if created.is_none() {
                    return Err(SignatureInputError::RequireParameter("created"));
                }

                // If not specified, implementations MUST operate as if the field were specified
                // with a single value, `(created)`, in the list of HTTP headers.
                indexset! {
                    TargetField::Created(created)
                }
            }
            Some(headers) => headers
                .split(' ')
                .map(|field| {
                    Ok(match field {
                        REQUEST_TARGET => TargetField::RequestTarget,
                        CREATED => {
                            if created.is_none() {
                                return Err(SignatureInputError::RequireParameter("created"));
                            }
                            TargetField::Created(created)
                        }
                        EXPIRES => TargetField::Expires(TimeOrDuration::Time(
                            expires.ok_or(SignatureInputError::RequireParameter("expires"))?,
                        )),
                        header => TargetField::HeaderField(HeaderName::from_str(header).unwrap()),
                    })
                })
                .collect::<Result<IndexSet<TargetField>, _>>()?,
        };

        // A zero-length `headers` parameter value MUST NOT be used.
        if headers.is_empty() {
            return Err(InvalidValue::NonEmptyArray)?;
        }

        let Some(signature) = params
            .get("signature")
            .map(|encoded| base64::engine::general_purpose::STANDARD.decode(encoded))
            .transpose()
            .unwrap()
        else {
            return Err(SignatureInputError::RequireParameter("signature"));
        };

        Ok(Self {
            key_id: key_id.to_string(),
            algorithm: algorithm.to_string(),
            created,
            expires,
            headers,
            signature,
        })
    }
}
