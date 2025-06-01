use std::time::Duration;

use http::{Request, Response};
use indexmap::IndexSet;

use crate::errors::{HttpPayloadSeekError, SignatureParamsError};
use crate::sign::SignatureBase;
use crate::sign::field::{TargetField, TimeOrDuration};

#[derive(Debug, Clone)]
pub struct SignatureParams {
    targets: IndexSet<TargetField>,
}

pub struct SignatureParamsBuilder {
    builder: Result<SignatureParams, SignatureParamsError>,
}

impl SignatureParams {
    pub fn builder() -> SignatureParamsBuilder {
        SignatureParamsBuilder {
            builder: Ok(SignatureParams {
                targets: Default::default(),
            }),
        }
    }

    pub(crate) fn seek_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<SignatureBase, HttpPayloadSeekError> {
        let seeked = self
            .targets
            .iter()
            .map(|target| target.seek_request(request))
            .collect::<Result<IndexSet<_>, _>>()?;

        Ok(SignatureBase::from_components(seeked))
    }

    pub(crate) fn seek_response<B>(
        &self,
        response: &Response<B>,
    ) -> Result<SignatureBase, HttpPayloadSeekError> {
        let seeked = self
            .targets
            .iter()
            .map(|target| target.seek_response(response))
            .collect::<Result<IndexSet<_>, _>>()?;

        Ok(SignatureBase::from_components(seeked))
    }
}

impl SignatureParamsBuilder {
    pub fn add_header<H>(self, header: H) -> Self
    where
        H: TryInto<http::HeaderName>,
        H::Error: Into<http::Error>,
    {
        self.and_then(|mut params| {
            let header = header.try_into().map_err(Into::into)?;
            params.targets.insert(TargetField::HeaderField(header));
            Ok(params)
        })
    }

    pub fn add_request_target(self) -> Self {
        self.and_then(|mut params| {
            params.targets.insert(TargetField::RequestTarget);
            Ok(params)
        })
    }

    pub fn set_created(self) -> Self {
        self.and_then(|mut params| {
            params.targets.insert(TargetField::Created(None));
            Ok(params)
        })
    }

    pub fn set_expires(self, expires: impl Into<Duration>) -> Self {
        self.and_then(|mut params| {
            params
                .targets
                .insert(TargetField::Expires(TimeOrDuration::Duration(
                    expires.into(),
                )));
            Ok(params)
        })
    }

    pub fn build(self) -> Result<SignatureParams, SignatureParamsError> {
        // If not specified, implementations MUST operate as if the field were specified
        // with a single value, `(created)`, in the list of HTTP headers.
        self.builder.map(|mut params| {
            if params.targets.is_empty() {
                params.targets.insert(TargetField::Created(None));
            }
            Ok(params)
        })?
    }

    fn and_then<F>(self, f: F) -> Self
    where
        F: FnOnce(SignatureParams) -> Result<SignatureParams, SignatureParamsError>,
    {
        Self {
            builder: self.builder.and_then(f),
        }
    }
}
