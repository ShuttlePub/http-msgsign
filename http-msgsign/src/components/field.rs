use std::fmt::{Display, Formatter};

use http::{Request, Response};

use crate::components::params::{FieldParameter, Serializer};
use crate::components::values::Value;
use crate::components::{HttpComponent, NameType};
use crate::errors::{HttpComponentError, InvalidFormat, InvalidSerializer};
use crate::sign::ExchangeRecord;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct TargetField {
    name: NameType,
    params: Serializer,
}

impl Display for TargetField {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.name, self.params)
    }
}

// noinspection DuplicatedCode
impl TargetField {
    pub fn new(name: NameType, params: FieldParameter) -> Result<Self, InvalidSerializer> {
        Ok(Self {
            name,
            params: params.into_serializer()?,
        })
    }

    pub(crate) fn seek_request<B>(
        &self,
        request: &Request<B>,
    ) -> Result<HttpComponent, HttpComponentError> {
        if self.params.require_request() {
            return Err(HttpComponentError::InvalidDataType {
                expect: "response with request",
            });
        }

        match &self.name {
            NameType::Derived(derive) => Ok(HttpComponent {
                id: self.to_string(),
                value: derive.seek_request(request, &self.params)?,
            }),
            NameType::Field(target) => {
                let val = Value::from_header(target, request.headers())
                    .serialize(&self.params)?;
                Ok(HttpComponent {
                    id: self.to_string(),
                    value: Some(val),
                })
            }
        }
    }

    pub(crate) fn seek_response<B>(
        &self,
        response: &Response<B>,
    ) -> Result<HttpComponent, HttpComponentError> {
        if self.params.require_request() {
            return Err(HttpComponentError::InvalidDataType {
                expect: "response with request",
            });
        }

        match &self.name {
            NameType::Derived(derive) => Ok(HttpComponent {
                id: self.to_string(),
                value: derive.seek_response(response)?,
            }),
            NameType::Field(target) => {
                let val = Value::from_header(target, response.headers())
                    .serialize(&self.params)?;
                Ok(HttpComponent {
                    id: self.to_string(),
                    value: Some(val),
                })
            }
        }
    }

    pub(crate) fn seek_record<Req, Res>(
        &self,
        ExchangeRecord { request, response }: &ExchangeRecord<Req, Res>,
    ) -> Result<HttpComponent, HttpComponentError> {
        if self.params.require_request() {
            match &self.name {
                NameType::Derived(derive) => Ok(HttpComponent {
                    id: self.to_string(),
                    value: derive.seek_request(request, &self.params)?,
                }),
                NameType::Field(target) => {
                    let val = Value::from_header(target, request.headers())
                        .serialize(&self.params)?;
                    Ok(HttpComponent {
                        id: self.to_string(),
                        value: Some(val),
                    })
                }
            }
        } else {
            match &self.name {
                NameType::Derived(derive) => Ok(HttpComponent {
                    id: self.to_string(),
                    value: derive.seek_response(response)?,
                }),
                NameType::Field(target) => {
                    let val = Value::from_header(target, response.headers())
                        .serialize(&self.params)?;
                    Ok(HttpComponent {
                        id: self.to_string(),
                        value: Some(val),
                    })
                }
            }
        }
    }
}

impl TryFrom<sfv::Item> for TargetField {
    type Error = InvalidFormat;

    fn try_from(sfv::Item { bare_item, params }: sfv::Item) -> Result<Self, Self::Error> {
        Ok(Self {
            name: NameType::try_from(bare_item)?,
            params: Serializer::try_from(params).unwrap(),
        })
    }
}
