use std::fmt::{Display, Formatter};

use http::Request;

use crate::components::{HttpComponent, NameType, FieldParameters, ToComponent};
use crate::errors::{HttpFieldComponentError, InvalidFormat};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Identifier {
    name: NameType,
    params: FieldParameters,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.name, self.params)
    }
}

impl Identifier {
    pub fn new(name: NameType, params: FieldParameters) -> Self {
        Self { name, params }
    }
}

impl ToComponent for Identifier {
    type Parameters = ();

    fn to_component_with_request<B>(
        &self,
        request: &Request<B>,
        _: &Self::Parameters,
    ) -> Result<HttpComponent, HttpFieldComponentError> {
        match &self.name {
            NameType::Derived(derived) => derived.to_component_with_request(request, &self.params),
            NameType::Standard(covered) => {
                let val = request
                    .headers()
                    .get_all(covered)
                    .into_iter()
                    .map(|value| value.to_str())
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                if val.is_empty() {
                    Ok(HttpComponent {
                        id: self.name.to_string(),
                        value: None,
                    })
                } else {
                    Ok(HttpComponent {
                        id: self.name.to_string(),
                        value: Some(val.join(", ")),
                    })
                }
            }
        }
    }
}

impl TryFrom<sfv::Item> for Identifier {
    type Error = InvalidFormat;

    fn try_from(sfv::Item { bare_item, params }: sfv::Item) -> Result<Self, Self::Error> {
        Ok(Self {
            name: NameType::try_from(bare_item)?,
            params: FieldParameters::from(params),
        })
    }
}
