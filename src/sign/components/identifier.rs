use std::fmt::{Display, Formatter};
use crate::sign::components::{HttpComponent, Name, Parameters};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Identifier {
    name: Name,
    params: Parameters
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.name, self.params)
    }
}

impl Identifier {
    pub fn new(name: Name, params: Parameters) -> Self {
        Self { name, params }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn params(&self) -> &Parameters {
        &self.params
    }
}

impl Identifier {
    pub fn parse_request<B>(self, req: &http::Request<B>) -> HttpComponent {
        if let Name::Standard(ref covered) = self.name {
            let val = req.headers()
                .get_all(covered)
                .into_iter()
                .map(|value| value.to_str())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            
            if val.is_empty() {
                return HttpComponent::new(self, None);
            }
            
            HttpComponent::new(self, Some(val.join(", ")))
        } else if let Name::Derived(derived) = self.name {
            derived.parse_request(req)
        } else {
            unreachable!()
        }
    }
}