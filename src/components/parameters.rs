use crate::errors::InvalidComponentParameter;
use ordermap::OrderSet;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct FieldParameters(OrderSet<FieldParameter>);

impl Display for FieldParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return Ok(());
        }

        let params = self
            .0
            .iter()
            .map(|param| param.to_string())
            .collect::<Vec<_>>()
            .join(";");
        write!(f, ";{}", params)
    }
}

impl From<sfv::Parameters> for FieldParameters {
    fn from(value: sfv::Parameters) -> Self {
        Self(
            value
                .into_iter()
                .flat_map(FieldParameter::try_from)
                .collect::<OrderSet<_>>(),
        )
    }
}

impl FieldParameters {
    pub fn append(mut self, param: FieldParameter) -> Self {
        self.0.insert(param);
        self
    }

    pub fn iter(&self) -> ordermap::set::Iter<FieldParameter> {
        self.0.iter()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum FieldParameter {
    Sf,
    Key(String),
    Bs,
    Req,
    Tr,
    Name(String),
}

impl Display for FieldParameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldParameter::Sf => write!(f, "sf"),
            FieldParameter::Key(key) => write!(f, "key=\"{key}\""),
            FieldParameter::Bs => write!(f, "bs"),
            FieldParameter::Req => write!(f, "req"),
            FieldParameter::Tr => write!(f, "tr"),
            FieldParameter::Name(name) => write!(f, "name=\"{name}\""),
        }
    }
}

impl TryFrom<(sfv::Key, sfv::BareItem)> for FieldParameter {
    type Error = InvalidComponentParameter;

    fn try_from((key, value): (sfv::Key, sfv::BareItem)) -> Result<Self, Self::Error> {
        match (key.as_str(), value) {
            ("sf", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Sf),
            ("key", sfv::BareItem::String(key)) => Ok(Self::Key(key.into())),
            ("bs", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Bs),
            ("req", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Req),
            ("tr", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Tr),
            ("name", sfv::BareItem::String(name)) => Ok(Self::Name(name.into())),
            (_, value) => Err(InvalidComponentParameter(key, value)),
        }
    }
}

pub mod parameter {
    use crate::components::FieldParameter;

    pub struct Name;

    impl PartialEq<Name> for FieldParameter {
        fn eq(&self, _: &Name) -> bool {
            matches!(self, FieldParameter::Name(_))
        }
    }
}
