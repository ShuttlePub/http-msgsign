use ordermap::OrderSet;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default)]
pub struct Parameters(OrderSet<Parameter>);

impl Display for Parameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() { 
            return Ok(());
        }
        
        let params = self.0.iter()
            .map(|param| param.to_string())
            .collect::<Vec<_>>()
            .join(";");
        write!(f, ";{}", params)
    }
}

impl Parameters {
    pub fn append(mut self, param: Parameter) -> Self {
        self.0.insert(param);
        self
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Parameter {
    Sf,
    Key(String),
    Bs,
    Req,
    Tr,
}

impl Display for Parameter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Parameter::Sf => write!(f, "sf"),
            Parameter::Key(key) => write!(f, "key={key}"),
            Parameter::Bs => write!(f, "bs"),
            Parameter::Req => write!(f, "req"),
            Parameter::Tr => write!(f, "tr"),
        }
    }
}
