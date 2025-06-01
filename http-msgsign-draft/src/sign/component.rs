use std::fmt::{Display, Formatter};

#[derive(Debug, Eq, PartialEq, Hash)]
pub struct SignBaseComponent {
    pub(crate) id: String,
    pub(crate) value: Option<String>,
}

impl Display for SignBaseComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.value {
            Some(val) => write!(f, "{}: {}", self.id, val),
            None => write!(f, "{}: ", self.id),
        }
    }
}
