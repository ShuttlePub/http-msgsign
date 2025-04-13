use base64::Engine;
use std::fmt::Display;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Base64EncodedString(String);

impl Base64EncodedString {
    pub fn new<T: AsRef<[u8]>>(input: T) -> Self {
        Self(base64::engine::general_purpose::STANDARD.encode(input))
    }

    pub fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::engine::general_purpose::STANDARD.decode(&self.0)
    }
}

impl AsRef<str> for Base64EncodedString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Base64EncodedString> for String {
    fn from(value: Base64EncodedString) -> Self {
        value.0
    }
}

impl PartialEq<str> for Base64EncodedString {
    fn eq(&self, other: &str) -> bool {
        self.as_ref().eq(other)
    }
}

impl PartialEq<String> for Base64EncodedString {
    fn eq(&self, other: &String) -> bool {
        self.as_ref().eq(other)
    }
}

impl Display for Base64EncodedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
