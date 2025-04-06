mod body;
mod request;

pub use self::body::*;
pub use self::request::*;

use crate::base64::Base64EncodedString;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DigestHash(Vec<u8>);

impl DigestHash {
    pub fn new(digest: Vec<u8>) -> Self {
        Self(digest)
    }
    
    pub fn to_base64(&self) -> Base64EncodedString {
        Base64EncodedString::new(&self.0)
    }
}

pub trait ContentHasher: 'static + Send + Sync {
    const DIGEST_TYPE: &'static str;
    
    fn hash(content: &[u8]) -> DigestHash;
}
