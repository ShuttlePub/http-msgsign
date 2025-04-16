mod body;
mod header;
mod request;
mod response;

pub use self::body::*;

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

pub trait ContentDigest {
    type Error;
    type Content;
    fn digest<H: ContentHasher>(
        self,
    ) -> impl Future<Output = Result<Self::Content, Self::Error>> + Send
    where
        Self: Sized;
    fn verify_digest<H: ContentHasher>(
        self,
    ) -> impl Future<Output = Result<Self::Content, Self::Error>> + Send
    where
        Self: Sized;
}
