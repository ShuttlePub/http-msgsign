mod request;
mod response;

pub use http_content_digest::{BodyDigest, ContentHasher, DigestHash, errors::DigestError};

pub mod header;

pub trait Digest {
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
