use bytes::Bytes;
use http::Request;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

use crate::digest::{BodyDigest, ContentHasher};
use crate::errors::DigestError;
use crate::headers::CONTENT_DIGEST;

pub trait RequestDigest {
    type Error;
    type Request;
    fn digest<H: ContentHasher>(self) -> impl Future<Output=Result<Self::Request, Self::Error>> + Send where Self: Sized;
    fn verify<H: ContentHasher>(self) -> impl Future<Output=Result<Self::Request, Self::Error>> + Send where Self: Sized;
}

impl<B> RequestDigest for Request<B>
where
    B: http_body::Body + Send,
    B::Data: Send
{
    type Error = DigestError;
    type Request = Request<BoxBody<Bytes, DigestError>>;
    
    async fn digest<H: ContentHasher>(self) -> Result<Self::Request, Self::Error> {
        let (mut parts, body) = self.into_parts();
        let actual = body.digest::<H>().await
            .map_err(|_e| DigestError::Body)?;
        
        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();
        
        parts.headers
            .insert(CONTENT_DIGEST, format!("{}=:{}:", H::DIGEST_TYPE, actual.digest.to_base64()).parse().unwrap());
        
        Ok(Request::from_parts(parts, body))
    }
    
    async fn verify<H: ContentHasher>(self) -> Result<Self::Request, Self::Error> {
        let (parts, body) = self.into_parts();
        let expect = crate::headers::extract_content_digest(&parts.headers)?;
        
        if !expect.alg.eq(H::DIGEST_TYPE) {
            return Err(DigestError::AlgorithmNotSupported);
        }
        
        let actual = body.digest::<H>().await
            .map_err(|_e| DigestError::Body)?;
        
        if actual.digest != expect.digest {
            return Err(DigestError::Mismatch);
        }
        
        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();
        
        Ok(Request::from_parts(parts, body))
    }
}
