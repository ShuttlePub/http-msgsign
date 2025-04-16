use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use crate::digest::{BodyDigest, ContentDigest, ContentHasher};
use crate::digest::header::CONTENT_DIGEST;
use crate::errors::DigestError;

impl<B> ContentDigest for Response<B>
where
    B: http_body::Body + Send,
    B::Data: Send,
{
    type Error = DigestError;
    type Content = Response<BoxBody<Bytes, DigestError>>;
    
    async fn digest<H: ContentHasher>(self) -> Result<Self::Content, Self::Error> {
        let (mut parts, body) = self.into_parts();
        let actual = body.digest::<H>().await.map_err(|_e| DigestError::Body)?;
        
        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();
        
        parts.headers.insert(
            CONTENT_DIGEST,
            format!("{}=:{}:", H::DIGEST_TYPE, actual.digest.to_base64())
                .parse()
                .unwrap(),
        );
        
        Ok(Response::from_parts(parts, body))
    }
    
    async fn verify_digest<H: ContentHasher>(self) -> Result<Self::Content, Self::Error> {
        let (parts, body) = self.into_parts();
        let expect = super::header::extract_content_digest(&parts.headers)?;
        
        if !expect.alg.eq(H::DIGEST_TYPE) {
            return Err(DigestError::AlgorithmNotSupported);
        }
        
        let actual = body.digest::<H>().await.map_err(|_e| DigestError::Body)?;
        
        if actual.digest != expect.digest {
            return Err(DigestError::Mismatch);
        }
        
        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();
        
        Ok(Response::from_parts(parts, body))
    }
}