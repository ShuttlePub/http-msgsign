use super::{BodyDigest, ContentHasher, DigestError};
use crate::digest::Digest;
use crate::digest::header::{self, DIGEST};
use bytes::Bytes;
use http::Request;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

impl<B> Digest for Request<B>
where
    B: http_body::Body + Send,
    B::Data: Send,
{
    type Error = DigestError;
    type Content = Request<BoxBody<Bytes, DigestError>>;

    async fn digest<H: ContentHasher>(self) -> Result<Self::Content, Self::Error> {
        let (mut parts, body) = self.into_parts();
        let actual = body.digest::<H>().await.map_err(|_e| DigestError::Body)?;

        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();

        parts.headers.insert(
            DIGEST,
            format!("{}={}", H::DIGEST_ALG, actual.digest.to_base64())
                .parse()
                .unwrap(),
        );

        Ok(Request::from_parts(parts, body))
    }

    async fn verify_digest<H: ContentHasher>(self) -> Result<Self::Content, Self::Error> {
        let (parts, body) = self.into_parts();
        let expect = header::Digest::from_header(&parts.headers)?;

        if expect.alg != H::DIGEST_ALG {
            return Err(DigestError::AlgorithmNotSupported);
        };

        let actual = body.digest::<H>().await.map_err(|_e| DigestError::Body)?;

        if actual.digest != expect.digest {
            return Err(DigestError::Mismatch);
        }

        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();

        Ok(Request::from_parts(parts, body))
    }
}
