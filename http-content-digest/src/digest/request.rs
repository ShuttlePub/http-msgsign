use bytes::Bytes;
use http::Request;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};

use super::ContentDigest;
use crate::digest::{BodyDigest, ContentHasher};
use crate::errors::DigestError;
use crate::digest::header::{self, CONTENT_DIGEST};

impl<B> ContentDigest for Request<B>
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
            CONTENT_DIGEST,
            format!("{}={}", H::DIGEST_ALG, actual.digest.to_base64().to_sfv())
                .parse()
                .unwrap(),
        );

        Ok(Request::from_parts(parts, body))
    }

    async fn verify_digest<H: ContentHasher>(self) -> Result<Self::Content, Self::Error> {
        let (parts, body) = self.into_parts();
        let Some(expect) = header::ContentDigest::from_header(&parts.headers)?.find(H::DIGEST_ALG)
        else {
            return Err(DigestError::AlgorithmNotSupported)
        };

        let actual = body.digest::<H>().await.map_err(|_e| DigestError::Body)?;

        if actual.digest != expect {
            return Err(DigestError::Mismatch);
        }

        let body = Full::new(actual.body)
            .map_err(|infallible| match infallible {})
            .boxed();

        Ok(Request::from_parts(parts, body))
    }
}
