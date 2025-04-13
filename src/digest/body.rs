use super::{ContentHasher, DigestHash};
use http_body_util::BodyExt;

pub struct DigestWithContent {
    pub body: bytes::Bytes,
    pub digest: DigestHash,
}

impl<T> BodyDigest for T where T: http_body::Body {}

pub trait BodyDigest
where
    Self: http_body::Body,
{
    fn into_bytes(self) -> impl Future<Output = Result<bytes::Bytes, Self::Error>> + Send
    where
        Self: Sized + Send,
        Self::Data: Send,
    {
        async { Ok(self.collect().await?.to_bytes()) }
    }

    fn digest<H: ContentHasher>(
        self,
    ) -> impl Future<Output = Result<DigestWithContent, Self::Error>> + Send
    where
        Self: Sized + Send,
        Self::Data: Send,
    {
        async {
            let bytes = self.into_bytes().await?;
            let digest = H::hash(&bytes);

            Ok(DigestWithContent {
                body: bytes,
                digest,
            })
        }
    }
}
