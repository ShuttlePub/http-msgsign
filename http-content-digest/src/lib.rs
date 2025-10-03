mod base64;
mod digest;
pub mod errors;

pub use self::digest::*;

pub mod body {
    use bytes::Bytes;
    use http_body_util::combinators::BoxBody;
    use crate::errors::DigestError;
    
    pub type Body = BoxBody<Bytes, DigestError>;
}
