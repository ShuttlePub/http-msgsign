mod base;
mod input;
mod params;
mod request;
mod signature;

pub mod header {
    pub const SIGNATURE: &str = "signature";
    pub const SIGNATURE_INPUT: &str = "signature-input";
}

pub use self::{
    base::SignatureBase,
    input::*,
    params::SignatureParams,
    request::*, 
};

pub trait SignerKey: 'static + Sync + Send {
    const ALGORITHM: &'static str;

    fn key_id(&self) -> String;
    fn sign(&self, target: &[u8]) -> Vec<u8>;
}

pub trait VerifierKey: 'static + Sync + Send {
    const ALGORITHM: &'static str;

    fn key_id(&self) -> String;
    fn verify(
        &self,
        target: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::errors::VerificationError>;
}
