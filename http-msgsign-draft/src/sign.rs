use crate::errors::VerificationError;

mod base;
mod component;
mod field;
mod input;
pub mod params;
mod request;
mod response;

pub(crate) use self::base::*;
pub(crate) use self::input::*;
pub use self::params::*;

pub use self::request::*;
pub use self::response::*;

pub mod headers {
    pub use super::input::*;
}

pub trait SignerKey: 'static + Sync + Send {
    fn id(&self) -> String;
    fn algorithm(&self) -> String;

    fn sign(&self, target: &[u8]) -> Vec<u8>;
}

pub trait VerifierKey: 'static + Sync + Send {
    fn id(&self) -> String;
    fn algorithm(&self) -> String;

    fn verify(&self, target: &[u8], sig: &[u8]) -> Result<(), VerificationError>;
}
