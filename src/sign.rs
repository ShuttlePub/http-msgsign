pub mod components;
mod input;
mod params;
mod base;

pub use self::{
    input::*,
    params::SignatureParams,
};

pub trait SignerKey {
    const ALGORITHM: &'static str;
    
    fn sign(&self, target: &str) -> Vec<u8>;
    fn key_id(&self) -> String;
}

pub trait VerifierKey {
    const ALGORITHM: &'static str;
    
    fn verify(&self, target: &str, signature: &[u8]) -> bool;
    fn key_id(&self) -> String;
}