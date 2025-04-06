use crate::sign::SignatureParams;

#[derive(Debug, Clone)]
pub struct SignatureInput {
    profile: String,
    used_param: SignatureParams
}

