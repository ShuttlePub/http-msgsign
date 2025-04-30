use crate::components::values::Value;

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("Http body error")]
    Body,

    #[error("Mismatched content digest.")]
    Mismatch,

    #[error(transparent)]
    ExtractHeader(#[from] ExtractHeaderError),

    #[error("Algorithm not supported.")]
    AlgorithmNotSupported,
}

#[derive(Debug, thiserror::Error)]
pub enum ExtractHeaderError {
    #[error("No {header_name} header found.")]
    NoExist { header_name: &'static str },

    #[error("Failed to convert header value into str: {0}")]
    FailedToStr(http::header::ToStrError),

    #[error(transparent)]
    InvalidHeaderValue(Box<dyn std::error::Error + Sync + Send + 'static>),
}


#[derive(Debug, thiserror::Error)]
#[error("Invalid Content-Digest header value.")]
pub struct InvalidContentDigest;

impl From<InvalidContentDigest> for ExtractHeaderError {
    fn from(error: InvalidContentDigest) -> Self {
        ExtractHeaderError::InvalidHeaderValue(Box::new(error))
    }
}

impl From<sfv::Error> for ExtractHeaderError {
    fn from(e: sfv::Error) -> Self {
        ExtractHeaderError::InvalidHeaderValue(Box::new(e))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("`Signature` for the specified Label(`{0}`) is missing.")]
    NotExist(String),
    #[error("`Signature` does not exist in header.")]
    NotExistInHeader,
    #[error("`Signature` is not a valid `Dictionary`. {0}")]
    InvalidFormat(#[from] InvalidFormat),
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureInputError {
    #[error("`Signature-Input` does not exist in header.")]
    NotExistInHeader,
    #[error(transparent)]
    InvalidDataFormat(#[from] InvalidFormat),
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureParamsError {
    #[error(transparent)]
    InvalidHeaderName(#[from] http::Error),
    #[error(transparent)]
    InvalidParameter(#[from] InvalidSerializer)
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidFormat {
    #[error("Type `Dictionary` was expected. {0}")]
    Dictionary(sfv::Error),
    #[error("Type `InnerList` was expected")]
    InnerList,
    #[error("Type `Integer` was expected. {0}")]
    Integer(sfv::Error),
    #[error("Type `String` was expected.")]
    String,
    #[error(transparent)]
    HeaderName(http::Error),
    #[error("Type `ByteSequence` was expected.")]
    ByteSequence,
    #[error(transparent)]
    DerivedComponent(#[from] InvalidDerivedComponent),
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidSerializer {
    #[error("{0} is duplicated. Parameter keys must always be unique.")]
    Duplicated(String),
    
    #[error("`{interrogator}` does not correspond to {reject}.")]
    Incompatible {
        interrogator: &'static str,
        reject: String
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SerializeError {
    #[error("`{0:?}` is not a valid ASCII string.")]
    MustBeASCIIString(Value),
    #[error(transparent)]
    SfvSerialize(#[from] sfv::Error),
    #[error("{param_type} parameter does not support `{current_type}`.")]
    InvalidSerializableValue {
        param_type: String,
        current_type: &'static str,
    },
    #[error("Entry with the specified key=`{0}` does not exist.")]
    EntryNotExistsInDictionary(String),
    #[error("Cannot be parsed as SFV format.")]
    FailedParseToSfv,
    #[error(transparent)]
    InvalidFormat(#[from] InvalidFormat)
    
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid derived component.")]
pub struct InvalidDerivedComponent;

#[derive(Debug, thiserror::Error)]
#[error("invalid component parameter: {0}={1:?}")]
pub struct InvalidComponentParameter(pub sfv::Key, pub sfv::BareItem);

#[derive(Debug, thiserror::Error)]
pub enum HttpComponentError {
    #[error("Incorrect data type. expect: {expect}")]
    InvalidDataType {
        expect: &'static str,
    },
    #[error(transparent)]
    FailedSerializeValue(#[from] SerializeError),
    #[error("Necessary requirement have not been met. {reason}")]
    UnmetRequirement { reason: &'static str },
    #[error("DerivedComponent({0}) not supported.")]
    UnsupportedComponent(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error(transparent)]
    FailedBuildSignatureBase(#[from] HttpComponentError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    MissingSignature(#[from] SignatureError),
    #[error("`Signature-Input` for the specified Label(`{0}`) is missing.")]
    MissingSignatureInput(String),
    #[error(transparent)]
    FailedParseSignatureInput(#[from] SignatureInputError),
    #[error("Failed to decode signature. {0}")]
    FailedDecodeSignature(#[from] base64::DecodeError),
    #[error(transparent)]
    FailedBuildSignatureBase(#[from] HttpComponentError),
    #[error("Failed to verify signature")]
    FailedVerifySignature,
}
