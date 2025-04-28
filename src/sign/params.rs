use std::fmt::{Display, Formatter};
use std::time::SystemTime;

use indexmap::IndexSet;

use crate::components::params::FieldParameter;
use crate::components::{Derive, HttpComponent, Identifier, TargetField, ToComponent};
use crate::errors::{HttpComponentError, SignatureParamsError};
use crate::sign::{ExchangeRecord, SignatureInput, SignerKey};

pub const SIGNATURE_PARAMS: &str = "@signature-params";

#[derive(Debug, Clone)]
pub struct SignatureParams {
    covered: IndexSet<TargetField>,
    created: Option<u64>,
    expires: Option<u64>,
    algorithm: Option<String>,
    key_id: Option<String>,
    nonce: Option<String>,
    tag: Option<String>,
}

#[derive(Debug)]
pub struct KeyPropertyLoadedSignatureParams<'a> {
    origin: &'a SignatureParams,
    algorithm: Option<String>,
    key_id: Option<String>,
}

impl SignatureParams {
    pub fn to_component(&self) -> HttpComponent {
        HttpComponent {
            id: format!("\"{SIGNATURE_PARAMS}\""),
            value: Some(self.to_string()),
        }
    }

    pub fn request_to_component<B>(
        &self,
        request: &http::Request<B>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .covered
            .iter()
            .map(|covered| request.to_component(covered))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }

    pub fn response_to_component<B>(
        &self,
        response: &http::Response<B>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .covered
            .iter()
            .map(|covered| response.to_component(covered))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }
    
    pub fn record_to_component<Req, Res>(
        &self,
        record: &ExchangeRecord<Req, Res>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .covered
            .iter()
            .map(|covered| record.to_component(covered))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }

    pub fn load_signer_key<S: SignerKey>(&self, key: &S) -> KeyPropertyLoadedSignatureParams {
        KeyPropertyLoadedSignatureParams {
            origin: self,
            algorithm: Some(S::ALGORITHM.to_string()),
            key_id: Some(key.key_id().to_string()),
        }
    }
}

impl KeyPropertyLoadedSignatureParams<'_> {
    pub fn to_component(&self) -> HttpComponent {
        HttpComponent {
            id: format!("\"{SIGNATURE_PARAMS}\""),
            value: Some(self.to_string()),
        }
    }

    pub fn request_to_component<B>(
        &self,
        request: &http::Request<B>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .origin
            .covered
            .iter()
            .map(|target| request.to_component(target))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }

    pub fn response_to_component<B>(
        &self,
        response: &http::Response<B>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .origin
            .covered
            .iter()
            .map(|target| response.to_component(target))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }
    
    pub fn record_to_component<Req, Res>(
        &self,
        record: &ExchangeRecord<Req, Res>,
    ) -> Result<IndexSet<HttpComponent>, HttpComponentError> {
        let mut components = self
            .origin
            .covered
            .iter()
            .map(|target| record.to_component(target))
            .collect::<Result<IndexSet<_>, HttpComponentError>>()?;

        // This requirement that the component named @signature-params always be added at the end is satisfied here.
        components.insert(self.to_component());

        Ok(components)
    }
}

impl SignatureParams {
    pub fn builder() -> Builder {
        Builder::default()
    }
}

impl From<SignatureInput> for SignatureParams {
    fn from(value: SignatureInput) -> Self {
        Self {
            covered: value.covered,
            created: value.created,
            expires: value.expires,
            algorithm: value.algorithm,
            key_id: value.key_id,
            nonce: value.nonce,
            tag: value.tag,
        }
    }
}

impl Display for SignatureParams {
    //noinspection SpellCheckingInspection
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let covered = self.covered.iter().fold(String::new(), |acc, id| {
            if acc.is_empty() {
                format!("{id}")
            } else {
                format!("{acc} {id}")
            }
        });

        let mut base = format!("({})", covered);

        if let Some(created) = self.created {
            base += &format!(";created={created}");
        }

        if let Some(expires) = self.expires {
            base += &format!(";expires={expires}");
        }

        if let Some(algorithm) = &self.algorithm {
            base += &format!(";alg=\"{algorithm}\"");
        }

        if let Some(key_id) = &self.key_id {
            base += &format!(";keyid=\"{key_id}\"");
        }

        if let Some(nonce) = &self.nonce {
            base += &format!(";nonce=\"{nonce}\"");
        }

        if let Some(tag) = &self.tag {
            base += &format!(";tag=\"{tag}\"");
        }

        write!(f, "{}", base)
    }
}

impl Display for KeyPropertyLoadedSignatureParams<'_> {
    //noinspection SpellCheckingInspection
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut origin = format!("{}", self.origin);
        if self.origin.algorithm.is_none() {
            if let Some(algorithm) = &self.algorithm {
                origin += &format!(";alg=\"{algorithm}\"");
            }
        }
        if self.origin.key_id.is_none() {
            if let Some(key_id) = &self.key_id {
                origin += &format!(";keyid=\"{key_id}\"");
            }
        }
        write!(f, "{}", origin)
    }
}

pub struct Builder {
    builder: Result<SignatureParams, SignatureParamsError>,
}

//noinspection SpellCheckingInspection
impl Builder {
    /// `Derived Components` defined in RFC9421 can be added as covered components.  
    /// `Derived Components` have their own formatting behavior, so adding a Parameter may be redundant.
    /// Therefore, Parameter cannot be used.
    ///
    /// **Note**: The order in which they are added is preserved and is a common array with [`Builder::add_header`].
    ///
    /// See [`RFC9421 Derived Components`](https://datatracker.ietf.org/doc/html/rfc9421#name-derived-components)
    pub fn add_derive(self, derive: Derive, params: FieldParameter) -> Self {
        self.and_then(|mut sign_params| {
            sign_params
                .covered
                .insert(TargetField::new(derive.into(), params)?);
            Ok(sign_params)
        })
    }

    /// HTTP header values can be added to the covered component.  
    /// This is the so-called `HTTP Fields` defined in [RFC9421 HTTP Fields](https://datatracker.ietf.org/doc/html/rfc9421#name-http-fields).  
    /// Can also be assigned Parameter defined in [RFC9421 §2.1-17](https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-17).
    ///
    /// **Note**: The order in which they are added is preserved and is a common array with [`Builder::add_derive`].
    pub fn add_header<H>(self, header: H, params: FieldParameter) -> Self
    where
        H: TryInto<http::HeaderName>,
        H::Error: Into<http::Error>,
    {
        self.and_then(|mut sign_params| {
            let header = header.try_into().map_err(Into::into)?;
            sign_params
                .covered
                .insert(TargetField::new(Identifier::from(header), params)?);
            Ok(sign_params)
        })
    }

    /// `expires`: Expiration time as a UNIX timestamp value of type Integer.  
    /// Sub-second precision is not supported.
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.4](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.4)
    pub fn set_expires(self, expires: impl Into<u64>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.expires = Some(expires.into());
            Ok(sign_params)
        })
    }

    /// `alg`: The HTTP message signature algorithm from the "HTTP Signature Algorithms" registry, as a String value.
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.8](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.8)
    pub fn set_algorithm(self, algorithm: impl Into<String>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.algorithm = Some(algorithm.into());
            Ok(sign_params)
        })
    }

    /// `keyid`: The identifier for the key material as a String value.
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.10](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.10)
    pub fn set_key_id(self, key_id: impl Into<String>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.key_id = Some(key_id.into());
            Ok(sign_params)
        })
    }

    /// `nonce`: A random unique value generated for this signature as a String value.
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.6](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.6)
    pub fn set_nonce(self, nonce: impl Into<String>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.nonce = Some(nonce.into());
            Ok(sign_params)
        })
    }

    /// `tag`: An application-specific tag for the signature as a String value.  
    /// This value is used by applications to help identify signatures relevant for specific applications or protocols.
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.12](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.12)
    pub fn set_tag(self, tag: impl Into<String>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.tag = Some(tag.into());
            Ok(sign_params)
        })
    }

    pub fn set_created(self, created: impl Into<u64>) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.created = Some(created.into());
            Ok(sign_params)
        })
    }

    /// `created` is generated at [`Builder::build`] called.  
    /// This is because the specification recommends the inclusion of “created” so the process generates it by default.
    ///
    /// ---
    ///
    /// `created`: Creation time as a UNIX timestamp value of type Integer.  
    /// Sub-second precision is not supported.  
    /// The inclusion of this parameter is **RECOMMENDED**.  
    ///
    /// See [RFC9421 Signature Parameters §2.3-4.2](https://datatracker.ietf.org/doc/html/rfc9421#section-2.3-4.2)
    pub fn build(self) -> Result<SignatureParams, SignatureParamsError> {
        self.builder.map(|mut sign_params| {
            if sign_params.created.is_none() {
                let at = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs());
                sign_params.created = at;
            }
            sign_params
        })
    }

    fn and_then<F>(self, f: F) -> Self
    where
        F: FnOnce(SignatureParams) -> Result<SignatureParams, SignatureParamsError>,
    {
        Self {
            builder: self.builder.and_then(f),
        }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            builder: Ok(SignatureParams {
                covered: IndexSet::new(),
                created: None,
                expires: None,
                algorithm: None,
                key_id: None,
                nonce: None,
                tag: None,
            }),
        }
    }
}
