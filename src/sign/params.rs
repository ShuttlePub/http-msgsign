use crate::errors::SignatureParamsError;
use crate::sign::components::{Derived, HttpComponent, Identifier, Name, Parameters};
use indexmap::IndexSet;
use std::fmt::{Display, Formatter};
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct SignatureParams {
    covered: IndexSet<Identifier>,
    created: Option<u64>,
    expires: Option<u64>,
    algorithm: Option<String>,
    key_id: Option<String>,
    nonce: Option<String>,
    tag: Option<String>,
}

impl SignatureParams {
    pub fn builder() -> Builder {
        Builder::default()
    }
    
    pub(crate) fn parse_request<B>(self, req: &http::Request<B>) -> IndexSet<HttpComponent> {
        self.covered
            .into_iter()
            .map(|covered| covered.parse_request(req))
            .collect::<IndexSet<_>>()
    }
    
    pub fn to_component(&self) -> HttpComponent {
        HttpComponent::new(Identifier::new(Name::SignatureParams, Parameters::default()), Some(self.to_string()))
    }
}

impl Display for SignatureParams {
    //noinspection SpellCheckingInspection
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let covered = self.covered.iter()
            .fold(String::new(), |acc, id| {
                if acc.is_empty() {
                    id.to_string()
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

pub struct Builder {
    builder: Result<SignatureParams, SignatureParamsError>
}

//noinspection SpellCheckingInspection
impl Builder {
    /// `Derived Components` defined in RFC9421 can be added as covered components.  
    /// `Derived Components` have their own formatting behavior, so adding a Parameter may be redundant. 
    /// Therefore, Parameter cannot be used.
    ///
    /// **Note**: The order in which they are added is preserved, and is a common array with [`Builder::add_header`].
    /// 
    /// See [`RFC9421 Derived Components`](https://datatracker.ietf.org/doc/html/rfc9421#name-derived-components)
    pub fn add_derive(self, derive: Derived) -> Self {
        self.and_then(|mut sign_params| {
            sign_params.covered.insert(Identifier::new(derive.into(), Parameters::default()));
            Ok(sign_params)
        })
    }
    
    /// HTTP header values can be added to the covered component.  
    /// This is the so-called `HTTP Fields` defined in [RFC9421 HTTP Fields](https://datatracker.ietf.org/doc/html/rfc9421#name-http-fields).  
    /// Can also be assigned Parameter defined in [RFC9421 §2.1-17](https://datatracker.ietf.org/doc/html/rfc9421#section-2.1-17).
    /// 
    /// **Note**: The order in which they are added is preserved, and is a common array with [`Builder::add_derive`].
    pub fn add_header<H>(self, header: H, params: Parameters) -> Self 
    where
        H: TryInto<http::HeaderName>,
        H::Error: Into<http::Error>,
    {
        self.and_then(|mut sign_params| {
            let header = header.try_into().map_err(Into::into)?;
            sign_params.covered.insert(Identifier::new(Name::from(header), params));
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
    
    /// `created` is generated at [`Builder::build`] called.  
    /// This is because the specification recommends the inclusion of “created”, so the process generates it by default.
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
            let at = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs());
            sign_params.created = at;
            sign_params
        })
    }
    
    fn and_then<F>(self, f: F) -> Self
    where
        F: FnOnce(SignatureParams) -> Result<SignatureParams, SignatureParamsError>
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
            })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::sign::components::Parameter;
    use crate::test::create_request;
    use http::header;
    use std::ops::Add;
    use std::time::Duration;
    
    #[test]
    fn build_signature_params() {
        let expires = SystemTime::now()
            .add(Duration::from_secs(3600))
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let sign_params = SignatureParams::builder()
            .add_derive(Derived::Method)
            .add_derive(Derived::Path)
            .add_derive(Derived::Query)
            .add_header(header::CONTENT_TYPE, Parameters::default())
            .add_header(header::HOST, Parameters::default())
            .add_header(header::DATE, Parameters::default())
            .add_header("Custom-Dict", Parameters::default().append(Parameter::Key("a".to_string())))
            .set_expires(expires)
            .build();
        
        assert!(sign_params.is_ok());
        
        let sign_params = sign_params.unwrap();
        
        // Expected output format:
        // ("@method" "@path" "@query" "content-type" "host" "date" "custom-dict";key=a);created=<UNIX_TIME>;expires=<UNIX_TIME>
        println!("{}", sign_params);
    }
    
    #[test]
    fn parse_covered_component() {
        let req = create_request();
        
        let sign_params = SignatureParams::builder()
            .add_derive(Derived::Path)
            .add_derive(Derived::Method)
            .add_derive(Derived::QueryParam("foo".to_string()))
            .add_header(header::CONTENT_TYPE, Parameters::default())
            .add_header(header::DATE, Parameters::default())
            .add_header("custom-header", Parameters::default())
            .build()
            .unwrap();
        
        for covered in sign_params.clone().covered {
            println!("{}", covered.parse_request(&req));
        }
        
        println!("\"@signature-params\": {}", sign_params);
    }
}