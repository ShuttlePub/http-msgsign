use crate::sign::components::HttpComponent;
use crate::sign::{SignatureParams};
use indexmap::IndexSet;

pub struct SignatureBase {
    params: SignatureParams,
    covered: IndexSet<HttpComponent>,
}

impl SignatureBase {
    pub(crate) fn new<B>(req: &http::Request<B>, params: SignatureParams) -> SignatureBase {
        let cloned = params.clone();
        let tail = params.to_component();
        let mut covered = params.parse_request(req);
        covered.insert(tail);
        Self { covered, params: cloned }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::base64::Base64EncodedString;
    use crate::sign::components::{Derived, Parameters};
    use crate::test::create_request;
    use http::header;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use sha2::Sha512;
    
    const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC2xCxRXxCmqvKC
xj7b4kJDoXDz+iYzvUgzY39Hyk9vNuA6XSnvwxkayA85DYdLOeMPQU/Owfyg7YHl
R+3CzTgsdvYckBiXPbn6U3lyp8cB9rd+CYLfwV/AGSfuXnzZS09Zn/BwE6fIKBvf
Ity8mtfKu3xDEcmC9Y7bchOtRVizMiZtdDrtgZLRiEytuLFHOaja2mbclwgG2ces
RQyxPQ18V1+xmFNPxhvEG8DwV04OATDHu7+9/cn2puLj4q/xy+rIm6V4hFKNVc+w
gyeh6MifTgA88oiOkzJB2daVvLus3JC0Tj4JX6NwWOolsT9eKVy+rG3oOKuMUK9h
4piXW4cvAgMBAAECggEAfsyDYsDtsHQRZCFeIvdKudkboGkAcAz2NpDlEU2O5r3P
uy4/lhRpKmd6CD8Wil5S5ZaOZAe52XxuDkBk+C2gt1ihTxe5t9QfX0jijWVRcE9W
5p56qfpjD8dkKMBtJeRV3PxVt6wrT3ZkP97T/hX/eKuyfmWsxKrQvfbbJ+9gppEM
XEoIXtQydasZwdmXoyxu/8598tGTX25gHu3hYaErXMJ8oh+B0smcPR6gjpDjBTqw
m++nJN7w0MOjwel0DA2fdhJqFJ7Aqn2AeCBUhCVNlR2wfEz5H7ZFTAlliP1ZJNur
6zWcogJSaNAE+dZus9b3rcETm61A8W3eY54RZHN2wQKBgQDcwGEkLU6Sr67nKsUT
ymW593A2+b1+Dm5hRhp+92VCJewVPH5cMaYVem5aE/9uF46HWMHLM9nWu+MXnvGJ
mOQi7Ny+149Oz9vl9PzYrsLJ0NyGRzypvRbZ0jjSH7Xd776xQ8ph0L1qqNkfM6CX
eQ6WQNvJEIXcXyY0O6MTj2stZwKBgQDT8xR1fkDpVINvkr4kI2ry8NoEo0ZTwYCv
Z+lgCG2T/eZcsj79nQk3R2L1mB42GEmvaM3XU5T/ak4G62myCeQijbLfpw5A9/l1
ClKBdmR7eI0OV3eiy4si480mf/cLTzsC06r7DhjFkKVksDGIsKpfxIFWsHYiIUJD
vRIn76fy+QKBgQDOaLesGw0QDWNuVUiHU8XAmEP9s5DicF33aJRXyb2Nl2XjCXhh
fi78gEj0wyQgbbhgh7ZU6Xuz1GTn7j+M2D/hBDb33xjpqWPE5kkR1n7eNAQvLibj
06GtNGra1rm39ncIywlOYt7p/01dZmmvmIryJV0c6O0xfGp9hpHaNU0S2wKBgCX2
5ZRCIChrTfu/QjXA7lhD0hmAkYlRINbKeyALgm0+znOOLgBJj6wKKmypacfww8oa
sLxAKXEyvnU4177fTLDvxrmO99ulT1aqmaq85TTEnCeUfUZ4xRxjx4x84WhyMbTI
61h65u8EgMuvT8AXPP1Yen5nr1FfubnedREYOXIpAoGAMZlUBtQGIHyt6uo1s40E
DF+Kmhrggn6e0GsVPYO2ghk1tLNqgr6dVseRtYwnJxpXk9U6HWV8CJl5YLFDPlFx
mH9FLxRKfHIwbWPh0//Atxt1qwjy5FpILpiEUcvkeOEusijQdFbJJLZvbO0EjYU/
Uz4xpoYU8cPObY7JmDznKvc=
-----END PRIVATE KEY-----"#;
    
    #[test]
    fn signing() {
        let req = create_request();
        
        let sign_params = SignatureParams::builder()
            .add_derive(Derived::Method)
            .add_header(header::CONTENT_TYPE, Parameters::default())
            .add_header(header::DATE, Parameters::default())
            .build()
            .unwrap();
        
        let base = SignatureBase::new(&req, sign_params);
        
        let signature_base = base.covered.iter()
            .map(|component| component.to_string())
            .reduce(|mut acc, next| {
                acc += &format!("\n{next}");
                acc
            })
            .unwrap();
        
        println!("{signature_base}");
        
        let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(PRIVATE_KEY).unwrap();
        let signer = BlindedSigningKey::<Sha512>::new(private_key);
        let sign = signer.sign_with_rng(&mut rand::thread_rng(), signature_base.as_bytes());
        
        println!("signature-input: sig={}", base.params);
        println!("signature: sig=:{}:", Base64EncodedString::new(sign.to_vec()));
        
    }
}