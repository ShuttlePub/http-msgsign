use http::{HeaderMap, HeaderName};

use crate::components::params::Serializer;
use crate::errors::SerializeError;

#[derive(Debug, Clone)]
pub enum Value {
    String(String),
    BytesList(Vec<Vec<u8>>)
}

impl Value {
    pub fn from_header(key: &HeaderName, map: &HeaderMap) -> Value {
        let values = map.get_all(key);
        match values
            .iter()
            .map(|value| value.to_str().map(|st| st.to_string()))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(ascii_values) => {
                let normalized = ascii_values.into_iter()
                    .reduce(|mut acc, next| {
                        acc += &format!(", {}", next);
                        acc
                    })
                    .map(|joined| joined.trim_ascii().to_string())
                    .unwrap_or(String::new());
                
                Value::String(normalized)
            }
            Err(_) => { 
                let listed_bytes = values.into_iter()
                    .map(|value| value.as_bytes())
                    .map(|bytes| bytes.to_vec())
                    .collect::<Vec<_>>();
                
                Value::BytesList(listed_bytes)
            }
        }
    }
    
    pub fn serialize(self, serializer: &Serializer) -> Result<String, SerializeError> {
        let val = serializer.serialize(self)?;
        let Value::String(st) = val else {
            return Err(SerializeError::MustBeASCIIString(val));
        };
        Ok(st)
    }
}
