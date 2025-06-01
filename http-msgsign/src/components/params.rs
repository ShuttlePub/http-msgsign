use indexmap::IndexMap;
use sfv::ListEntry;
use sfv::SerializeValue;
use std::collections::HashSet;
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

use crate::base64::Base64EncodedString;
use crate::components::values::Value;
use crate::errors::{InvalidComponentParameter, InvalidFormat, InvalidSerializer, SerializeError};

pub mod param {
    use crate::components::params::{Bs, Key, Name, Req, Sf, Tr};

    pub fn key(key: impl Into<String>) -> Key {
        Key(key.into())
    }
    pub fn name(name: impl Into<String>) -> Name {
        Name(name.into())
    }
    pub const fn sf() -> Sf {
        Sf
    }
    pub const fn bs() -> Bs {
        Bs
    }
    pub const fn tr() -> Tr {
        Tr
    }
    pub const fn req() -> Req {
        Req
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Serializer {
    methods: IndexMap<String, SerializerType>,
    require_request: bool,
}

impl Hash for Serializer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_string().hash(state)
    }
}

impl Serializer {
    pub fn serialize(&self, mut value: Value) -> Result<Value, SerializeError> {
        for (_, ser) in &self.methods {
            value = ser.serialize(value)?;
        }
        Ok(value)
    }

    pub fn require_request(&self) -> bool {
        self.require_request
    }

    pub fn name(&self) -> Option<&str> {
        let Some(SerializerType::Name(name)) = self.methods.get(Name::IDENT) else {
            return None;
        };
        Some(name.0.as_str())
    }
}

impl Display for Serializer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let p = self
            .methods
            .iter()
            .map(|(_, ser)| ser.to_string())
            .collect::<Vec<_>>()
            .join("");
        write!(f, "{}", p)
    }
}

#[macro_export]
macro_rules! params {
    [] => { $crate::components::params::FieldParameter::default() };
    [$($param:ident),*] => {
        $crate::components::params::FieldParameter::default()
            $(.add_param($crate::components::params::param::$param()))*
    };
    [$key:ident($arg:tt)] => {
        $crate::components::params::FieldParameter::default()
            .add_param($crate::components::params::param::$key($arg))
    };
    [$key:ident($arg:tt), $($param:ident),*] => {
        $crate::components::params::FieldParameter::default()
            .add_param($crate::components::params::param::$key($arg))
            $(.add_param($crate::components::params::param::$param()))*
    };
}

pub struct FieldParameter {
    builder: Result<Serializer, InvalidSerializer>,
}

impl Default for FieldParameter {
    fn default() -> Self {
        Self {
            builder: Ok(Serializer {
                methods: IndexMap::new(),
                require_request: false,
            }),
        }
    }
}

impl FieldParameter {
    pub fn add_param<P>(self, param: P) -> Self
    where
        P: Into<SerializerType> + DefinedParam,
    {
        self.and_then(|mut ser| {
            let ident = P::IDENT;
            let param = param.into();

            if let SerializerType::Req(_) = param {
                ser.require_request = true;
            }

            if ser.methods.insert(ident.to_string(), param).is_some() {
                return Err(InvalidSerializer::Duplicated(ident.to_string()));
            }

            Ok(ser)
        })
    }

    pub fn into_serializer(self) -> Result<Serializer, InvalidSerializer> {
        self.builder.and_then(|ser| {
            let methods = &ser.methods;
            methods.iter().try_for_each(|(_, interrogator)| {
                if methods.iter().any(|(contain, _)| {
                    interrogator.incompatible()
                        .iter()
                        .any(|reject| *contain == *reject)
                }) {
                    let contains = methods.iter()
                        .map(|(key, _)| key.as_str())
                        .collect::<HashSet<_>>();
                    let incompatible = interrogator.incompatible()
                        .iter()
                        .copied()
                        .collect::<HashSet<_>>();
                    let interrogator = interrogator.as_str();
                    let Some(reject) = (&contains & &incompatible).iter()
                        .map(|st| st.to_string())
                        .reduce(|mut acc, s| {
                            acc += &format!(", {}", s);
                            acc
                        })
                    else {
                        unreachable!("At the time this error occurs, some incompatibility information should have been obtained.")
                    };
                    return Err(InvalidSerializer::Incompatible {
                        interrogator,
                        reject,
                    })
                }
                Ok(())
            })?;
            Ok(ser)
        })
    }

    // Helper
    fn and_then<F>(self, f: F) -> Self
    where
        F: FnOnce(Serializer) -> Result<Serializer, InvalidSerializer>,
    {
        Self {
            builder: self.builder.and_then(f),
        }
    }
}

impl TryFrom<sfv::Parameters> for Serializer {
    type Error = InvalidSerializer;

    fn try_from(value: sfv::Parameters) -> Result<Self, Self::Error> {
        let ser = value
            .into_iter()
            .map(SerializerType::try_from)
            .flat_map(|ser| match ser {
                Ok(ser) => Ok((ser.as_str().to_string(), ser)),
                Err(err) => Err(err),
            })
            .collect::<IndexMap<_, _>>();

        let require_request = ser.contains_key(Req::IDENT);

        Ok(Self {
            methods: ser,
            require_request,
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum SerializerType {
    Sf(Sf),
    Key(Key),
    Bs(Bs),
    Tr(Tr),
    Req(Req),
    Name(Name),
}

impl SerializerType {
    pub const fn incompatible(&self) -> &[&str] {
        match self {
            SerializerType::Sf(_) => &["key", "bs"],
            SerializerType::Key(_) => &["sf", "bs"],
            SerializerType::Bs(_) => &["sf", "key"],
            _ => &[],
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            SerializerType::Sf(_) => "sf",
            SerializerType::Key(_) => "key",
            SerializerType::Bs(_) => "bs",
            SerializerType::Tr(_) => "tr",
            SerializerType::Req(_) => "req",
            SerializerType::Name(_) => "name",
        }
    }
}

impl Display for SerializerType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SerializerType::Sf(ser) => Display::fmt(ser, f),
            SerializerType::Key(ser) => Display::fmt(ser, f),
            SerializerType::Bs(ser) => Display::fmt(ser, f),
            SerializerType::Tr(ser) => Display::fmt(ser, f),
            SerializerType::Req(ser) => Display::fmt(ser, f),
            SerializerType::Name(ser) => Display::fmt(ser, f),
        }
    }
}

impl ValueSerializer for SerializerType {
    fn serialize(&self, value: Value) -> Result<Value, SerializeError> {
        match self {
            SerializerType::Sf(ser) => ser.serialize(value),
            SerializerType::Key(ser) => ser.serialize(value),
            SerializerType::Bs(ser) => ser.serialize(value),
            _ => Ok(value),
        }
    }
}

impl TryFrom<(sfv::Key, sfv::BareItem)> for SerializerType {
    type Error = InvalidComponentParameter;

    fn try_from((key, item): (sfv::Key, sfv::BareItem)) -> Result<Self, Self::Error> {
        match (key.as_str(), item) {
            ("sf", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Sf(Sf)),
            ("key", sfv::BareItem::String(key)) => Ok(Self::Key(Key(key.into()))),
            ("bs", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Bs(Bs)),
            ("req", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Req(Req)),
            ("tr", sfv::BareItem::Boolean(bool)) if bool => Ok(Self::Tr(Tr)),
            ("name", sfv::BareItem::String(name)) => Ok(Self::Name(Name(name.into()))),
            (_, value) => Err(InvalidComponentParameter(key, value)),
        }
    }
}

pub trait DefinedParam: 'static + Sync + Send {
    const IDENT: &'static str;
}

pub trait ValueSerializer: 'static + Sync + Send {
    fn serialize(&self, value: Value) -> Result<Value, SerializeError>;
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct Sf;

impl From<Sf> for SerializerType {
    fn from(value: Sf) -> Self {
        SerializerType::Sf(value)
    }
}

impl Display for Sf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";sf")
    }
}

impl DefinedParam for Sf {
    const IDENT: &'static str = "sf";
}

impl ValueSerializer for Sf {
    fn serialize(&self, value: Value) -> Result<Value, SerializeError> {
        let Value::String(st) = value else {
            return Err(SerializeError::InvalidSerializableValue {
                param_type: ";sf".to_string(),
                current_type: "ByteSequence",
            });
        };

        let value = if let Ok(item) = sfv::Parser::new(&st).parse_item() {
            Ok(item.serialize_value())
        } else if let Ok(dict) = sfv::Parser::new(&st).parse_dictionary() {
            Ok(dict.serialize_value().unwrap_or_default())
        } else if let Ok(list) = sfv::Parser::new(&st).parse_list() {
            Ok(list.serialize_value().unwrap_or_default())
        } else {
            Err(SerializeError::FailedParseToSfv)
        }?;

        Ok(Value::String(value))
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Key(String);

impl From<Key> for SerializerType {
    fn from(value: Key) -> Self {
        SerializerType::Key(value)
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";key=\"{}\"", self.0)
    }
}

impl DefinedParam for Key {
    const IDENT: &'static str = "key";
}

impl ValueSerializer for Key {
    fn serialize(&self, value: Value) -> Result<Value, SerializeError> {
        let key = self.0.as_str();
        let Value::String(st) = value else {
            return Err(SerializeError::InvalidSerializableValue {
                param_type: format!(";key=\"{}\"", self.0),
                current_type: "ByteSequence",
            });
        };

        let mut dict = sfv::Parser::new(&st)
            .parse_dictionary()
            .map_err(InvalidFormat::Dictionary)?;

        let Some(entry) = dict.shift_remove(key) else {
            return Err(SerializeError::EntryNotExistsInDictionary(key.to_string()));
        };

        let value = match entry {
            ListEntry::Item(item) => item.serialize_value(),
            entry @ ListEntry::InnerList(_) => vec![entry].serialize_value().unwrap_or_default(),
        };

        Ok(Value::String(value))
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct Bs;

impl From<Bs> for SerializerType {
    fn from(value: Bs) -> Self {
        SerializerType::Bs(value)
    }
}

impl Display for Bs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";bs")
    }
}

impl DefinedParam for Bs {
    const IDENT: &'static str = "bs";
}

impl ValueSerializer for Bs {
    fn serialize(&self, value: Value) -> Result<Value, SerializeError> {
        let byte_seq = match value {
            Value::String(st) => vec![Base64EncodedString::new(st)],
            Value::BytesList(list) => list
                .into_iter()
                .map(Base64EncodedString::new)
                .collect::<Vec<_>>(),
        };

        let value = byte_seq
            .into_iter()
            .map(|seq| seq.to_sfv())
            .collect::<Vec<String>>()
            .join(", ");

        Ok(Value::String(value))
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct Tr;

impl From<Tr> for SerializerType {
    fn from(value: Tr) -> Self {
        SerializerType::Tr(value)
    }
}

impl Display for Tr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";tr")
    }
}

impl DefinedParam for Tr {
    const IDENT: &'static str = "tr";
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct Req;

impl From<Req> for SerializerType {
    fn from(value: Req) -> Self {
        SerializerType::Req(value)
    }
}

impl Display for Req {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";req")
    }
}

impl DefinedParam for Req {
    const IDENT: &'static str = "req";
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct Name(String);

impl From<Name> for SerializerType {
    fn from(value: Name) -> Self {
        SerializerType::Name(value)
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, ";name=\"{}\"", self.0)
    }
}

impl DefinedParam for Name {
    const IDENT: &'static str = "name";
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_incompatible_serializers() {
        let ser = params![sf, bs].into_serializer();
        assert!(ser.is_err());

        let ser = params![key("a"), sf].into_serializer();
        assert!(ser.is_err());

        let ser = params![key("a"), bs].into_serializer();
        assert!(ser.is_err());

        let ser = params![key("a"), sf, bs].into_serializer();
        assert!(ser.is_err());

        let ser = params![key("a")].into_serializer();
        assert!(ser.is_ok());
    }

    #[test]
    #[should_panic]
    fn test_duplicated_serializers() {
        let _ = params![sf, sf].into_serializer().unwrap();
    }

    #[test]
    #[should_panic]
    fn test_report_incompatible_serializers() {
        let _ = params![sf, bs].into_serializer().unwrap();
    }

    #[test]
    fn test_sf_serializer() {
        let val = Value::String(r#" "london",   "berlin" "#.to_string());
        let ser = params![sf].into_serializer().unwrap();
        let val = ser.serialize(val).unwrap();
        let Value::String(visible) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // Normalized to List in sf-list.
        assert_eq!(visible, r#""london", "berlin""#);
    }

    #[test]
    fn test_key_serializer() {
        let dict = Value::String(r#" a=1, b=2;x=1;y=2, c=(a   b    c);valid, d"#.to_string());

        // extract key=`a` from dict
        let ser = params![key("a")].into_serializer().unwrap();
        let val = ser.serialize(dict.clone()).unwrap();
        let Value::String(visible) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // it's mean integer in sf-integer
        assert_eq!(visible, r#"1"#);

        // extract key=`b` from dict
        let ser = params![key("b")].into_serializer().unwrap();
        let val = ser.serialize(dict.clone()).unwrap();
        let Value::String(visible) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // it's mean integer(2) with parameters x=1, y=2
        assert_eq!(visible, r#"2;x=1;y=2"#);

        // extract key=`c` from dict
        let ser = params![key("c")].into_serializer().unwrap();
        let val = ser.serialize(dict.clone()).unwrap();
        let Value::String(visible) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // it's mean inner-list in sfv
        assert_eq!(visible, r#"(a b c);valid"#);

        // extract key=`d` from dict
        let ser = params![key("d")].into_serializer().unwrap();
        let val = ser.serialize(dict.clone()).unwrap();
        let Value::String(visible) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // it's mean true in sf-boolean
        assert_eq!(visible, "?1");
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_bs_serializer() {
        let val = Value::String(r#"value, with, lots, of, commas"#.to_string());
        let ser = params![bs].into_serializer().unwrap();
        let val = ser.serialize(val).unwrap();
        let Value::String(val) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // it's mean ByteSequence(Base64) in sf-byte-sequence
        assert_eq!(val, ":dmFsdWUsIHdpdGgsIGxvdHMsIG9mLCBjb21tYXM=:");
    }

    //noinspection SpellCheckingInspection
    #[test]
    fn test_nothing_operation_param() {
        let list = Value::String(r#" "london",   "berlin" "#.to_string());
        let ser = params![tr].into_serializer().unwrap();
        let val = ser.serialize(list.clone()).unwrap();
        let Value::String(val) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        // If you've read RFC9421, this test will seem a bit odd.
        // You would think that the whitespace on both ends should be gone,
        // but rest assured that it is done when the values from the HeaderMap are normalized.
        assert_eq!(val, r#" "london",   "berlin" "#);

        let ser = params![req].into_serializer().unwrap();
        let val = ser.serialize(list.clone()).unwrap();
        let Value::String(val) = val else {
            panic!("Expected String, but got {:?}", val);
        };

        assert_eq!(val, r#" "london",   "berlin" "#);
    }
}
