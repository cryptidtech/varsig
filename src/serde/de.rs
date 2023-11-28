use crate::vs::{Varsig, SIGILV1, SIGILV2};
use core::fmt;
use multicodec::Codec;
use multiutil::{EncodedVarbytes, EncodedVaruint, Varbytes, Varuint};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Varsig`]
impl<'de> Deserialize<'de> for Varsig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] =
            &["version", "codec", "encoding", "attributes", "signature"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Version,
            Codec,
            Encoding,
            Attributes,
            Signature,
        }

        struct VarsigVisitor;

        impl<'de> Visitor<'de> for VarsigVisitor {
            type Value = Varsig;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "struct Varsig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Varsig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut sigil = None;
                let mut codec = None;
                let mut msg_encoding = None;
                let mut attributes = None;
                let mut signature = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Version => {
                            if sigil.is_some() {
                                return Err(Error::duplicate_field("version"));
                            }
                            let v: u8 = map.next_value()?;
                            sigil = Some(match v {
                                1 => SIGILV1,
                                2 => SIGILV2,
                                _ => return Err(Error::custom("invlid Varsig version")),
                            });
                        }
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let c: u64 = map.next_value()?;
                            codec = Some(
                                Codec::try_from(c)
                                    .map_err(|_| Error::custom("invalid varsig codec"))?,
                            );
                        }
                        Field::Encoding => {
                            if msg_encoding.is_some() {
                                return Err(Error::duplicate_field("encoding"));
                            }
                            let e: u64 = map.next_value()?;
                            msg_encoding =
                                Some(Codec::try_from(e).map_err(|_| {
                                    Error::custom("invalid varsig payload encoding")
                                })?);
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(Error::duplicate_field("attributes"));
                            }
                            let cv: Vec<EncodedVaruint<u64>> = map.next_value()?;
                            attributes = Some(cv);
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(Error::duplicate_field("signature"));
                            }
                            let sig: EncodedVarbytes = map.next_value()?;
                            signature = Some(sig);
                        }
                    }
                }
                let sigil = sigil.ok_or_else(|| Error::missing_field("version"))?;
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let msg_encoding = msg_encoding.ok_or_else(|| Error::missing_field("encoding"))?;
                let attributes: Vec<u64> = attributes
                    .ok_or_else(|| Error::missing_field("attributes"))?
                    .iter()
                    .map(|v| v.clone().to_inner().to_inner())
                    .collect();
                let signature = signature
                    .ok_or_else(|| Error::missing_field("signature"))?
                    .to_inner()
                    .to_inner();
                match codec {
                    Codec::Ed25519Pub => Ok(Varsig::EdDSA {
                        sigil,
                        msg_encoding,
                        signature,
                    }),
                    _ => Ok(Varsig::Unknown {
                        sigil,
                        codec,
                        msg_encoding: Some(msg_encoding),
                        attributes,
                        signature,
                    }),
                }
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct("Varsig", FIELDS, VarsigVisitor)
        } else {
            let (sigil, codec, msg_encoding, attributes, signature): (
                Codec,
                Codec,
                Codec,
                Vec<Varuint<u64>>,
                Varbytes,
            ) = Deserialize::deserialize(deserializer)?;

            if sigil != SIGILV1 && sigil != SIGILV2 {
                return Err(Error::custom("deserialized sigil is not a Varsig sigil"));
            }

            let attributes = attributes.iter().map(|v| v.clone().to_inner()).collect();
            let signature = signature.to_inner();
            match codec {
                Codec::Ed25519Pub => Ok(Varsig::EdDSA {
                    sigil,
                    msg_encoding,
                    signature,
                }),
                _ => Ok(Varsig::Unknown {
                    sigil,
                    codec,
                    msg_encoding: Some(msg_encoding),
                    attributes,
                    signature,
                }),
            }
        }
    }
}
