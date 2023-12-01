use crate::Error;
use multibase::Base;
use multicodec::Codec;
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use ssh_key::{Algorithm, Signature};
use std::fmt;

/// the varsig sigil
pub const SIGIL: Codec = Codec::Varsig;

/// a base encoded varsig
pub type EncodedVarsig = BaseEncoded<Varsig>;

/// The main varsig structure
#[derive(Clone, PartialEq)]
pub enum Varsig {
    /// Unknown signature
    Unknown {
        /// version of the varsig header
        version: u8,
        /// key codec value that is Unknown
        codec: Codec,
        /// msg encoding codec
        msg_encoding: Option<Codec>,
        /// signature-specific attributes
        attributes: Vec<u64>,
        /// the signature-specific data
        signature: Vec<u8>,
    },

    /// EdDSA signature, key codec 0xED
    EdDSA {
        /// version of the varsig header
        version: u8,
        /// the payload encoding
        msg_encoding: Codec,
        /// the signature data
        signature: Vec<u8>,
    },
}

impl Varsig {
    /// get the version
    pub fn version(&self) -> u8 {
        match self {
            Varsig::Unknown { version, .. } => *version,
            Varsig::EdDSA { version, .. } => *version,
        }
    }

    /// get the payload encoding
    pub fn msg_encoding(&self) -> Codec {
        match self {
            Varsig::Unknown { msg_encoding, .. } => msg_encoding.unwrap_or(Codec::Raw),
            Varsig::EdDSA { msg_encoding, .. } => *msg_encoding,
        }
    }

    /// get the attributes
    pub fn attributes(&self) -> Vec<u64> {
        match self {
            Varsig::Unknown { attributes, .. } => attributes.clone(),
            Varsig::EdDSA { .. } => Vec::default(),
        }
    }

    /// get the signature vector
    pub fn signature(&self) -> Vec<u8> {
        match self {
            Varsig::Unknown { signature, .. } => signature.clone(),
            Varsig::EdDSA { signature, .. } => signature.clone(),
        }
    }
}

impl CodecInfo for Varsig {
    /// Return that we are a Varsig object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the signing codec for the varsig
    fn codec(&self) -> Codec {
        match self {
            Varsig::Unknown { codec, .. } => *codec,
            Varsig::EdDSA { .. } => Codec::Ed25519Pub,
        }
    }
}

impl EncodingInfo for Varsig {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Into<Vec<u8>> for Varsig {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the version
        v.append(&mut Varuint(self.version()).into());
        // add in the signing codec
        v.append(&mut self.codec().into());
        let attributes = self.attributes();
        let mut signature = self.signature();
        if self.version() == 2 {
            // add in the payload encoding
            v.append(&mut self.msg_encoding().into());
            // add in the number signature specific attributes
            v.append(&mut Varuint(attributes.len()).into());
            // add in the signature specific attributes
            attributes
                .iter()
                .for_each(|a| v.append(&mut Varuint(*a).into()));
            // add in the signature data
            v.append(&mut Varbytes(signature).into());
        } else {
            // add in the signature specific attributes
            for ss in attributes {
                v.append(&mut Varuint(ss).into());
            }
            // add in the payload encoding
            v.append(&mut self.msg_encoding().into());
            // add the signature data
            v.append(&mut signature);
        }
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Varsig {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (vs, _) = Self::try_decode_from(s)?;
        Ok(vs)
    }
}

impl<'a> TryDecodeFrom<'a> for Varsig {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the version
        let (version, ptr) = Varuint::<u8>::try_decode_from(bytes)?;
        let version = version.to_inner();
        // decoded the signing coded
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // get the payload encoding if v2
        let (msg_encoding, ptr) = match version {
            1 => (None, ptr),
            2 => {
                // parse the encoding codec for the data that was signed
                let (msg_encoding, ptr) = Codec::try_decode_from(ptr)?;
                (Some(msg_encoding), ptr)
            }
            _ => return Err(Error::InvalidVersion(version)),
        };
        // get the attributes if v2
        let (attributes, ptr) = match version {
            1 => (Vec::default(), ptr),
            2 => {
                // parse the number of attributes
                let (len, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
                let len = len.to_inner();

                let mut v = Vec::with_capacity(len);
                let mut p = ptr;
                for _ in 0..len {
                    // parse the varuint attribute
                    let (attribute, ptr) = Varuint::<u64>::try_decode_from(p)?;
                    v.push(attribute.to_inner());
                    p = ptr;
                }
                (v, p)
            }
            _ => return Err(Error::InvalidVersion(version)),
        };
        let (signature, ptr) = match version {
            1 => match codec {
                Codec::Ed25519Pub => {
                    let s = ptr[..64].to_vec();
                    let p = &ptr[64..];
                    (s, p)
                }
                _ => {
                    let s = ptr[..].to_vec();
                    let p = &ptr[..];
                    (s, p)
                }
            },
            2 => {
                // parse the signature byts array
                let (s, p) = Varbytes::try_decode_from(ptr)?;
                (s.to_inner(), p)
            }
            _ => return Err(Error::InvalidVersion(version)),
        };

        match codec {
            Codec::Ed25519Pub => {
                let msg_encoding = msg_encoding.unwrap_or(Codec::Raw);
                Ok((
                    Self::EdDSA {
                        version,
                        msg_encoding,
                        signature,
                    },
                    ptr,
                ))
            }
            _ => Ok((
                Self::Unknown {
                    version,
                    codec,
                    msg_encoding,
                    attributes,
                    signature,
                },
                ptr,
            )),
        }
    }
}

/// Exposes direct access to the signature data
impl AsRef<[u8]> for Varsig {
    fn as_ref(&self) -> &[u8] {
        match self {
            Varsig::Unknown { signature, .. } => signature.as_ref(),
            Varsig::EdDSA { signature, .. } => signature.as_ref(),
        }
    }
}

impl fmt::Debug for Varsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (version, codec) = match self {
            Varsig::Unknown { version, codec, .. } => (*version, *codec),
            Varsig::EdDSA { version, .. } => (*version, Codec::Ed25519Pub),
        };
        write!(f, "{:?} v{} - {:?}", SIGIL, version, codec)
    }
}

/// Builder for Varsigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    version: u8,
    codec: Codec,
    msg_encoding: Codec,
    attributes: Vec<u64>,
    signature: Vec<u8>,
    encoding: Option<Base>,
}

impl Builder {
    /// create a new v1 varsig
    pub fn newv1(codec: Codec) -> Self {
        Self {
            version: 1,
            codec,
            ..Default::default()
        }
    }

    /// create a new v1 varsig
    pub fn newv2(codec: Codec) -> Self {
        Self {
            version: 2,
            codec,
            ..Default::default()
        }
    }

    /// create new v1 from ssh Signature
    pub fn new_from_ssh_signature(sig: &Signature) -> Result<Self, Error> {
        match sig.algorithm() {
            Algorithm::Ed25519 => Ok(Self {
                version: 2,
                codec: Codec::Ed25519Pub,
                msg_encoding: Codec::Raw,
                signature: sig.as_bytes().to_vec(),
                ..Default::default()
            }),
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }

    /// set the key codec
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// set the string encoding
    pub fn with_encoding(mut self, base: Base) -> Self {
        self.encoding = Some(base);
        self
    }

    /// set the encoding of the signed data
    pub fn with_msg_encoding(mut self, codec: Codec) -> Self {
        self.msg_encoding = codec;
        self
    }

    /// set the signature data
    pub fn with_signature_bytes(mut self, data: &[u8]) -> Self {
        self.signature = data.to_vec();
        self
    }

    /// set the signature-specific values for the header
    pub fn with_attributes(mut self, data: &Vec<u64>) -> Self {
        self.attributes = data.clone();
        self
    }

    /// build it
    pub fn build(&self) -> Varsig {
        match self.codec {
            Codec::Ed25519Pub => Varsig::EdDSA {
                version: self.version,
                msg_encoding: self.msg_encoding,
                signature: self.signature.clone(),
            },
            _ => Varsig::Unknown {
                version: self.version,
                codec: self.codec,
                msg_encoding: Some(self.msg_encoding),
                attributes: self.attributes.clone(),
                signature: self.signature.clone(),
            },
        }
    }

    /// build a base encoded varsig
    pub fn build_encoded(&self) -> EncodedVarsig {
        let vs = match self.codec {
            Codec::Ed25519Pub => Varsig::EdDSA {
                version: self.version,
                msg_encoding: self.msg_encoding,
                signature: self.signature.clone(),
            },
            _ => Varsig::Unknown {
                version: self.version,
                codec: self.codec,
                msg_encoding: Some(self.msg_encoding),
                attributes: self.attributes.clone(),
                signature: self.signature.clone(),
            },
        };
        let base = self.encoding.unwrap_or(Base::Base16Lower);
        BaseEncoded::new_base(base, vs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded() {
        let vs = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build_encoded();
        let s = vs.to_string();
        assert_eq!(vs, EncodedVarsig::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_default() {
        let vs1 = Builder::newv2(Codec::default())
            .with_msg_encoding(Codec::default())
            .with_signature_bytes(Vec::default().as_slice())
            .build_encoded();
        let s = vs1.to_string();
        let vs2 = EncodedVarsig::try_from(s.as_str()).unwrap();
        assert_eq!(vs1, vs2);

        let vsa = vs1.clone().to_inner();
        let vsb = vs2.clone().to_inner();
        assert_eq!(vsa, vsb);
    }

    #[test]
    fn test_eddsa() {
        let vs = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build();
        let v: Vec<u8> = vs.clone().into();
        assert_eq!(vs, Varsig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_eip191_unknown() {
        // this builds a Varsig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let vs1 = Builder::newv2(Codec::Secp256K1Pub)
            .with_msg_encoding(Codec::Eip191)
            .with_attributes(&[Codec::Keccak256.code()].to_vec())
            .with_signature_bytes([0u8; 64].as_slice())
            .build();
        let v: Vec<u8> = vs1.clone().into();
        let vs2 = Varsig::try_from(v.as_slice()).unwrap();
        assert_eq!(vs1, vs2);
    }
}
