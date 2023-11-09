use crate::error::Error;
use multibase::Base;
use multicodec::codec::Codec;
use multiutil::{EncodeInto, TryDecodeFrom};
use ssh_key::{Algorithm, Signature};
use std::fmt;

/// the varsig v1 sigil
pub const SIGILV1: Codec = Codec::Varsigv1;

/// the varsig v2 sigil
pub const SIGILV2: Codec = Codec::Varsigv2;

/// The main varsig structure
#[derive(Clone, PartialEq)]
pub enum Varsig {
    /// Unknown signature
    Unknown {
        /// version of the varsig header
        sigil: Codec,
        /// key codec value that is Unknown
        codec: Codec,
        /// multibase encoding
        string_encoding: Base,
        /// encoding codec for the data that was signed
        encoding: Option<Codec>,
        /// signature-specific header values
        signature_specific: Vec<Codec>,
        /// the signature-specific data
        signature: Vec<u8>,
    },

    /// EdDSA signature, key codec 0xED
    EdDSA {
        /// version of the varsig header
        sigil: Codec,
        /// multibase encoding
        string_encoding: Base,
        /// the encoding info
        encoding: Codec,
        /// the signature data
        signature: Vec<u8>,
    },
}

impl Varsig {
    /// get the sigil for the Varsig
    pub fn sigil(&self) -> Codec {
        match self {
            Varsig::Unknown { sigil, .. } => *sigil,
            Varsig::EdDSA { sigil, .. } => *sigil,
        }
    }

    /// get the codec for the Varsig
    pub fn codec(&self) -> Codec {
        match self {
            Varsig::Unknown { codec, .. } => *codec,
            Varsig::EdDSA { .. } => Codec::Ed25519Pub,
        }
    }

    /// get the encoding for the Varsig
    pub fn encoding(&self) -> Option<Codec> {
        let encoding = match self {
            Varsig::Unknown { encoding, .. } => *encoding,
            Varsig::EdDSA { encoding, .. } => Some(*encoding),
        };
        encoding.clone()
    }

    /// get the string encoding
    pub fn string_encoding(&self) -> Base {
        match self {
            Varsig::Unknown {
                string_encoding, ..
            } => *string_encoding,
            Varsig::EdDSA {
                string_encoding, ..
            } => *string_encoding,
        }
    }

    /// set the string encoding
    pub fn set_string_encoding(&mut self, e: Base) {
        match self {
            Varsig::Unknown {
                string_encoding, ..
            } => *string_encoding = e,
            Varsig::EdDSA {
                string_encoding, ..
            } => *string_encoding = e,
        }
    }

    /// get the signature payload
    pub fn signature(&self) -> Vec<u8> {
        let signature = match self {
            Varsig::Unknown { signature, .. } => signature,
            Varsig::EdDSA { signature, .. } => signature,
        };
        signature.clone()
    }
}

impl fmt::Debug for Varsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Varsig::Unknown {
                sigil,
                codec,
                string_encoding: _,
                encoding,
                signature_specific,
                signature,
            } => {
                writeln!(f, "{}:", sigil)?;
                writeln!(f, "\tKey Type: {}", codec)?;
                match encoding {
                    Some(e) => {
                        writeln!(f, "\tEncoding: {}", e)?;
                    }
                    None => {
                        writeln!(f, "\tEncoding: Unknown")?;
                    }
                }
                write!(f, "\tSignature Specific: [ ")?;
                for ss in signature_specific {
                    write!(f, "{}, ", ss)?;
                }
                writeln!(f, "]")?;
                let mut sig = hex::encode(&signature);
                if sig.len() > 16 {
                    let bs = sig.as_str()[..8].to_string();
                    let es = sig.as_str()[sig.len() - 8..].to_string();
                    sig = format!("{}...{}", bs, es);
                }
                writeln!(f, "\tSig: ({}) {}", signature.len(), sig)?;
            }
            Varsig::EdDSA {
                sigil,
                string_encoding: _,
                encoding,
                signature,
            } => {
                writeln!(f, "{}:", sigil)?;
                writeln!(f, "\tKey Type: {}", self.codec())?;
                writeln!(f, "\tEncoding: {}", encoding)?;
                let mut sig = hex::encode(&signature);
                if sig.len() > 16 {
                    let bs = sig.as_str()[..8].to_string();
                    let es = sig.as_str()[sig.len() - 8..].to_string();
                    sig = format!("{}...{}", bs, es);
                }
                writeln!(f, "\tSig: ({}) {}", signature.len(), sig)?;
            }
        }
        Ok(())
    }
}

impl EncodeInto for Varsig {
    fn encode_into(&self) -> Vec<u8> {
        match self {
            Varsig::Unknown {
                sigil,
                codec,
                string_encoding: _,
                encoding,
                signature_specific,
                signature,
            } => {
                // start with the sigil
                let mut v = sigil.encode_into();

                // add in the codec
                v.append(&mut codec.encode_into());

                // add in the encoding
                if let Some(enc) = encoding {
                    v.append(&mut enc.encode_into());
                }

                // add in the signature specific values
                for ss in signature_specific {
                    v.append(&mut ss.encode_into());
                }

                // add in the signature data
                v.append(&mut signature.clone());

                v
            }
            Varsig::EdDSA {
                sigil,
                string_encoding: _,
                encoding,
                signature,
            } => {
                // start with the sigil
                let mut v = sigil.encode_into();

                // add the key codec
                v.append(&mut Codec::Ed25519Pub.encode_into());

                // add the encoding data
                v.append(&mut encoding.encode_into());

                // add the signature data
                v.append(&mut signature.clone());

                v
            }
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

/// Convert the varsig to a STring using the specified encoding
impl ToString for Varsig {
    fn to_string(&self) -> String {
        let v = self.encode_into();
        multibase::encode(self.string_encoding(), &v)
    }
}

impl TryFrom<String> for Varsig {
    type Error = Error;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&str> for Varsig {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match multibase::decode(s) {
            Ok((base, v)) => {
                let (mut vs, _) = Self::try_decode_from(v.as_slice())?;
                vs.set_string_encoding(base);
                Ok(vs)
            }
            Err(e) => Err(Error::Multibase(e)),
        }
    }
}

impl TryFrom<Vec<u8>> for Varsig {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        let (vs, _) = Self::try_decode_from(v.as_slice())?;
        Ok(vs)
    }
}

impl<'a> TryDecodeFrom<'a> for Varsig {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // ensure the first byte is a varsig sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGILV1 && sigil != SIGILV2 {
            return Err(Error::MissingSigil);
        }

        // decoded the unsigned varint multicodec value
        let (codec, ptr) = Codec::try_decode_from(ptr)?;

        Ok(match codec {
            Codec::Ed25519Pub => {
                // parse the encoding codec for the data that was signed
                let (encoding, ptr) = Codec::try_decode_from(ptr)?;

                (
                    Self::EdDSA {
                        sigil,
                        string_encoding: Base::Base16Lower,
                        encoding,
                        signature: ptr.to_vec(),
                    },
                    ptr,
                )
            }
            _ => {
                let (encoding, ptr) = match sigil {
                    Codec::Varsigv1 => (None, ptr),
                    Codec::Varsigv2 => {
                        // parse the encoding codec for the data that was signed
                        let (encoding, ptr) = Codec::try_decode_from(ptr)?;
                        (Some(encoding), ptr)
                    }
                    _ => return Err(Error::MissingSigil),
                };

                (
                    Self::Unknown {
                        sigil,
                        codec,
                        string_encoding: Base::Base16Lower,
                        encoding,
                        signature_specific: Vec::default(),
                        signature: ptr.to_vec(),
                    },
                    ptr,
                )
            }
        })
    }
}

impl TryFrom<&Signature> for Varsig {
    type Error = Error;

    fn try_from(sig: &Signature) -> Result<Self, Self::Error> {
        match sig.algorithm() {
            Algorithm::Ed25519 => Ok(Builder::newv1()
                .with_codec(Codec::Ed25519Pub)
                .with_encoding(Codec::Raw)
                .with_signature_bytes(sig.as_bytes())
                .build()),
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }
}

/// Builder for Varsigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    sigil: Codec,
    codec: Codec,
    string_encoding: Option<Base>,
    encoding: Codec,
    signature_specific: Vec<Codec>,
    signature: Vec<u8>,
}

impl Builder {
    /// create a new v1 varsig
    pub fn newv1() -> Self {
        Self {
            sigil: Codec::Varsigv1,
            ..Default::default()
        }
    }

    /// create a new v1 varsig
    pub fn newv2() -> Self {
        Self {
            sigil: Codec::Varsigv1,
            ..Default::default()
        }
    }

    /// set the key codec
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// set the string encoding
    pub fn with_string_encoding(mut self, base: Base) -> Self {
        self.string_encoding = Some(base);
        self
    }

    /// set the encoding of the signed data
    pub fn with_encoding(mut self, codec: Codec) -> Self {
        self.encoding = codec;
        self
    }

    /// set the signature data
    pub fn with_signature_bytes(mut self, data: &[u8]) -> Self {
        self.signature = data.to_vec();
        self
    }

    /// set the signature-specific values for the header
    pub fn with_signature_specific(mut self, data: &[Codec]) -> Self {
        self.signature_specific = data.to_vec();
        self
    }

    /// build it
    pub fn build(&self) -> Varsig {
        match self.codec {
            Codec::Ed25519Pub => Varsig::EdDSA {
                sigil: self.sigil,
                string_encoding: self.string_encoding.unwrap_or(Base::Base16Lower),
                encoding: self.encoding,
                signature: self.signature.clone(),
            },
            _ => Varsig::Unknown {
                sigil: self.sigil,
                codec: self.codec,
                string_encoding: self.string_encoding.unwrap_or(Base::Base16Lower),
                encoding: Some(self.encoding),
                signature_specific: self.signature_specific.clone(),
                signature: self.signature.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let vs = Builder::newv1().build();
        let v = vs.encode_into();
        assert_eq!(3, v.len());
    }

    #[test]
    fn test_unknown() {
        let vs = Builder::newv1()
            .with_codec(Codec::Unknown(0xDEAD))
            .with_encoding(Codec::Raw)
            .with_signature_bytes(Vec::default().as_slice())
            .build();
        let v = vs.encode_into();
        assert_eq!(5, v.len());
    }

    #[test]
    fn test_eddsa() {
        let vs = Builder::newv2()
            .with_codec(Codec::Ed25519Pub)
            .with_encoding(Codec::Raw)
            .with_signature_bytes(Vec::default().as_slice())
            .build();
        let v = vs.encode_into();
        assert_eq!(4, v.len());
    }

    #[test]
    fn test_eip191_unknown() {
        // this builds a Varsig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let vs = Builder::newv1()
            .with_codec(Codec::Secp256K1Pub)
            .with_encoding(Codec::Eip191)
            .with_signature_specific(&[Codec::Keccak256])
            .with_signature_bytes(Vec::default().as_slice())
            .build();
        let v = vs.encode_into();
        for b in &v {
            println!("0x{:0>1x}", b);
        }
        assert_eq!(7, v.len());
    }
}
