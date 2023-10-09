use crate::error::Error;
use multicodec::{codec::Codec, mc::MultiCodec};
use std::fmt;

/// The main varsig structure
#[derive(Clone, Debug, PartialEq)]
pub enum Varsig {
    /// Unknown signature
    Unknown {
        /// key codec value that is Unknown
        key: Codec,
        /// encoding codec for the data that was signed
        encoding: Codec,
        /// signature-specific header values
        signature_specific: Vec<Codec>,
        /// the signature-specific data
        signature: Vec<u8>,
    },

    /// EdDSA signature, key codec 0xED
    EdDSA {
        /// the encoding info
        encoding: Codec,
        /// the signature data
        signature: Vec<u8>,
    },
}

impl Varsig {
    /// encodes the Varsig to a buffer
    pub fn to_vec(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Codec::Varsig.into();
        match self {
            Varsig::Unknown {
                key,
                encoding,
                signature_specific,
                signature,
            } => {
                let k: Vec<u8> = key.clone().into();
                v.extend_from_slice(&k);
                let e: Vec<u8> = encoding.clone().into();
                v.extend_from_slice(&e);
                for ss in signature_specific {
                    let s: Vec<u8> = ss.clone().into();
                    v.extend_from_slice(&s);
                }
                v.extend_from_slice(&signature);
            }
            Varsig::EdDSA {
                encoding,
                signature,
            } => {
                let c: Vec<u8> = Codec::Ed25519Pub.into();
                v.extend_from_slice(&c);
                let e: Vec<u8> = encoding.clone().into();
                v.extend_from_slice(&e);
                v.extend_from_slice(&signature);
            }
        }
        v
    }

    /// get the codec for the Varsig
    pub fn key(&self) -> Codec {
        match self {
            Varsig::Unknown {
                key,
                encoding: _,
                signature_specific: _,
                signature: _,
            } => key.clone(),
            Varsig::EdDSA { .. } => Codec::Ed25519Pub,
        }
    }

    /// get the encoding for the Varsig
    pub fn encoding(&self) -> Codec {
        let encoding = match self {
            Varsig::Unknown {
                key: _,
                encoding,
                signature_specific: _,
                signature: _,
            } => encoding,
            Varsig::EdDSA {
                encoding,
                signature: _,
            } => encoding,
        };
        encoding.clone()
    }

    /// get the signature payload
    pub fn signature(&self) -> Vec<u8> {
        let signature = match self {
            Varsig::Unknown {
                key: _,
                encoding: _,
                signature_specific: _,
                signature,
            } => signature,
            Varsig::EdDSA {
                encoding: _,
                signature,
            } => signature,
        };
        signature.clone()
    }
}

impl Default for Varsig {
    fn default() -> Self {
        Varsig::Unknown {
            key: Codec::default(),
            encoding: Codec::default(),
            signature_specific: Vec::default(),
            signature: Vec::default(),
        }
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
            Ok((_, v)) => Self::try_from(v.as_slice()),
            Err(e) => Err(Error::Multibase(e)),
        }
    }
}

impl TryFrom<Vec<u8>> for Varsig {
    type Error = Error;

    fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(v.as_slice())
    }
}

impl TryFrom<&[u8]> for Varsig {
    type Error = Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // ensure the first byte is the magic byte
        let vs = MultiCodec::try_from(data)?;
        if vs.codec() != Codec::Varsig {
            return Err(Error::MissingSigil);
        }

        // decoded the unsigned varint multicodec value
        let key = MultiCodec::try_from(vs.data())?;

        // parse the encoding codec for the data that was signed
        let encoding = MultiCodec::try_from(key.data())?;

        Ok(match key.codec() {
            Codec::Ed25519Pub => Self::EdDSA {
                encoding: encoding.codec(),
                signature: encoding.data().to_vec(),
            },
            _ => Self::Unknown {
                key: key.codec(),
                encoding: encoding.codec(),
                signature_specific: Vec::default(),
                signature: encoding.data().to_vec(),
            },
        })
    }
}

impl fmt::Display for Varsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Varsig:")?;
        match self {
            Varsig::Unknown {
                key,
                encoding,
                signature_specific,
                signature,
            } => {
                writeln!(f, "\tKey Type: {}", key)?;
                writeln!(f, "\tEncoding: {}", encoding)?;
                write!(f, "\tSignature Specific: [ ")?;
                for ss in signature_specific {
                    write!(f, "{}, ", ss)?;
                }
                writeln!(f, "]")?;
                writeln!(
                    f,
                    "\tSig: ({}) {}",
                    signature.len(),
                    hex::encode(&signature)
                )?;
            }
            Varsig::EdDSA {
                encoding,
                signature,
            } => {
                writeln!(f, "\tKey Type: {}", self.key())?;
                writeln!(f, "\tEncoding: {}", encoding)?;
                writeln!(
                    f,
                    "\tSig: ({}) {}",
                    signature.len(),
                    hex::encode(&signature)
                )?;
            }
        }
        Ok(())
    }
}

/// Builder for Varsigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    key: Codec,
    encoding: Codec,
    signature_specific: Vec<Codec>,
    signature: Vec<u8>,
}

impl Builder {
    /// set the key codec
    pub fn key(mut self, codec: Codec) -> Self {
        self.key = codec;
        self
    }

    /// set the encoding of the signed data
    pub fn encoding(mut self, codec: Codec) -> Self {
        self.encoding = codec;
        self
    }

    /// set the signature data
    pub fn signature(mut self, data: &[u8]) -> Self {
        self.signature = data.to_vec();
        self
    }

    /// set the signature-specific values for the header
    pub fn signature_specific(mut self, data: &[Codec]) -> Self {
        self.signature_specific = data.to_vec();
        self
    }

    /// build it
    pub fn build(&self) -> Varsig {
        match self.key {
            Codec::Ed25519Pub => Varsig::EdDSA {
                encoding: self.encoding,
                signature: self.signature.clone(),
            },
            _ => Varsig::Unknown {
                key: self.key,
                encoding: self.encoding,
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
        let v = Varsig::default().to_vec();
        assert_eq!(3, v.len());
    }

    #[test]
    fn test_unknown() {
        let vs = Builder::default()
            .key(Codec::Unknown(0xDEAD))
            .encoding(Codec::Raw)
            .signature(Vec::default().as_slice())
            .build();
        let v = vs.to_vec();
        assert_eq!(5, v.len());
    }

    #[test]
    fn test_eddsa() {
        let vs = Builder::default()
            .key(Codec::Ed25519Pub)
            .encoding(Codec::Raw)
            .signature(Vec::default().as_slice())
            .build();
        let v = vs.to_vec();
        assert_eq!(4, v.len());
    }

    #[test]
    fn test_eip191_unknown() {
        // this builds a Varsig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let vs = Builder::default()
            .key(Codec::Secp256K1Pub)
            .encoding(Codec::Eip191)
            .signature_specific(&[Codec::Keccak256])
            .signature(Vec::default().as_slice())
            .build();
        let v = vs.to_vec();
        for b in &v {
            println!("0x{:0>1x}", b);
        }
        assert_eq!(7, v.len());
    }
}
