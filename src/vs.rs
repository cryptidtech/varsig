use crate::error::Error;
use multicodec::{codec::Codec, mc::MultiCodec};
use std::fmt;

/// The main varsig structure
#[derive(Clone, Debug, PartialEq)]
pub enum Varsig {
    /// Unknown signature
    Unknown {
        /// version of the varsig header
        version: Codec,
        /// key codec value that is Unknown
        key: Codec,
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
        version: Codec,
        /// the encoding info
        encoding: Codec,
        /// the signature data
        signature: Vec<u8>,
    },
}

impl Varsig {
    /// encodes the Varsig to a buffer
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Varsig::Unknown {
                version,
                key,
                encoding,
                signature_specific,
                signature,
            } => {
                let mut v = version.to_vec();
                v.extend_from_slice(&key.to_vec());
                match version {
                    Codec::Varsigv1 => {
                        for ss in signature_specific {
                            v.extend_from_slice(&ss.to_vec());
                        }
                        if let Some(encoding) = encoding {
                            v.extend_from_slice(&encoding.to_vec());
                        }
                    }
                    Codec::Varsigv2 => {
                        if let Some(encoding) = encoding {
                            v.extend_from_slice(&encoding.to_vec());
                        }
                        for ss in signature_specific {
                            v.extend_from_slice(&ss.to_vec());
                        }
                    }
                    _ => {}
                }
                v.extend_from_slice(&signature);
                v
            }
            Varsig::EdDSA {
                version,
                encoding,
                signature,
            } => {
                let mut v: Vec<u8> = version.clone().into();
                let c: Vec<u8> = Codec::Ed25519Pub.into();
                v.extend_from_slice(&c);
                // there are no signature-specific values
                let e: Vec<u8> = encoding.clone().into();
                v.extend_from_slice(&e);
                v.extend_from_slice(&signature);
                v
            }
        }
    }

    /// get the version for the Varsig
    pub fn version(&self) -> Codec {
        match self {
            Varsig::Unknown { version, .. } => version.clone(),
            Varsig::EdDSA { .. } => Codec::Ed25519Pub,
        }
    }

    /// get the codec for the Varsig
    pub fn key(&self) -> Codec {
        match self {
            Varsig::Unknown { key, .. } => key.clone(),
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

    /// get the signature payload
    pub fn signature(&self) -> Vec<u8> {
        let signature = match self {
            Varsig::Unknown { signature, .. } => signature,
            Varsig::EdDSA { signature, .. } => signature,
        };
        signature.clone()
    }
}

/*
impl Default for Varsig {
    fn default() -> Self {
        Varsig::Unknown {
            version: Codec::Varsigv2,
            key: Codec::default(),
            encoding: None,
            signature_specific: Vec::default(),
            signature: Vec::default(),
        }
    }
}
*/

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
        let version = MultiCodec::try_from(data)?;
        if version.codec() != Codec::Varsigv1 && version.codec() != Codec::Varsigv2 {
            return Err(Error::MissingSigil);
        }

        // decoded the unsigned varint multicodec value
        let key = MultiCodec::try_from(version.data())?;

        Ok(match key.codec() {
            Codec::Ed25519Pub => {
                // parse the encoding codec for the data that was signed
                let encoding = MultiCodec::try_from(key.data())?;

                Self::EdDSA {
                    version: version.codec(),
                    encoding: encoding.codec(),
                    signature: encoding.data().to_vec(),
                }
            }
            _ => {
                let (encoding, data) = match version.codec() {
                    Codec::Varsigv1 => (None, key.data()),
                    Codec::Varsigv2 => {
                        // parse the encoding codec for the data that was signed
                        let e = MultiCodec::try_from(key.data())?;
                        (Some(e.codec()), e.data())
                    }
                    _ => return Err(Error::MissingSigil),
                };

                Self::Unknown {
                    version: version.codec(),
                    key: key.codec(),
                    encoding,
                    signature_specific: Vec::default(),
                    signature: data.to_vec(),
                }
            }
        })
    }
}

impl fmt::Display for Varsig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Varsig::Unknown {
                version,
                key,
                encoding,
                signature_specific,
                signature,
            } => {
                writeln!(f, "{}:", version)?;
                writeln!(f, "\tKey Type: {}", key)?;
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
                version,
                encoding,
                signature,
            } => {
                writeln!(f, "{}:", version)?;
                writeln!(f, "\tKey Type: {}", self.key())?;
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

/// Builder for Varsigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    version: Codec,
    key: Codec,
    encoding: Codec,
    signature_specific: Vec<Codec>,
    signature: Vec<u8>,
}

impl Builder {
    /// create a new v1 varsig
    pub fn newv1() -> Self {
        Self {
            version: Codec::Varsigv1,
            ..Default::default()
        }
    }

    /// create a new v1 varsig
    pub fn newv2() -> Self {
        Self {
            version: Codec::Varsigv2,
            ..Default::default()
        }
    }

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
                version: self.version,
                encoding: self.encoding,
                signature: self.signature.clone(),
            },
            _ => Varsig::Unknown {
                version: self.version,
                key: self.key,
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
        let v = vs.to_vec();
        assert_eq!(3, v.len());
    }

    #[test]
    fn test_unknown() {
        let vs = Builder::newv1()
            .key(Codec::Unknown(0xDEAD))
            .encoding(Codec::Raw)
            .signature(Vec::default().as_slice())
            .build();
        let v = vs.to_vec();
        assert_eq!(5, v.len());
    }

    #[test]
    fn test_eddsa() {
        let vs = Builder::newv2()
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
        let vs = Builder::newv1()
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
