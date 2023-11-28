use crate::vs::Varsig;
use multicodec::Codec;
use multiutil::{CodecInfo, EncodedVaruint, Varbytes, Varuint};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Varsig`]
impl ser::Serialize for Varsig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let cv: Vec<EncodedVaruint<u64>> = self
                .attributes()
                .iter()
                .map(|v| Varuint::<u64>::encoded_new(*v))
                .collect();
            let version = match self.sigil() {
                Codec::Varsigv1 => 1u8,
                Codec::Varsigv2 => 2u8,
                _ => return Err(ser::Error::custom("invalid sigil")),
            };
            let mut ss = serializer.serialize_struct("Varsig", 5)?;
            ss.serialize_field("version", &version)?;
            ss.serialize_field("codec", &self.codec().code())?;
            ss.serialize_field("encoding", &self.payload_encoding().code())?;
            ss.serialize_field("attributes", &cv)?;
            ss.serialize_field("signature", &Varbytes::encoded_new(self.signature()))?;
            ss.end()
        } else {
            let cv: Vec<Varuint<u64>> = self.attributes().iter().map(|v| Varuint(*v)).collect();
            let sig = Varbytes(self.signature());
            (self.sigil(), self.codec(), self.payload_encoding(), cv, sig).serialize(serializer)
        }
    }
}
