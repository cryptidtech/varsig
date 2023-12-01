use crate::{vs::SIGIL, Varsig};
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
            let mut ss = serializer.serialize_struct("Varsig", 5)?;
            ss.serialize_field("version", &self.version())?;
            ss.serialize_field("codec", &self.codec().code())?;
            ss.serialize_field("encoding", &self.msg_encoding().code())?;
            ss.serialize_field("attributes", &cv)?;
            ss.serialize_field("signature", &Varbytes::encoded_new(self.signature()))?;
            ss.end()
        } else {
            let cv: Vec<Varuint<u64>> = self.attributes().iter().map(|v| Varuint(*v)).collect();
            let sig = Varbytes(self.signature());
            (
                SIGIL,
                Varuint(self.version()),
                self.codec(),
                self.msg_encoding(),
                cv,
                sig,
            )
                .serialize(serializer)
        }
    }
}
