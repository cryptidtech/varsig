//! Serde (de)serialization for [`crate::Varsig`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, Varsig};
    use multibase::Base;
    use multicodec::Codec;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_serde_compact() {
        let vs = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build();

        assert_tokens(
            &vs.compact(),
            &[
                Token::Tuple { len: 5 },
                Token::BorrowedBytes(&[57]),
                Token::BorrowedBytes(&[237, 1]),
                Token::BorrowedBytes(&[0]),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::BorrowedBytes(&[
                    64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                Token::TupleEnd,
            ],
        )
    }

    #[test]
    fn test_serde_encoded_string() {
        let vs = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .with_encoding(Base::Base58Btc)
            .build_encoded();

        assert_tokens(
            &vs.readable(),
            &[Token::BorrowedStr("z3Ye1KGXPfHDM1YLPDDzHsZbDpjFS9qCRzDLh3nLRYgmVESqRsoxX7mEq7ZgoqmC6VZhheT4wMFUYgSyeC5gV5GvJYx8s2hZy")
            ],
        )
    }

    #[test]
    fn test_serde_readable() {
        let vs = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build();

        assert_tokens(
            &vs.readable(),
            &[
                Token::Struct {
                    name: "Varsig",
                    len: 5,
                },
                Token::BorrowedStr("version"),
                Token::U8(2_u8),
                Token::BorrowedStr("codec"),
                Token::U64(237_u64),
                Token::BorrowedStr("encoding"),
                Token::U64(0_u64),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::BorrowedStr("signature"),
                Token::BorrowedStr("f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_serde_json() {
        let vs1 = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build();
        let s = serde_json::to_string(&vs1).unwrap();
        let vs2: Varsig = serde_json::from_str(&s).unwrap();
        assert_eq!(vs1, vs2);
    }

    #[test]
    fn test_serde_cbor() {
        let vs1 = Builder::newv2(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .build();
        let v = serde_cbor::to_vec(&vs1).unwrap();
        let vs2: Varsig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(vs1, vs2);
    }

    #[test]
    fn test_eip191_unknown() {
        // this builds a Varsig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let vs1 = Builder::newv1(Codec::Secp256K1Pub)
            .with_msg_encoding(Codec::Eip191)
            .with_attributes(&[Codec::Keccak256.code()].to_vec())
            .with_signature_bytes([0u8; 64].as_slice())
            .build();
        let s = serde_json::to_string(&vs1).unwrap();
        let vs2: Varsig = serde_json::from_str(&s).unwrap();
        assert_eq!(vs1, vs2);
    }
}
