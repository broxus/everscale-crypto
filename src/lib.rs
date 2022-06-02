extern crate core;

pub mod ed25519;

#[cfg(feature = "tl-proto")]
pub mod tl {
    use std::ops::Deref;

    /// Public key which is used in protocol
    #[derive(Debug, Copy, Clone, Eq, PartialEq, tl_proto::TlRead, tl_proto::TlWrite)]
    #[tl(boxed)]
    pub enum PublicKey<'tl> {
        #[tl(id = 0x4813b4c6, size_hint = 32)]
        Ed25519 { key: &'tl [u8; 32] },
        #[tl(id = 0x34ba45cb)]
        Overlay { name: &'tl [u8] },
        #[tl(id = 0x2dbcadd4, size_hint = 32)]
        Aes { key: &'tl [u8; 32] },
        #[tl(id = 0xb61f450a)]
        Unencoded { data: &'tl [u8] },
    }

    impl PublicKey<'_> {
        pub fn as_equivalent_owned(&self) -> PublicKeyOwned {
            match self {
                &Self::Ed25519 { key } => PublicKeyOwned::Ed25519 { key: *key },
                Self::Overlay { name } => PublicKeyOwned::Overlay {
                    name: name.to_vec(),
                },
                &Self::Aes { key } => PublicKeyOwned::Aes { key: *key },
                Self::Unencoded { data } => PublicKeyOwned::Unencoded {
                    data: data.to_vec(),
                },
            }
        }
    }

    /// Public key which is used in protocol. Owned version
    #[derive(Debug, Clone, Eq, PartialEq, tl_proto::TlRead, tl_proto::TlWrite)]
    #[tl(boxed)]
    pub enum PublicKeyOwned {
        #[tl(id = 0x4813b4c6, size_hint = 32)]
        Ed25519 { key: [u8; 32] },
        #[tl(id = 0x34ba45cb)]
        Overlay { name: Vec<u8> },
        #[tl(id = 0x2dbcadd4, size_hint = 32)]
        Aes { key: [u8; 32] },
        #[tl(id = 0xb61f450a)]
        Unencoded { data: Vec<u8> },
    }

    impl PublicKeyOwned {
        pub fn as_equivalent_ref(&self) -> PublicKey<'_> {
            match self {
                Self::Ed25519 { key } => PublicKey::Ed25519 { key },
                Self::Overlay { name } => PublicKey::Overlay {
                    name: name.as_slice(),
                },
                Self::Aes { key } => PublicKey::Aes { key },
                Self::Unencoded { data } => PublicKey::Unencoded {
                    data: data.as_slice(),
                },
            }
        }
    }

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[repr(transparent)]
    pub struct Signature(pub [u8; 64]);

    impl Deref for Signature {
        type Target = [u8; 64];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl tl_proto::TlWrite for Signature {
        type Repr = tl_proto::Bare;

        #[inline(always)]
        fn max_size_hint(&self) -> usize {
            68 // 1 byte len + 64 bytes data + 3 bytes alignment
        }

        #[inline(always)]
        fn write_to<P: tl_proto::TlPacket>(&self, packet: &mut P) {
            <&[u8]>::write_to(&self.0.as_slice(), packet);
        }
    }

    impl<'a> tl_proto::TlRead<'a> for Signature {
        type Repr = tl_proto::Bare;

        #[inline(always)]
        fn read_from(packet: &'a [u8], offset: &mut usize) -> tl_proto::TlResult<Self> {
            <&'a [u8]>::read_from(packet, offset)?
                .try_into()
                .map(Self)
                .map_err(|_| tl_proto::TlError::UnexpectedEof)
        }
    }
}
