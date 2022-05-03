pub mod ed25519;

#[cfg(feature = "tl-proto")]
pub mod tl {
    /// Public key which is used in protocol
    #[derive(Debug, Copy, Clone, tl_proto::TlRead, tl_proto::TlWrite)]
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
}
