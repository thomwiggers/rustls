
enum_builder! {
    /// The `SignatureAlgorithm` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U8
    EnumName: SignatureAlgorithm;
    EnumVal{
        Anonymous => 0x00,
        RSA => 0x01,
        DSA => 0x02,
        ECDSA => 0x03,
        ED25519 => 0x07,
        ED448 => 0x08,
        KEMTLS => 0x0f,
        NIKE => 0x10,
        MLDSA44 => 0x11,
        MLDSA65 => 0x12,
        MLDSA87 => 0x13,
        XMSS1 => 0x14,
        XMSS3 => 0x15,
        XMSS5 => 0x16,
    }
}