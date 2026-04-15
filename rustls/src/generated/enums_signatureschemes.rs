
enum_builder! {
    /// The `SignatureScheme` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    EnumName: SignatureScheme;
    EnumVal{
        RSA_PKCS1_SHA1 => 0x0201,
        ECDSA_SHA1_Legacy => 0x0203,
        RSA_PKCS1_SHA256 => 0x0401,
        ECDSA_NISTP256_SHA256 => 0x0403,
        RSA_PKCS1_SHA384 => 0x0501,
        ECDSA_NISTP384_SHA384 => 0x0503,
        RSA_PKCS1_SHA512 => 0x0601,
        ECDSA_NISTP521_SHA512 => 0x0603,
        RSA_PSS_SHA256 => 0x0804,
        RSA_PSS_SHA384 => 0x0805,
        RSA_PSS_SHA512 => 0x0806,
        ED25519 => 0x0807,
        ED448 => 0x0808,
        MLDSA44 => 0xfe00,
        MLDSA65 => 0xfe01,
        MLDSA87 => 0xfe02,
        XMSS1 => 0xfe03,
        XMSS3 => 0xfe04,
        XMSS5 => 0xfe05,
        KEMTLS_MLKEM512 => 0xfe06,
        KEMTLS_MLKEM768 => 0xfe07,
        KEMTLS_MLKEM1024 => 0xfe08,
        NIKE_CTIDH512 => 0xfe09,

    }
}