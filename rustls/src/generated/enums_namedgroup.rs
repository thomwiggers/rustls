
enum_builder! {
    /// The `NamedGroup` TLS protocol enum.  Values in this enum are taken
    /// from the various RFCs covering TLS, and are listed by IANA.
    /// The `Unknown` item is used when processing unrecognised ordinals.
    @U16
    EnumName: NamedGroup;
    EnumVal{
        secp256r1 => 0x0017,
        secp384r1 => 0x0018,
        secp521r1 => 0x0019,
        X25519 => 0x001d,
        X448 => 0x001e,
        FFDHE2048 => 0x0100,
        FFDHE3072 => 0x0101,
        FFDHE4096 => 0x0102,
        FFDHE6144 => 0x0103,
        FFDHE8192 => 0x0104,
        X25519MLKEM768 => 0x11eb,
        secp256r1MLKEM768 => 0x11ec,
        secp384r1MLKEM1024 => 0x11ed,
        MlKem512 => 0x01fc,
        MlKem768 => 0x01fd,
        MlKem1024 => 0x01fe,
        CTIDH512 => 0x01ff,
    }
}
