# sigs
from itertools import repeat
import textwrap
import subprocess
from algorithms import signs, kems, get_oid, nikes


with open('rustls/src/generated/named_group_to_kex.rs', 'w') as fh:
    fh.write("match group {\n")
    for alg, oqsalg in kems:
        fh.write(f"""
        NamedGroup::{oqsalg} => {{
            oqs::init();
            let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber512).unwrap();
            Some(KexAlgorithm::KEM(kem))
        }},
""")
    for alg in nikes:
        algname = alg.replace("csidh", "CSIDH")
        if alg.startswith("ctidh"):
            fh.write(f"""
        NamedGroup::{alg.upper()} => {{
            Some(KexAlgorithm::CSIDH(NikeImpl::{alg.upper()}))
        }},
""")
        else:
            fh.write(f"""
        NamedGroup::{alg.upper()} => {{
            Some(KexAlgorithm::CSIDH(NikeImpl::SecSidh(secsidh::Algorithm::{algname})))
            }},
""")
    fh.write("_ => None,\n}")

with open('rustls/src/generated/supported_kex_groups.rs', 'w') as fh:
    fh.write("&[\n")
    for alg, oqsalg in kems:
        fh.write(f"""NamedGroup::{oqsalg},\n""")
    for alg in nikes:
        fh.write(f"""NamedGroup::{alg.upper()},\n""")
    fh.write("""    NamedGroup::X25519,
    NamedGroup::secp384r1,
    NamedGroup::secp256r1,
]""")


with open('rustls/src/generated/enums_namedgroup.rs', 'w') as fh:
    fh.write("""
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
""")
    for id, (alg, oqsalg) in enumerate(kems, start=0x01fc):
        fh.write(f"        {oqsalg} => 0x{id:04x},\n")
    for id, alg in enumerate(nikes, start=0x01fc+len(kems)):
        fh.write(f"        {alg.upper()} => 0x{id:04x},\n")
    fh.write("""    }
}
""")

with open("rustls/src/generated/enums_signaturealgorithms.rs", "w") as fh:
    fh.write("""
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
        NIKE => 0x10,\n""")
    for id, (alg, oqsalg) in enumerate(signs, start=0x11):
        fh.write(f"        {alg.upper()} => 0x{id:02x},\n")
    fh.write("    }\n}")


with open("rustls/src/generated/enums_signatureschemes.rs", "w") as fh:
    fh.write("""
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
""")
    for id, (alg, oqsalg) in enumerate(signs, start=0xfe00):
        fh.write(f"        {alg.upper()} => 0x{id:04x},\n")
    for id, (alg, oqsalg) in enumerate(kems, start=0xfe00 + len(signs)):
        fh.write(f"        KEMTLS_{alg.upper()} => 0x{id:04x},\n")
    for id, alg in enumerate(nikes, start=0xfe00+len(kems)+len(signs)):
        fh.write(f"        NIKE_{alg.upper()} => 0x{id:04x},\n")
    fh.write("""
    }
}""")

with open("rustls/src/generated/supported_sign_tls13.rs", "w") as fh:
    fh.write("&[\n")
    fh.write("    SignatureScheme::ECDSA_NISTP384_SHA384,\n")
    fh.write("    SignatureScheme::ECDSA_NISTP256_SHA256,\n")
    fh.write("    SignatureScheme::RSA_PSS_SHA512,\n")
    fh.write("    SignatureScheme::RSA_PSS_SHA384,\n")
    fh.write("    SignatureScheme::RSA_PSS_SHA256,\n")
    fh.write("    SignatureScheme::ED25519,\n")
    for alg, oqsalg in signs:
        fh.write(f"    SignatureScheme::{alg.upper()},\n")
    for alg, oqsalg in kems:
        fh.write(f"    SignatureScheme::KEMTLS_{alg.upper()},\n")
    for alg in nikes:
        fh.write(f"    SignatureScheme::NIKE_{alg.upper()},\n")
    fh.write("]")

with open("rustls/src/generated/pq_sigscheme_to_sigalg.rs", "w") as fh:
    fh.write("match self.scheme {\n")
    for alg, oqsalg in signs:
        fh.write(f"    SignatureScheme::{alg.upper()} => SignatureAlgorithm::{alg.upper()},\n")
    fh.write("    _ => unreachable!(),")
    fh.write("}")

with open("rustls/src/generated/sigscheme_to_oqsalg.rs", "w") as fh:
    fh.write("match scheme {\n")
    for alg, oqsalg in signs:
        if alg.startswith("xmss"):
            continue
        fh.write(f"    SignatureScheme::{alg.upper()} => oqs::sig::Algorithm::{oqsalg},\n")
    fh.write("    _ => unreachable!(),")
    fh.write("}")

with open("rustls/src/generated/kemscheme_to_oqsalg.rs", "w") as fh:
    fh.write("match scheme {\n")
    for alg, oqsalg in kems:
        fh.write(f"    SignatureScheme::KEMTLS_{alg.upper()} => oqs::kem::Algorithm::{oqsalg},\n")
    fh.write("    _ => unreachable!(),")
    fh.write("}")

with open("rustls/src/generated/nike_to_csidhalg.rs", "w") as fh:
    fh.write("match scheme {\n")
    for alg in nikes:
        secsidhalg = alg.replace("csidh", "CSIDH")
        if alg.startswith("ctidh"):
            fh.write(f"    SignatureScheme::NIKE_{alg.upper()} => NikeImpl::{alg.upper()},\n")
        else:
            fh.write(f"    SignatureScheme::NIKE_{alg.upper()} => NikeImpl::SecSidh(secsidh::Algorithm::{secsidhalg}),\n")
    fh.write("    _ => unreachable!(),")
    fh.write("}")


with open("rustls/src/generated/pq_sigschemes.rs", "w") as fh:
    fh.write("&[\n")
    for alg, oqsalg in signs:
        fh.write(f"    SignatureScheme::{alg.upper()},\n")
    fh.write("]")

with open("rustls/src/generated/pq_kemschemes.rs", "w") as fh:
    fh.write("&[\n")
    for alg, oqsalg in kems:
        fh.write(f"    SignatureScheme::KEMTLS_{alg.upper()},\n")
    fh.write("]")

with open("rustls/src/generated/nikes.rs", "w") as fh:
    fh.write("&[\n")
    for alg in nikes:
        fh.write(f"\tSignatureScheme::NIKE_{alg.upper()},\n")
    fh.write("]")

for alg, _ in signs + kems + list(zip(nikes, repeat("nope"))):
    input_str = f"OBJECT_IDENTIFIER {{ {get_oid(alg.lower())} }}\n"
    subprocess.run(
        ["../mk-cert/ascii2der", "-o", f"rustls/src/generated/data/alg-{alg}.der"],
        input=input_str.encode(),
        check=True
    )

with open("rustls/src/generated/scheme_to_oid.rs", "w") as fh:
    fh.write("match scheme {\n")
    for alg, _ in signs:
        fh.write(f"    SignatureScheme::{alg.upper()} => include_bytes!(\"data/alg-{alg}.der\"),\n")
    for alg, _ in kems:
        fh.write(f"    SignatureScheme::KEMTLS_{alg.upper()} => include_bytes!(\"data/alg-{alg}.der\"),\n")
    for alg in nikes:
        fh.write(f"    SignatureScheme::NIKE_{alg.upper()} => include_bytes!(\"data/alg-{alg}.der\"),\n")
    fh.write("    _ => unreachable!(),")
    fh.write("}")

with open("rustls/src/generated/supported_sigalgs.rs", "w") as fh:
    fh.write("""
/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,""")
    for alg, _ in signs:
        fh.write(f"    &webpki::{alg.upper()},\n")
    fh.write("];")

with open("rustls/src/generated/convert_sigalg.rs", "w") as fh:
    fh.write("""
match scheme {
    ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
    ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
    ED25519 => Ok(&webpki::ED25519),
    RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
    RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
    RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),""")
    for alg, _ in signs:
        fh.write(f"    {alg.upper()} => Ok(&webpki::{alg.upper()}),\n")
    fh.write("""
    _ => {
        let error_msg = format!("received unsupported sig scheme {:?}", scheme);
        Err(TLSError::PeerMisbehavedError(error_msg))
    }
}""")

with open("rustls/src/generated/webpki_nike_to_sigalg.rs", "w") as fh:
    first = True
    for alg in nikes:
        fh.write(textwrap.dedent(f"""
        {"else" if not first else ""} if webpkischeme == &webpki::{alg.upper()} {{
            return SignatureScheme::NIKE_{alg.upper()};
        }}
        """))
        first = False

with open("rustls/src/generated/nikealgs_match.rs",  "w") as fh:
    fh.write("match (named_group, sigalg) {\n")
    for alg in nikes:
        fh.write(f"\t(NamedGroup::{alg.upper()}, SignatureScheme::NIKE_{alg.upper()}) => true,\n")
    fh.write("\t(_, _) => false,")
    fh.write("}")
