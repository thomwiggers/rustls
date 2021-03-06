
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
    &webpki::RSA_PKCS1_3072_8192_SHA384,    &webpki::DILITHIUM2,
    &webpki::DILITHIUM3,
    &webpki::DILITHIUM5,
    &webpki::FALCON512,
    &webpki::FALCON1024,
    &webpki::RAINBOWICLASSIC,
    &webpki::RAINBOWICIRCUMZENITHAL,
    &webpki::RAINBOWICOMPRESSED,
    &webpki::RAINBOWIIICLASSIC,
    &webpki::RAINBOWIIICIRCUMZENITHAL,
    &webpki::RAINBOWIIICOMPRESSED,
    &webpki::RAINBOWVCLASSIC,
    &webpki::RAINBOWVCIRCUMZENITHAL,
    &webpki::RAINBOWVCOMPRESSED,
    &webpki::SPHINCSHARAKA128FSIMPLE,
    &webpki::SPHINCSHARAKA128FROBUST,
    &webpki::SPHINCSHARAKA128SSIMPLE,
    &webpki::SPHINCSHARAKA128SROBUST,
    &webpki::SPHINCSHARAKA192FSIMPLE,
    &webpki::SPHINCSHARAKA192FROBUST,
    &webpki::SPHINCSHARAKA192SSIMPLE,
    &webpki::SPHINCSHARAKA192SROBUST,
    &webpki::SPHINCSHARAKA256FSIMPLE,
    &webpki::SPHINCSHARAKA256FROBUST,
    &webpki::SPHINCSHARAKA256SSIMPLE,
    &webpki::SPHINCSHARAKA256SROBUST,
    &webpki::SPHINCSSHA256128FSIMPLE,
    &webpki::SPHINCSSHA256128FROBUST,
    &webpki::SPHINCSSHA256128SSIMPLE,
    &webpki::SPHINCSSHA256128SROBUST,
    &webpki::SPHINCSSHA256192FSIMPLE,
    &webpki::SPHINCSSHA256192FROBUST,
    &webpki::SPHINCSSHA256192SSIMPLE,
    &webpki::SPHINCSSHA256192SROBUST,
    &webpki::SPHINCSSHA256256FSIMPLE,
    &webpki::SPHINCSSHA256256FROBUST,
    &webpki::SPHINCSSHA256256SSIMPLE,
    &webpki::SPHINCSSHA256256SROBUST,
    &webpki::SPHINCSSHAKE256128FSIMPLE,
    &webpki::SPHINCSSHAKE256128FROBUST,
    &webpki::SPHINCSSHAKE256128SSIMPLE,
    &webpki::SPHINCSSHAKE256128SROBUST,
    &webpki::SPHINCSSHAKE256192FSIMPLE,
    &webpki::SPHINCSSHAKE256192FROBUST,
    &webpki::SPHINCSSHAKE256192SSIMPLE,
    &webpki::SPHINCSSHAKE256192SROBUST,
    &webpki::SPHINCSSHAKE256256FSIMPLE,
    &webpki::SPHINCSSHAKE256256FROBUST,
    &webpki::SPHINCSSHAKE256256SSIMPLE,
    &webpki::SPHINCSSHAKE256256SROBUST,
    &webpki::XMSS,
];